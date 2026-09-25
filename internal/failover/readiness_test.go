package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadinessUsesIndependentEpochAndVoteAuthority(t *testing.T) {
	var epoch atomic.Uint64
	epoch.Store(1042)
	var mismatchedGenesis atomic.Bool
	genesis := "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		if request.Method != "getGenesisHash" {
			http.Error(w, "native endpoint unsupported", 500)
			return
		}
		value := genesis
		if mismatchedGenesis.Load() {
			value = testActive
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value})
	}))
	defer local.Close()
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&request))
		var result any
		switch request.Method {
		case "getGenesisHash":
			result = genesis
		case "getEpochInfo":
			result = map[string]any{"epoch": epoch.Load()}
		case "getAccountInfo":
			result = map[string]any{"context": map[string]int{"slot": 1000}, "value": map[string]any{
				"owner": "Vote111111111111111111111111111111111111111", "lamports": 1,
				"data": map[string]any{"program": "vote", "parsed": map[string]any{"type": "vote", "info": map[string]any{
					"nodePubkey": testActive, "authorizedVoters": []map[string]any{{"epoch": 1042, "authorizedVoter": testActive}, {"epoch": 1043, "authorizedVoter": testSourcePassive}},
				}}},
			}}
		default:
			http.Error(w, "unsupported", 500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	defer cluster.Close()
	reader := NewSafetyReader(local.URL, cluster.URL)
	require.NoError(t, reader.CheckReadiness(context.Background(), testVote, testActive, true))
	epoch.Store(1043)
	require.ErrorContains(t, reader.CheckReadiness(context.Background(), testVote, testActive, true), "epoch 1043 voter")
	// Separate authorized voters remain valid for a pure Agave transfer.
	require.NoError(t, reader.CheckReadiness(context.Background(), testVote, testActive, false))
	mismatchedGenesis.Store(true)
	require.ErrorContains(t, reader.CheckReadiness(context.Background(), testVote, testActive, false), "genesis hashes differ")
}

type readinessOverride struct {
	safetyReader
	checks int
}

func (r *readinessOverride) CheckReadiness(context.Context, string, string, bool) error {
	r.checks++
	if r.checks == 2 {
		return fmt.Errorf("authority changed during slot guard")
	}
	return nil
}

func TestAuthorityRecheckedAfterGuardBeforePromotion(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	reader := &readinessOverride{safetyReader: f.server.safety}
	f.server.safety = reader
	a, b := f.run(t)
	require.Error(t, a)
	require.ErrorContains(t, b, "authority changed during slot guard")
	require.Equal(t, []string{"source-demoted"}, f.events)
	require.Equal(t, 2, reader.checks)
}
