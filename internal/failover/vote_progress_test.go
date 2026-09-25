package failover

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVoteProgressRequiresExactAccountIdentityAndStrictAdvance(t *testing.T) {
	var lastVote atomic.Uint64
	lastVote.Store(2000)
	var wrongNode atomic.Bool
	cluster := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
			Params []struct {
				VotePubkey string `json:"votePubkey"`
			} `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Method != "getVoteAccounts" || len(request.Params) != 1 || request.Params[0].VotePubkey != testVote {
			w.WriteHeader(400)
			return
		}
		node := testActive
		if wrongNode.Load() {
			node = testSourcePassive
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": map[string]any{
			"current":    []map[string]any{{"votePubkey": testDestinationPassive, "nodePubkey": testActive, "lastVote": 999999}},
			"delinquent": []map[string]any{{"votePubkey": testVote, "nodePubkey": node, "lastVote": lastVote.Load()}},
		}})
	}))
	defer cluster.Close()
	reader := NewSafetyReader("http://127.0.0.1:1", cluster.URL)
	advanced, err := reader.VoteAdvanced(context.Background(), testVote, testActive, 2000)
	require.NoError(t, err)
	require.False(t, advanced, "a stale equal-slot vote and another vote account cannot pass")
	lastVote.Store(2001)
	advanced, err = reader.VoteAdvanced(context.Background(), testVote, testActive, 2000)
	require.NoError(t, err)
	require.True(t, advanced)
	wrongNode.Store(true)
	_, err = reader.VoteAdvanced(context.Background(), testVote, testActive, 2000)
	require.ErrorContains(t, err, "node identity changed")
}
