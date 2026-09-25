package validator

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/sol-strategies/solana-validator-failover/internal/identities"
	"github.com/stretchr/testify/require"
)

func TestNativeConfigurationDoesNotRequireAgavePaths(t *testing.T) {
	dir := t.TempDir()
	binary := createDummyAgaveValidator(t)
	nativeConfig := filepath.Join(dir, "validator.toml")
	require.NoError(t, os.WriteFile(nativeConfig, []byte("name = \"native\"\n"), 0600))
	active := createTestKeyFile(t, dir, "active.json")
	passive := createTestKeyFile(t, dir, "passive.json")
	keys, err := identities.NewFromConfig(&identities.Config{Active: active, Passive: passive})
	require.NoError(t, err)
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		if request.Method != "getClusterNodes" {
			w.WriteHeader(500)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": []map[string]any{{
			"pubkey": keys.Passive.PubKey(), "gossip": "192.0.2.2:8001", "version": "26.09.4",
		}}})
	}))
	defer local.Close()
	cfg := &Config{Client: "firedancer", FiredancerConfig: nativeConfig, Bin: binary,
		VoteAccount: "9f7dqiYNBZbgPesAnLeWnKCtxYHSfMg5x1EMZCJwVwG7", Cluster: "mainnet-beta",
		ClusterRPCURL: "https://api.mainnet-beta.solana.com", RPCAddress: local.URL, AverageSlotDuration: "400ms",
		Identities: identities.Config{Active: active, Passive: passive}, Name: "native-test", PublicIP: "192.0.2.2",
		Failover: FailoverConfig{MinimumTimeToLeaderSlot: "5m", Peers: PeersConfig{"peer": {Address: "192.0.2.1:9898"}},
			SetIdentityActiveCmdTemplate:  "{{ .Bin }} set-identity --config {{ .FiredancerConfig }} {{ .Identities.Active.KeyFile }}",
			SetIdentityPassiveCmdTemplate: "{{ .Bin }} set-identity --config {{ .FiredancerConfig }} {{ .Identities.Passive.KeyFile }}",
			Monitor:                       MonitorConfig{CreditSamples: CreditSamplesConfig{Count: 1, Interval: "1s"}}}}
	v, err := NewFromConfig(cfg)
	require.NoError(t, err)
	require.Empty(t, v.LedgerDir)
	require.Empty(t, v.TowerFile)
	require.Contains(t, v.SetIdentityActiveCommand, "--config "+nativeConfig)
	require.Contains(t, v.SetIdentityActiveCommand, active)
	require.NotContains(t, v.SetIdentityActiveCommand, "--require-tower")
	require.NotContains(t, v.SetIdentityPassiveCommand, "--ledger")
	cfg.VoteAccount = ""
	_, err = NewFromConfig(cfg)
	require.ErrorContains(t, err, "requires validator.vote_account")
}
