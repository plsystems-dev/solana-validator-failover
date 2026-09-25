package failover

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sol-strategies/solana-validator-failover/internal/hooks"
	"github.com/sol-strategies/solana-validator-failover/internal/solana"
	"github.com/stretchr/testify/require"
)

func handoverTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
		&tls.Config{Certificates: []tls.Certificate{pair}, RootCAs: pool, ServerName: "localhost"}
}

// This RPC intentionally implements only the native methods used for safety.
// Other endpoints return method-not-found, preventing accidental dependence on
// native getVoteAccounts/getLeaderSchedule support.
func handoverRPC(t *testing.T, state *testRuntime, clock *atomic.Uint64, switched func(string), voteSlots ...func() uint64) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/switch" {
			var request struct {
				Identity string `json:"identity"`
			}
			if json.NewDecoder(r.Body).Decode(&request) != nil {
				w.WriteHeader(400)
				return
			}
			state.setIdentity(request.Identity)
			if switched != nil {
				switched(request.Identity)
			}
			json.NewEncoder(w).Encode(map[string]bool{"ok": true})
			return
		}
		var request struct {
			Method string `json:"method"`
			ID     any    `json:"id"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			w.WriteHeader(400)
			return
		}
		var result any
		switch request.Method {
		case "getHealth":
			result = "ok"
		case "getIdentity":
			state.mu.Lock()
			identity := state.identity
			state.mu.Unlock()
			result = map[string]string{"identity": identity}
		case "getSlot":
			result = clock.Add(1)
		case "getVoteAccounts":
			state.mu.Lock()
			isLocal := state.identity != ""
			state.mu.Unlock()
			if isLocal {
				w.WriteHeader(500)
				return
			}
			lastVote := clock.Load()
			if len(voteSlots) > 0 {
				lastVote = voteSlots[0]()
			}
			result = map[string]any{"current": []map[string]any{{"votePubkey": testVote, "nodePubkey": testActive, "lastVote": lastVote}}, "delinquent": []any{}}
		case "getGenesisHash":
			result = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
		case "getEpochInfo", "getAccountInfo":
			state.mu.Lock()
			isLocal := state.identity != ""
			state.mu.Unlock()
			if isLocal {
				w.WriteHeader(500)
				return
			}
			if request.Method == "getEpochInfo" {
				result = map[string]any{"epoch": 1042, "absoluteSlot": clock.Load()}
			} else {
				result = map[string]any{"context": map[string]any{"slot": clock.Load()}, "value": map[string]any{
					"owner": "Vote111111111111111111111111111111111111111", "lamports": 1, "data": map[string]any{
						"program": "vote", "parsed": map[string]any{"type": "vote", "info": map[string]any{
							"nodePubkey": testActive, "authorizedVoters": []map[string]any{{"epoch": 1042, "authorizedVoter": testActive}},
						}},
					},
				}}
			}
		default:
			json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32601, "message": "unsupported"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}))
	t.Cleanup(s.Close)
	return s
}

func fakeIdentityCLI(t *testing.T, client, rpcURL, publicKey string, promote bool) string {
	t.Helper()
	dir := t.TempDir()
	identity := filepath.Join(dir, "identity.json")
	data, err := json.Marshal(map[string]string{"pubkey": publicKey})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(identity, data, 0600))
	script := filepath.Join(dir, "validator")
	program := fmt.Sprintf(`#!/usr/bin/env python3
import json,sys,urllib.request
args=sys.argv[1:]
assert "set-identity" in args
client=%q
if client=="firedancer":
    assert "--config" in args and "--ledger" not in args and "--require-tower" not in args
else:
    assert "--ledger" in args and "--config" not in args
path=next(arg for arg in args if arg.endswith("identity.json"))
with open(path) as f: identity=json.load(f)["pubkey"]
body=json.dumps({"identity":identity}).encode()
request=urllib.request.Request(%q+"/switch",data=body,headers={"Content-Type":"application/json"})
with urllib.request.urlopen(request,timeout=3) as response: response.read()
`, client, rpcURL)
	require.NoError(t, os.WriteFile(script, []byte(program), 0700))
	if client == "firedancer" {
		return script + " set-identity --config " + filepath.Join(dir, "native.toml") + " " + identity
	}
	command := script + " --ledger " + dir + " set-identity " + identity
	if promote {
		command += " --require-tower"
	}
	return command
}

func TestQUICMTLSHandover(t *testing.T) {
	for _, direction := range [][2]string{{"agave", "firedancer"}, {"firedancer", "agave"}} {
		for _, scenario := range []string{"success", "dry-run", "lost-before-commit", "lost-after-commit", "stale-votes"} {
			t.Run(direction[0]+"-"+direction[1]+"/"+scenario, func(t *testing.T) {
				f := newHandoverFixture(t, direction[0], direction[1])
				var clock atomic.Uint64
				clock.Store(1000)
				sourceRPC := handoverRPC(t, f.source, &clock, func(string) { f.record("source-demoted") })
				destinationRPC := handoverRPC(t, f.destination, &clock, func(string) { f.record("destination-promoted") })
				voteSlot := func() uint64 {
					if scenario == "stale-votes" {
						return 1000
					}
					return clock.Load()
				}
				clusterRPC := handoverRPC(t, &testRuntime{}, &clock, nil, voteSlot)
				f.client.activeNodeInfo.PublicIP = "127.0.0.1"
				f.client.activeNodeInfo.RPCAddress = sourceRPC.URL
				f.client.activeNodeInfo.SetIdentityCommand = fakeIdentityCLI(t, direction[0], sourceRPC.URL, testSourcePassive, false)
				f.server.passiveNodeInfo.PublicIP = "127.0.0.1"
				f.server.passiveNodeInfo.RPCAddress = destinationRPC.URL
				f.server.passiveNodeInfo.SetIdentityCommand = fakeIdentityCLI(t, direction[1], destinationRPC.URL, testActive, true)
				serverTLS, clientTLS := handoverTLS(t)
				portSocket, err := net.ListenPacket("udp4", "127.0.0.1:0")
				require.NoError(t, err)
				port := portSocket.LocalAddr().(*net.UDPAddr).Port
				require.NoError(t, portSocket.Close())
				server, err := NewServerFromConfig(ServerConfig{Port: port, TLSConfig: serverTLS, PassiveNodeInfo: f.server.passiveNodeInfo,
					Safety: NewSafetyReader(destinationRPC.URL, clusterRPC.URL), IsDryRunFailover: scenario == "dry-run", AutoConfirm: true})
				require.NoError(t, err)
				server.pollInterval = 0
				if scenario == "stale-votes" {
					server.voteTimeout = 30 * time.Millisecond
				}
				marker := filepath.Join(t.TempDir(), "hook-ran")
				if scenario == "dry-run" {
					server.hooks.Pre.WhenPassive = []hooks.Hook{{Name: "forbidden-in-drill", Command: "touch", Args: []string{marker}, MustSucceed: true}}
				}
				if scenario == "lost-before-commit" {
					reader := server.safety
					reads := 0
					server.safety = safetyReaderFunc(func(ctx context.Context) (RuntimeStatus, error) {
						status, err := reader.Snapshot(ctx)
						reads++
						if reads == 2 {
							server.activeConn.CloseWithError(99, "injected pre-commit disconnect")
						}
						return status, err
					})
				}
				if scenario == "lost-after-commit" {
					server.runCommand = func(ctx context.Context, command string, dry bool) error {
						err := runIdentityCommand(ctx, command, dry)
						server.activeConn.CloseWithError(99, "injected post-commit disconnect")
						return err
					}
				}
				serverDone := make(chan error, 1)
				go func() { serverDone <- server.Start() }()
				client, err := NewClientFromConfig(ClientConfig{ServerName: "destination", ServerAddress: fmt.Sprintf("127.0.0.1:%d", port),
					TLSConfig: clientTLS, ActiveNodeInfo: f.client.activeNodeInfo, Safety: NewSafetyReader(sourceRPC.URL, clusterRPC.URL), SolanaRPCClient: solana.NewMockClient()})
				require.NoError(t, err)
				clientDone := make(chan error, 1)
				go func() { clientDone <- client.Start() }()
				var sourceErr, destinationErr error
				for i := 0; i < 2; i++ {
					select {
					case sourceErr = <-clientDone:
						clientDone = nil
					case destinationErr = <-serverDone:
						serverDone = nil
					case <-time.After(30 * time.Second):
						client.cancel()
						server.cancel()
						t.Fatal("QUIC participants did not finish")
					}
				}
				switch scenario {
				case "success":
					require.NoError(t, sourceErr)
					require.NoError(t, destinationErr)
					require.Equal(t, []string{"source-demoted", "destination-promoted"}, f.events)
				case "dry-run":
					require.NoError(t, sourceErr)
					require.NoError(t, destinationErr)
					require.Empty(t, f.events)
					require.NoFileExists(t, marker)
				case "lost-before-commit":
					require.Error(t, sourceErr)
					require.Error(t, destinationErr)
					require.Equal(t, []string{"source-demoted"}, f.events)
				case "lost-after-commit", "stale-votes":
					require.Error(t, sourceErr)
					require.Error(t, destinationErr)
					require.Equal(t, []string{"source-demoted", "destination-promoted"}, f.events)
				}
			})
		}
	}
}
