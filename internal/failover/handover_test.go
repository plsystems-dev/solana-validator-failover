package failover

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/log"
	"github.com/sol-strategies/solana-validator-failover/internal/hooks"
	"github.com/sol-strategies/solana-validator-failover/internal/identities"
	"github.com/sol-strategies/solana-validator-failover/internal/solana"
	pkgconstants "github.com/sol-strategies/solana-validator-failover/pkg/constants"
	"github.com/stretchr/testify/require"
)

const testVote = "9f7dqiYNBZbgPesAnLeWnKCtxYHSfMg5x1EMZCJwVwG7"

const testActive = "FwnWx7x99rGwLmipzz8ii15NqcHkKRo2oS1Y7j6LivgZ"
const testSourcePassive = "gXrJqGTx9BD5TomyQW48C3u5K5SpCsua873cFR9sbFy"
const testDestinationPassive = "88GTwFp8KPctYmwi8UK9dD9W5vr11jMKN2eYMDoFWmi2"

type testRuntime struct {
	mu       sync.Mutex
	identity string
	slot     uint64
	err      error
}

func (r *testRuntime) Snapshot(ctx context.Context) (RuntimeStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return RuntimeStatus{}, err
	}
	if r.err != nil {
		return RuntimeStatus{}, r.err
	}
	r.slot += 100
	return RuntimeStatus{r.identity, r.slot, r.slot, r.slot, r.slot}, nil
}

func (r *testRuntime) VoteAdvanced(_ context.Context, _ string, active string, after uint64) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.identity == active && r.slot > after, nil
}

func (r *testRuntime) CheckReadiness(context.Context, string, string, bool) error { return nil }

func (r *testRuntime) setIdentity(identity string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identity = identity
}

type handoverFixture struct {
	client      *Client
	server      *Server
	source      *testRuntime
	destination *testRuntime
	a, b        net.Conn
	mu          sync.Mutex
	events      []string
}

func newHandoverFixture(t *testing.T, sourceClient, destinationClient string) *handoverFixture {
	t.Helper()
	dir := t.TempDir()
	makeNode := func(name, client, passive, command string) *NodeInfo {
		return &NodeInfo{Hostname: name, PublicIP: "192.0.2.1", Client: client, VoteAccount: testVote,
			Identities:         &identities.Identities{Active: &identities.Identity{PubKeyStr: testActive}, Passive: &identities.Identity{PubKeyStr: passive}},
			SetIdentityCommand: command, TowerFile: filepath.Join(dir, name+".tower"),
			SolanaValidatorFailoverVersion: pkgconstants.AppVersion}
	}
	sourceNode := makeNode("source", sourceClient, testSourcePassive, "demote-source")
	destinationNode := makeNode("destination", destinationClient, testDestinationPassive, "promote-destination --require-tower")
	if destinationClient == "firedancer" {
		destinationNode.SetIdentityCommand = "promote-destination"
	}
	require.NoError(t, os.WriteFile(sourceNode.TowerFile, []byte("source tower"), 0600))
	require.NoError(t, os.WriteFile(destinationNode.TowerFile, []byte("old destination tower"), 0600))
	a, b := net.Pipe()
	f := &handoverFixture{a: a, b: b, source: &testRuntime{identity: testActive, slot: 1000}, destination: &testRuntime{identity: testDestinationPassive, slot: 1000}}
	logger := log.New(io.Discard)
	f.client = &Client{ctx: context.Background(), activeNodeInfo: sourceNode, safety: f.source,
		maxSlotLag: 32, logger: logger, tlsConfig: &tls.Config{}, solanaRPCClient: solana.NewMockClient(), failoverStream: NewFailoverStream(a)}
	f.server = &Server{ctx: context.Background(), passiveNodeInfo: destinationNode, safety: f.destination,
		maxSlotLag: 32, logger: logger, mtlsEnabled: true, autoConfirm: true, failoverStream: NewFailoverStream(b)}
	f.client.runCommand = func(_ context.Context, _ string, dry bool) error {
		if !dry {
			f.record("source-demoted")
			f.source.setIdentity(testSourcePassive)
		}
		return nil
	}
	f.server.runCommand = func(_ context.Context, command string, dry bool) error {
		if !dry {
			f.record(command)
			f.destination.setIdentity(testActive)
		}
		return nil
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return f
}

func (f *handoverFixture) record(event string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *handoverFixture) run(t *testing.T) (error, error) {
	t.Helper()
	sourceDone := make(chan error, 1)
	destinationDone := make(chan error, 1)
	go func() { defer f.a.Close(); sourceDone <- f.client.runSource() }()
	go func() {
		defer f.b.Close()
		if err := writeWireVersion(f.b); err != nil {
			destinationDone <- err
			return
		}
		destinationDone <- f.server.runDestination()
	}()
	var a, b error
	for i := 0; i < 2; i++ {
		select {
		case a = <-sourceDone:
			sourceDone = nil
		case b = <-destinationDone:
			destinationDone = nil
		case <-time.After(5 * time.Second):
			f.a.Close()
			f.b.Close()
			t.Fatal("protocol did not terminate")
		}
	}
	return a, b
}

func TestHandoverClientMatrix(t *testing.T) {
	for _, pair := range [][2]string{{"agave", "firedancer"}, {"firedancer", "agave"}, {"firedancer", "firedancer"}, {"agave", "agave"}} {
		t.Run(strings.Join(pair[:], "-"), func(t *testing.T) {
			f := newHandoverFixture(t, pair[0], pair[1])
			a, b := f.run(t)
			require.NoError(t, a)
			require.NoError(t, b)
			require.Equal(t, "source-demoted", f.events[0])
			require.Len(t, f.events, 2)
			mixed := pair[0] == "firedancer" || pair[1] == "firedancer"
			require.Equal(t, !mixed, strings.Contains(f.events[1], "--require-tower"))
			if pair[1] == "firedancer" {
				content, err := os.ReadFile(f.server.passiveNodeInfo.TowerFile)
				require.NoError(t, err)
				require.Equal(t, "old destination tower", string(content))
			} else {
				archives, err := filepath.Glob(f.server.passiveNodeInfo.TowerFile + ".planned-stale-*")
				require.NoError(t, err)
				require.Len(t, archives, 1)
				if mixed {
					require.NoFileExists(t, f.server.passiveNodeInfo.TowerFile)
				} else {
					content, err := os.ReadFile(f.server.passiveNodeInfo.TowerFile)
					require.NoError(t, err)
					require.Equal(t, "source tower", string(content))
				}
			}
		})
	}
}

func TestHandoverDemotionFailureNeverPromotes(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	f.client.runCommand = func(context.Context, string, bool) error { return errors.New("demotion failed") }
	a, b := f.run(t)
	require.ErrorContains(t, a, "demotion failed")
	require.Error(t, b)
	require.Empty(t, f.events)
}

func TestHandoverSuccessfulCommandWithWrongIdentityNeverPromotes(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	f.client.runCommand = func(context.Context, string, bool) error { return nil }
	a, b := f.run(t)
	require.ErrorContains(t, a, "demotion not verified")
	require.Error(t, b)
	require.Empty(t, f.events)
}

func TestHandoverLostSourceProofNeverPromotes(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	reads := 0
	f.client.safety = safetyReaderFunc(func(ctx context.Context) (RuntimeStatus, error) {
		reads++
		if reads == 4 {
			return RuntimeStatus{}, errors.New("source RPC unavailable")
		}
		return f.source.Snapshot(ctx)
	})
	a, b := f.run(t)
	require.Error(t, a)
	require.Error(t, b)
	require.Equal(t, []string{"source-demoted"}, f.events)
}

func TestHandoverSourceReactivationDuringProofNeverPromotes(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	reads := 0
	f.client.safety = safetyReaderFunc(func(ctx context.Context) (RuntimeStatus, error) {
		reads++
		if reads == 4 {
			f.source.setIdentity(testActive)
		}
		return f.source.Snapshot(ctx)
	})
	a, b := f.run(t)
	require.Error(t, a)
	require.ErrorContains(t, b, "identity is")
	require.Equal(t, []string{"source-demoted"}, f.events)
}

func TestHandoverPromotionFailureDoesNotReactivateSource(t *testing.T) {
	f := newHandoverFixture(t, "firedancer", "agave")
	f.server.runCommand = func(context.Context, string, bool) error {
		f.record("failed-promotion")
		return errors.New("unknown command outcome")
	}
	a, b := f.run(t)
	require.Error(t, a)
	require.ErrorContains(t, b, "promotion outcome uncertain")
	require.Equal(t, []string{"source-demoted", "failed-promotion"}, f.events)
	status, err := f.source.Snapshot(context.Background())
	require.NoError(t, err)
	require.Equal(t, testSourcePassive, status.Identity)
}

func TestHandoverNativeDryRunDoesNotMutate(t *testing.T) {
	f := newHandoverFixture(t, "agave", "firedancer")
	f.server.isDryRunFailover = true
	var output bytes.Buffer
	f.server.logger = log.New(&output)
	marker := filepath.Join(t.TempDir(), "hook-ran")
	f.server.hooks.Pre.WhenPassive = []hooks.Hook{{Name: "mutation", Command: "touch", Args: []string{marker}, MustSucceed: true}}
	a, b := f.run(t)
	require.NoError(t, a)
	require.NoError(t, b)
	require.Empty(t, f.events)
	require.NoFileExists(t, marker)
	content, err := os.ReadFile(f.server.passiveNodeInfo.TowerFile)
	require.NoError(t, err)
	require.Equal(t, "old destination tower", string(content))
	require.Contains(t, output.String(), "dry run: negotiated immediate handover; no source fence or identity changes performed")
	require.Contains(t, output.String(), "dry run verified; identities unchanged")
	require.NotContains(t, output.String(), "source demotion verified")
	require.NotContains(t, output.String(), "verified handover complete")
	plan, err := RenderFailoverPlan(PlanData{IsDryRun: true, SkipTowerSync: true,
		ActiveNodeInfo: *f.client.activeNodeInfo, PassiveNodeInfo: *f.server.passiveNodeInfo})
	require.NoError(t, err)
	require.Contains(t, plan, "Dry run only: identity changes, hooks and tower writes are skipped.")
	require.Contains(t, plan, "on the passive participant.")
	require.NotContains(t, plan, "for realsies")
}

func (f safetyReaderFunc) VoteAdvanced(context.Context, string, string, uint64) (bool, error) {
	return false, nil
}

func (f safetyReaderFunc) CheckReadiness(context.Context, string, string, bool) error { return nil }

type safetyReaderFunc func(context.Context) (RuntimeStatus, error)

func (f safetyReaderFunc) Snapshot(ctx context.Context) (RuntimeStatus, error) { return f(ctx) }

func TestRuntimeStatusRejectsLag(t *testing.T) {
	status := RuntimeStatus{Identity: testDestinationPassive, Processed: 1000, Finalized: 1000, ClusterProcessed: 1033, ClusterFinalized: 1000}
	require.ErrorContains(t, status.validate(testDestinationPassive, 32), "differ by 33")
}

func TestCapabilitiesRejectBeforeAnyMutation(t *testing.T) {
	for _, kind := range []string{"unknown-client", "rollback", "unauthenticated"} {
		t.Run(kind, func(t *testing.T) {
			f := newHandoverFixture(t, "agave", "firedancer")
			switch kind {
			case "unknown-client":
				f.client.activeNodeInfo.Client = "unknown"
			case "rollback":
				f.server.rollback.Enabled = true
			case "unauthenticated":
				f.server.mtlsEnabled = false
			}
			a, b := f.run(t)
			require.Error(t, a)
			require.Error(t, b)
			require.Empty(t, f.events)
		})
	}
}
