package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
)

const (
	DefaultMaxSlotLag = uint64(32)
	rpcTimeout        = 8 * time.Second
	commandTimeout    = 30 * time.Second
	proofTimeout      = 20 * time.Second
)

// RuntimeStatus is sampled after a fresh identity check, then checked again
// before sending it. A source proof is sampled in response to a fresh challenge
// on the authenticated stream, separately from the demotion acknowledgement.
type RuntimeStatus struct {
	Identity         string
	Processed        uint64
	Finalized        uint64
	ClusterProcessed uint64
	ClusterFinalized uint64
}

type safetyReader interface {
	Snapshot(context.Context) (RuntimeStatus, error)
	CheckReadiness(context.Context, string, string, bool) error
	VoteAdvanced(context.Context, string, string, uint64) (bool, error)
}

type rpcSafetyReader struct {
	local   *rpc.Client
	cluster *rpc.Client
}

func NewSafetyReader(local, cluster string) safetyReader {
	return &rpcSafetyReader{rpc.New(local), rpc.New(cluster)}
}

func (r *rpcSafetyReader) VoteAdvanced(ctx context.Context, voteAccount, activeIdentity string, afterSlot uint64) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	pubkey, err := solanago.PublicKeyFromBase58(voteAccount)
	if err != nil {
		return false, err
	}
	keepUnstaked := true
	accounts, err := r.cluster.GetVoteAccounts(ctx, &rpc.GetVoteAccountsOpts{VotePubkey: &pubkey, Commitment: rpc.CommitmentConfirmed, KeepUnstakedDelinquents: &keepUnstaked})
	if err != nil {
		return false, fmt.Errorf("independent vote progress: %w", err)
	}
	if accounts == nil {
		return false, fmt.Errorf("independent RPC returned no vote accounts")
	}
	for _, group := range [][]rpc.VoteAccountsResult{accounts.Current, accounts.Delinquent} {
		for _, account := range group {
			if account.VotePubkey != pubkey {
				continue
			}
			if account.NodePubkey.String() != activeIdentity {
				return false, fmt.Errorf("vote-account node identity changed during handover")
			}
			return account.LastVote > afterSlot, nil
		}
	}
	return false, nil
}

// CheckReadiness uses the independent RPC for epoch and parsed vote state.
// Native Firedancer does not implement all of Agave's account/vote endpoints.
func (r *rpcSafetyReader) CheckReadiness(ctx context.Context, voteAccount, activeIdentity string, identityIsVoter bool) error {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	localGenesis, err := r.local.GetGenesisHash(ctx)
	if err != nil {
		return fmt.Errorf("local genesis: %w", err)
	}
	clusterGenesis, err := r.cluster.GetGenesisHash(ctx)
	if err != nil {
		return fmt.Errorf("independent genesis: %w", err)
	}
	if localGenesis == (solanago.Hash{}) || localGenesis != clusterGenesis {
		return fmt.Errorf("local and independent RPC genesis hashes differ or are empty")
	}
	if voteAccount == "" {
		if identityIsVoter {
			return fmt.Errorf("native handover requires validator.vote_account")
		}
		return nil
	}
	pubkey, err := solanago.PublicKeyFromBase58(voteAccount)
	if err != nil {
		return fmt.Errorf("invalid vote account: %w", err)
	}
	epoch, err := r.cluster.GetEpochInfo(ctx, rpc.CommitmentProcessed)
	if err != nil {
		return fmt.Errorf("independent epoch: %w", err)
	}
	if epoch == nil {
		return fmt.Errorf("independent RPC returned no epoch")
	}
	account, err := r.cluster.GetAccountInfoWithOpts(ctx, pubkey, &rpc.GetAccountInfoOpts{Encoding: solanago.EncodingJSONParsed, Commitment: rpc.CommitmentFinalized})
	if err != nil {
		return fmt.Errorf("independent vote state: %w", err)
	}
	if account == nil || account.Value == nil || account.Value.Data == nil || account.Value.Owner.String() != "Vote111111111111111111111111111111111111111" {
		return fmt.Errorf("configured vote account is not a vote-program account")
	}
	var state struct {
		Program string `json:"program"`
		Parsed  struct {
			Type string `json:"type"`
			Info struct {
				NodePubkey       string `json:"nodePubkey"`
				AuthorizedVoters []struct {
					Epoch           uint64 `json:"epoch"`
					AuthorizedVoter string `json:"authorizedVoter"`
				} `json:"authorizedVoters"`
			} `json:"info"`
		} `json:"parsed"`
	}
	if err := json.Unmarshal(account.Value.Data.GetRawJSON(), &state); err != nil {
		return fmt.Errorf("parsed vote state: %w", err)
	}
	if state.Program != "vote" || state.Parsed.Type != "vote" || state.Parsed.Info.NodePubkey != activeIdentity {
		return fmt.Errorf("vote account node identity differs from the active identity")
	}
	var voter string
	var voterEpoch uint64
	for _, entry := range state.Parsed.Info.AuthorizedVoters {
		if entry.Epoch <= epoch.Epoch && (voter == "" || entry.Epoch > voterEpoch) {
			voter, voterEpoch = entry.AuthorizedVoter, entry.Epoch
		}
	}
	if voter == "" {
		return fmt.Errorf("no effective vote authority for epoch %d", epoch.Epoch)
	}
	if identityIsVoter && voter != activeIdentity {
		return fmt.Errorf("epoch %d voter %s is not the native identity-only signer %s", epoch.Epoch, voter, activeIdentity)
	}
	return nil
}

func (r *rpcSafetyReader) Snapshot(ctx context.Context) (s RuntimeStatus, err error) {
	ctx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	health, err := r.local.GetHealth(ctx)
	if err != nil {
		return s, fmt.Errorf("local health: %w", err)
	}
	if health != rpc.HealthOk {
		return s, fmt.Errorf("local health is %q", health)
	}
	identity, err := r.local.GetIdentity(ctx)
	if err != nil {
		return s, fmt.Errorf("local identity: %w", err)
	}
	if identity == nil {
		return s, fmt.Errorf("local RPC returned no identity")
	}
	s.Identity = identity.Identity.String()
	if s.Processed, err = r.local.GetSlot(ctx, rpc.CommitmentProcessed); err != nil {
		return s, err
	}
	if s.Finalized, err = r.local.GetSlot(ctx, rpc.CommitmentFinalized); err != nil {
		return s, err
	}
	if s.ClusterProcessed, err = r.cluster.GetSlot(ctx, rpc.CommitmentProcessed); err != nil {
		return s, err
	}
	if s.ClusterFinalized, err = r.cluster.GetSlot(ctx, rpc.CommitmentFinalized); err != nil {
		return s, err
	}
	after, err := r.local.GetIdentity(ctx)
	if err != nil {
		return s, err
	}
	if after == nil {
		return s, fmt.Errorf("local RPC returned no identity after status read")
	}
	if after.Identity.String() != s.Identity {
		return s, fmt.Errorf("identity changed during status read")
	}
	return s, nil
}

func (s RuntimeStatus) validate(identity string, maxLag uint64) error {
	if s.Identity != identity {
		return fmt.Errorf("identity is %s, expected %s", s.Identity, identity)
	}
	if s.Processed == 0 || s.Finalized == 0 || s.ClusterProcessed == 0 || s.ClusterFinalized == 0 {
		return fmt.Errorf("RPC returned a zero slot")
	}
	for _, pair := range [][2]uint64{{s.Processed, s.ClusterProcessed}, {s.Finalized, s.ClusterFinalized}} {
		lo, hi := min(pair[0], pair[1]), max(pair[0], pair[1])
		if hi-lo > maxLag {
			return fmt.Errorf("local/cluster slots differ by %d (limit %d)", hi-lo, maxLag)
		}
	}
	return nil
}

func negotiateTowerTransfer(source, destination *NodeInfo, skipTower, rollback, authenticated bool) (bool, error) {
	for _, n := range []*NodeInfo{source, destination} {
		if n.Client != "agave" && n.Client != "firedancer" {
			return false, fmt.Errorf("unknown client capability %q", n.Client)
		}
		if n.Identities == nil || n.Identities.Active == nil || n.Identities.Passive == nil {
			return false, fmt.Errorf("missing peer identities")
		}
		if n.Identities.Active.PubKey() == "" || n.Identities.Passive.PubKey() == "" || n.Identities.Active.PubKey() == n.Identities.Passive.PubKey() {
			return false, fmt.Errorf("active and passive identities must be nonempty and distinct")
		}
	}
	if source.Identities.Active.PubKey() != destination.Identities.Active.PubKey() {
		return false, fmt.Errorf("active identities differ")
	}
	if source.Identities.Passive.PubKey() == destination.Identities.Passive.PubKey() {
		return false, fmt.Errorf("passive identities must be distinct")
	}
	if source.Client == "firedancer" || destination.Client == "firedancer" {
		if source.VoteAccount == "" || source.VoteAccount != destination.VoteAccount {
			return false, fmt.Errorf("native peers must configure the same nonempty validator.vote_account")
		}
		if !authenticated {
			return false, fmt.Errorf("native handover requires mTLS")
		}
		if rollback {
			return false, fmt.Errorf("automatic rollback is unsupported for native handover; use a verified reverse handover")
		}
		return false, nil
	}
	if skipTower {
		return false, fmt.Errorf("--skip-tower-sync is unsafe for Agave; use tower transfer")
	}
	return true, nil
}

// Existing command templates remain supported. In a mixed/native handover
// there is no incoming tower, so only the standalone require-tower option is
// removed. Native commands never receive Agave ledger/tower arguments.
func promotionCommand(command string, transferTower bool) string {
	if transferTower {
		return command
	}
	args := strings.Fields(command)
	filtered := args[:0]
	for _, arg := range args {
		if arg != "--require-tower" {
			filtered = append(filtered, arg)
		}
	}
	return strings.Join(filtered, " ")
}

func runIdentityCommand(ctx context.Context, command string, dryRun bool) error {
	if dryRun {
		return nil
	}
	args := strings.Fields(command)
	if len(args) == 0 {
		return fmt.Errorf("empty identity command")
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("identity command failed (outcome must be verified): %w: %s", err, output)
	}
	return nil
}

func sendPhase(s *Stream, phase string) error {
	if err := s.Stream.SetWriteDeadline(time.Now().Add(proofTimeout)); err != nil {
		return err
	}
	s.message.Phase = phase
	return s.Encode()
}

func receivePhase(s *Stream, timeout time.Duration) error {
	if err := s.Stream.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if err := s.Decode(); err != nil {
		return err
	}
	if s.message.Phase == "abort" {
		return fmt.Errorf("peer aborted: %s", s.message.ErrorMessage)
	}
	return nil
}

func abortPeer(s *Stream, err error) {
	if s == nil || err == nil {
		return
	}
	s.message.ErrorMessage = err.Error()
	_ = s.Stream.SetWriteDeadline(time.Now().Add(time.Second))
	s.message.Phase = "abort"
	_ = s.Encode()
}
