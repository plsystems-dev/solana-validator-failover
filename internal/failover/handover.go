package failover

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pkgconstants "github.com/sol-strategies/solana-validator-failover/pkg/constants"
)

const transactionTimeout = 30 * time.Minute

func (c *Client) runSource() (err error) {
	f := c.failoverStream
	defer func() { abortPeer(f, err) }()
	if c.safety == nil {
		return fmt.Errorf("missing local/independent RPC safety reader")
	}
	if err := f.Stream.SetReadDeadline(time.Now().Add(proofTimeout)); err != nil {
		return err
	}
	if err := readAndCheckWireVersion(f.Stream); err != nil {
		return err
	}
	if err := c.safety.CheckReadiness(c.ctx, c.activeNodeInfo.VoteAccount, c.activeNodeInfo.Identities.Active.PubKey(), c.activeNodeInfo.Client == "firedancer"); err != nil {
		return err
	}
	initial, err := c.safety.Snapshot(c.ctx)
	if err != nil {
		return err
	}
	if err := initial.validate(c.activeNodeInfo.Identities.Active.PubKey(), c.maxSlotLag); err != nil {
		return err
	}
	f.SetActiveNodeInfo(c.activeNodeInfo)
	f.SetActiveRollbackEnabled(c.rollback.Enabled)
	f.message.SourceStatus = initial
	if err := sendPhase(f, "hello"); err != nil {
		return err
	}
	if err := receivePhase(f, transactionTimeout); err != nil {
		return err
	}
	if f.message.Phase != "ready" || !f.GetCanProceed() {
		return fmt.Errorf("peer did not authorize handover")
	}
	if f.GetPassiveNodeInfo().SolanaValidatorFailoverVersion != pkgconstants.AppVersion {
		return fmt.Errorf("peer application version differs")
	}
	quiet, err := negotiatedQuietSlots(c.activeNodeInfo, f.GetPassiveNodeInfo(), c.skipTowerSync, c.rollback.Enabled, c.tlsConfig != nil)
	if err != nil {
		return err
	}
	if quiet != f.message.RequiredQuietSlots {
		return fmt.Errorf("peer proposed an incompatible lockout policy")
	}
	dry := f.GetIsDryRunFailover()
	if !dry {
		if err := c.waitMinTimeToLeaderSlot(); err != nil {
			return err
		}
		if err := c.hooks.RunPreWhenActive(c.getHookEnvMap(hookEnvMapParams{isPreFailover: true})); err != nil {
			return err
		}
	}
	before, err := c.safety.Snapshot(c.ctx)
	if err != nil {
		return err
	}
	if err := before.validate(c.activeNodeInfo.Identities.Active.PubKey(), c.maxSlotLag); err != nil {
		return err
	}
	if err := c.safety.CheckReadiness(c.ctx, c.activeNodeInfo.VoteAccount, c.activeNodeInfo.Identities.Active.PubKey(), quiet != 0); err != nil {
		return err
	}
	f.SetFailoverStartSlot(before.Processed)
	f.SetActiveNodeSetIdentityStartTime()
	if err := c.runCommand(c.ctx, c.activeNodeInfo.SetIdentityCommand, dry); err != nil {
		return err
	}
	f.SetActiveNodeSetIdentityEndTime()
	expected := c.activeNodeInfo.Identities.Passive.PubKey()
	if dry {
		expected = c.activeNodeInfo.Identities.Active.PubKey()
	}
	status, err := c.safety.Snapshot(c.ctx)
	if err != nil {
		return fmt.Errorf("cannot verify source demotion: %w", err)
	}
	if err := status.validate(expected, c.maxSlotLag); err != nil {
		return fmt.Errorf("source demotion not verified: %w", err)
	}
	f.message.SourceStatus = status
	// Both transfer modes must send this acknowledgement. Tower transfer is an
	// optional payload, never the protocol's implicit demotion barrier.
	if quiet == 0 {
		if err := c.activeNodeInfo.SetTowerFileBytes(); err != nil {
			return err
		}
		if len(c.activeNodeInfo.TowerFileBytes) == 0 {
			return fmt.Errorf("source tower is empty")
		}
		f.SetActiveNodeInfo(c.activeNodeInfo)
	}
	if err := sendPhase(f, "demoted"); err != nil {
		return err
	}
	var sequence uint64
	for {
		if err := receivePhase(f, 2*time.Minute); err != nil {
			return fmt.Errorf("handover outcome unknown; keep source fenced: %w", err)
		}
		switch f.message.Phase {
		case "check-source":
			if f.message.Sequence != sequence+1 {
				return fmt.Errorf("invalid source-proof sequence")
			}
			sequence++
			status, err := c.safety.Snapshot(c.ctx)
			if err != nil {
				return err
			}
			if err := status.validate(expected, c.maxSlotLag); err != nil {
				return err
			}
			f.message.SourceStatus = status
			if err := sendPhase(f, "source-proof"); err != nil {
				return err
			}
		case "complete":
			if !f.GetIsSuccessfullyCompleted() {
				return fmt.Errorf("peer did not confirm completion")
			}
			status, err := c.safety.Snapshot(c.ctx)
			if err != nil {
				return err
			}
			if err := status.validate(expected, c.maxSlotLag); err != nil {
				return err
			}
			if !dry {
				if err := c.hooks.RunPostWhenPassive(c.getHookEnvMap(hookEnvMapParams{isPostFailover: true})); err != nil {
					return err
				}
			}
			if err := sendPhase(f, "complete-ack"); err != nil {
				return err
			}
			return nil
		default:
			return fmt.Errorf("unexpected handover phase %q", f.message.Phase)
		}
	}
}

func (s *Server) runDestination() (err error) {
	f := s.failoverStream
	defer func() { abortPeer(f, err) }()
	if s.safety == nil {
		return fmt.Errorf("missing local/independent RPC safety reader")
	}
	if err := receivePhase(f, proofTimeout); err != nil {
		return err
	}
	if f.message.Phase != "hello" {
		return fmt.Errorf("expected capability handshake")
	}
	source := f.message.ActiveNodeInfo
	if source.SolanaValidatorFailoverVersion != pkgconstants.AppVersion {
		return fmt.Errorf("peer application version differs")
	}
	quiet, err := negotiatedQuietSlots(&source, s.passiveNodeInfo, s.skipTowerSync,
		s.rollback.Enabled || f.GetActiveRollbackEnabled(), s.mtlsEnabled)
	if err != nil {
		return err
	}
	// Until rollback has its own acknowledged reverse transaction, an ambiguous
	// failure cannot safely reactivate the original signer, for either client.
	if s.rollback.Enabled || f.GetActiveRollbackEnabled() {
		return fmt.Errorf("automatic rollback is not supported by the fenced protocol; configure rollback.enabled=false")
	}
	if s.mtlsEnabled && s.activeConn != nil {
		certs := s.activeConn.ConnectionState().TLS.PeerCertificates
		if len(certs) == 0 {
			return fmt.Errorf("missing authenticated source certificate")
		}
		if err := certs[0].VerifyHostname(source.PublicIP); err != nil {
			return fmt.Errorf("source certificate does not match advertised host: %w", err)
		}
	}
	activeKey := s.passiveNodeInfo.Identities.Active.PubKey()
	if err := s.safety.CheckReadiness(s.ctx, s.passiveNodeInfo.VoteAccount, activeKey, quiet != 0); err != nil {
		return err
	}
	sourcePassive := source.Identities.Passive.PubKey()
	destinationPassive := s.passiveNodeInfo.Identities.Passive.PubKey()
	if err := f.message.SourceStatus.validate(activeKey, s.maxSlotLag); err != nil {
		return err
	}
	if s.solanaRPCClient != nil {
		node, err := s.solanaRPCClient.NodeFromIPWithExpectedPubkey(source.PublicIP, activeKey)
		if err != nil {
			return err
		}
		if err := validateActiveGossipIdentity(node.IP(), node.PubKey(), source.PublicIP, activeKey); err != nil {
			return err
		}
	}
	local, err := s.safety.Snapshot(s.ctx)
	if err != nil {
		return err
	}
	if err := local.validate(destinationPassive, s.maxSlotLag); err != nil {
		return err
	}
	f.SetPassiveNodeInfo(s.passiveNodeInfo)
	f.SetIsDryRunFailover(s.isDryRunFailover)
	f.SetSkipTowerSync(quiet != 0)
	f.message.RequiredQuietSlots = quiet
	if err := f.ConfirmFailover(s.hooks, s.rollback, source.RPCAddress, s.rpcURL, s.autoConfirm); err != nil {
		return err
	}
	if !s.isDryRunFailover {
		if err := s.hooks.RunPreWhenPassive(s.getHookEnvMap(hookEnvMapParams{isPreFailover: true})); err != nil {
			return err
		}
	}
	f.SetCanProceed(true)
	if err := sendPhase(f, "ready"); err != nil {
		return err
	}
	if err := receivePhase(f, transactionTimeout); err != nil {
		return err
	}
	if f.message.Phase != "demoted" {
		return fmt.Errorf("missing mandatory source-demoted acknowledgement")
	}
	expectedSource := sourcePassive
	if s.isDryRunFailover {
		expectedSource = activeKey
	}
	if err := f.message.SourceStatus.validate(expectedSource, s.maxSlotLag); err != nil {
		return err
	}
	local, err = s.safety.Snapshot(s.ctx)
	if err != nil {
		return err
	}
	if err := local.validate(destinationPassive, s.maxSlotLag); err != nil {
		return err
	}
	// For an Agave tower transfer, exclude votes already possible at the
	// post-demotion anchor. Native mode adds the mandatory lockout interval.
	target := max(f.message.SourceStatus.Processed, f.message.SourceStatus.ClusterProcessed, local.Processed, local.ClusterProcessed)
	if quiet != 0 {
		target, err = guardTarget(f.message.SourceStatus, local)
		if err != nil {
			return err
		}
		f.message.GuardAnchor = target - NativeQuietSlots
		if s.isDryRunFailover {
			s.logger.Infof("dry run: negotiated %d-slot policy; no source fence, slot wait or identity changes performed", quiet)
		} else {
			s.logger.Infof("source demotion verified; finalized slot guard target=%d", target)
		}
	}
	// Save the received tower before later proof messages replace message data.
	towerBytes := append([]byte(nil), f.message.ActiveNodeInfo.TowerFileBytes...)
	towerHash := f.message.ActiveNodeInfo.TowerFileHash
	if !s.isDryRunFailover {
		for sequence := uint64(1); ; sequence++ {
			f.message.Sequence = sequence
			if err := sendPhase(f, "check-source"); err != nil {
				return err
			}
			if err := receivePhase(f, proofTimeout); err != nil {
				return fmt.Errorf("lost source fence proof: %w", err)
			}
			if f.message.Phase != "source-proof" || f.message.Sequence != sequence {
				return fmt.Errorf("invalid source fence proof")
			}
			if err := f.message.SourceStatus.validate(sourcePassive, s.maxSlotLag); err != nil {
				return err
			}
			local, err = s.safety.Snapshot(s.ctx)
			if err != nil {
				return err
			}
			if err := local.validate(destinationPassive, s.maxSlotLag); err != nil {
				return err
			}
			if quiet == 0 || quietPeriodComplete(target, f.message.SourceStatus, local) {
				break
			}
			select {
			case <-s.ctx.Done():
				return s.ctx.Err()
			case <-time.After(s.pollInterval):
			}
		}
		// The wait may cross an epoch or an authority update. Re-read the
		// on-chain authority and genesis immediately before the final mutation.
		if err := s.safety.CheckReadiness(s.ctx, s.passiveNodeInfo.VoteAccount, activeKey, quiet != 0); err != nil {
			return err
		}
		local, err = s.safety.Snapshot(s.ctx)
		if err != nil {
			return err
		}
		if err := local.validate(destinationPassive, s.maxSlotLag); err != nil {
			return err
		}
		if quiet != 0 && !quietPeriodComplete(target, f.message.SourceStatus, local) {
			return fmt.Errorf("finalized slot guard no longer satisfied")
		}
		if s.passiveNodeInfo.Client == "agave" {
			if quiet == 0 {
				if len(towerBytes) == 0 || source.ComputeTowerFileHashFromBytes(towerBytes) != towerHash {
					return fmt.Errorf("invalid source tower payload")
				}
				if err := installTower(s.passiveNodeInfo.TowerFile, towerBytes); err != nil {
					return err
				}
			} else if err := archiveTower(s.passiveNodeInfo.TowerFile); err != nil {
				return err
			}
		}
	}
	f.SetPassiveNodeSetIdentityStartTime()
	command := promotionCommand(s.passiveNodeInfo.SetIdentityCommand, quiet)
	if err := s.runCommand(s.ctx, command, s.isDryRunFailover); err != nil {
		return fmt.Errorf("promotion outcome uncertain; no automatic rollback: %w", err)
	}
	f.SetPassiveNodeSetIdentityEndTime()
	expectedDestination := activeKey
	if s.isDryRunFailover {
		expectedDestination = destinationPassive
	}
	local, err = s.safety.Snapshot(s.ctx)
	if err != nil {
		return fmt.Errorf("cannot verify promotion; keep automation inhibited: %w", err)
	}
	if err := local.validate(expectedDestination, s.maxSlotLag); err != nil {
		return err
	}
	f.SetFailoverEndSlot(local.Processed)
	if !s.isDryRunFailover {
		if s.passiveNodeInfo.VoteAccount != "" {
			if err := s.waitForVote(activeKey, target); err != nil {
				return err
			}
		} else {
			s.logger.Warn("no validator.vote_account configured; completion verifies identity/health/head only")
		}
		if err := s.hooks.RunPostWhenActive(s.getHookEnvMap(hookEnvMapParams{isPostFailover: true})); err != nil {
			return err
		}
	}
	f.SetIsSuccessfullyCompleted(true)
	if err := sendPhase(f, "complete"); err != nil {
		return err
	}
	if err := receivePhase(f, proofTimeout); err != nil {
		return fmt.Errorf("completion acknowledgement lost; keep automation inhibited: %w", err)
	}
	if f.message.Phase != "complete-ack" {
		return fmt.Errorf("invalid completion acknowledgement")
	}
	if s.isDryRunFailover {
		s.logger.Info("dry run verified; identities unchanged")
	} else {
		s.logger.Info("verified handover complete")
	}
	return nil
}

func (s *Server) waitForVote(activeIdentity string, afterSlot uint64) error {
	limit := s.voteTimeout
	if limit == 0 {
		limit = time.Minute
	}
	ctx, cancel := context.WithTimeout(s.ctx, limit)
	defer cancel()
	for {
		status, err := s.safety.Snapshot(ctx)
		if err != nil {
			return fmt.Errorf("post-promotion health/identity unavailable: %w", err)
		}
		if err := status.validate(activeIdentity, s.maxSlotLag); err != nil {
			return err
		}
		advanced, err := s.safety.VoteAdvanced(ctx, s.passiveNodeInfo.VoteAccount, activeIdentity, afterSlot)
		if err != nil {
			return err
		}
		if advanced {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vote account did not advance beyond slot %d before deadline; keep automation inhibited: %w", afterSlot, ctx.Err())
		case <-time.After(s.votePollInterval):
		}
	}
}

func archiveTower(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("tower is not a regular file: %s", path)
	}
	return os.Rename(path, fmt.Sprintf("%s.planned-stale-%d", path, time.Now().UnixNano()))
}

func installTower(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tower-handover-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := archiveTower(path); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Command execution is intentionally separate from protocol messages: neither
// participant ever executes an identity command received from its peer.
