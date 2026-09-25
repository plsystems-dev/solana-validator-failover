package failover

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/log"
	solanago "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/quic-go/quic-go"
	"github.com/sol-strategies/solana-validator-failover/internal/constants"
	"github.com/sol-strategies/solana-validator-failover/internal/hooks"
	"github.com/sol-strategies/solana-validator-failover/internal/solana"
	"github.com/sol-strategies/solana-validator-failover/internal/style"
)

// ClientConfig is the configuration for the failover client, client is always the active node
type ClientConfig struct {
	Safety                         safetyReader
	MaxSlotLag                     uint64
	ServerName                     string
	ServerAddress                  string
	ActiveNodeInfo                 *NodeInfo
	MinTimeToLeaderSlot            time.Duration
	WaitMinTimeToLeaderSlotEnabled bool
	Hooks                          hooks.FailoverHooks
	LocalRPCClient                 *rpc.Client
	SolanaRPCClient                solana.ClientInterface
	RPCURL                         string
	SkipTowerSync                  bool
	Rollback                       hooks.RollbackConfig
	// TLSConfig is an optional mTLS config. When non-nil, the client presents its
	// certificate to the server and verifies the server's certificate against the CA.
	// When nil, server certificate verification is skipped (InsecureSkipVerify).
	TLSConfig *tls.Config
}

// Client is the failover client - an active node connects to a passive node server to handover as active
type Client struct {
	safety                         safetyReader
	maxSlotLag                     uint64
	transport                      *quic.Transport
	runCommand                     func(context.Context, string, bool) error
	Conn                           *quic.Conn
	ctx                            context.Context
	cancel                         context.CancelFunc
	logger                         *log.Logger
	activeNodeInfo                 *NodeInfo
	failoverStream                 *Stream
	hooks                          hooks.FailoverHooks
	minTimeToLeaderSlot            time.Duration
	waitMinTimeToLeaderSlotEnabled bool
	localRPCClient                 *rpc.Client
	solanaRPCClient                solana.ClientInterface
	rpcURL                         string
	serverName                     string
	serverAddress                  string
	skipTowerSync                  bool
	rollback                       hooks.RollbackConfig
	tlsConfig                      *tls.Config // non-nil when mTLS is enabled
}

// NewClientFromConfig creates a new QUIC client from a configuration
func NewClientFromConfig(config ClientConfig) (client *Client, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), transactionTimeout)

	var clientTLSConfig *tls.Config
	if config.TLSConfig != nil {
		cloned := config.TLSConfig.Clone()
		cloned.NextProtos = []string{ProtocolName}
		clientTLSConfig = cloned
	}

	client = &Client{
		safety:                         config.Safety,
		maxSlotLag:                     config.MaxSlotLag,
		runCommand:                     runIdentityCommand,
		logger:                         log.Default(),
		ctx:                            ctx,
		cancel:                         cancel,
		activeNodeInfo:                 config.ActiveNodeInfo,
		hooks:                          config.Hooks,
		minTimeToLeaderSlot:            config.MinTimeToLeaderSlot,
		waitMinTimeToLeaderSlotEnabled: config.WaitMinTimeToLeaderSlotEnabled,
		localRPCClient:                 config.LocalRPCClient,
		solanaRPCClient:                config.SolanaRPCClient,
		rpcURL:                         config.RPCURL,
		serverName:                     config.ServerName,
		serverAddress:                  config.ServerAddress,
		skipTowerSync:                  config.SkipTowerSync,
		rollback:                       config.Rollback,
		tlsConfig:                      clientTLSConfig,
	}
	if client.maxSlotLag == 0 {
		client.maxSlotLag = DefaultMaxSlotLag
	}

	err = client.connectToServer()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}

	client.logger.Debugf("connected to %s", style.RenderPassiveString(config.ServerName, false))

	return client, nil
}

// Start starts the QUIC client
func (c *Client) Start() (err error) {
	defer c.cancel()
	defer func() {
		code := quic.ApplicationErrorCode(0)
		if err != nil {
			code = 1
		}
		_ = c.Conn.CloseWithError(code, "participant finished")
	}()
	if c.transport != nil {
		defer c.transport.Close()
	}
	stream, err := c.Conn.OpenStreamSync(c.ctx)
	if err != nil {
		return fmt.Errorf("open handover stream: %w", err)
	}
	defer stream.Close()
	if _, err := stream.Write([]byte{MessageTypeFailoverInitiateRequest}); err != nil {
		return err
	}
	if err := writeWireVersion(stream); err != nil {
		return err
	}
	c.failoverStream = NewFailoverStream(stream)
	if err := c.runSource(); err != nil {
		return err
	}
	// Do not close the connection immediately after queuing complete-ack:
	// that can discard the acknowledgement before the destination reads it.
	// Only its successful, post-ack close confirms protocol completion.
	select {
	case <-c.Conn.Context().Done():
		cause := context.Cause(c.Conn.Context())
		var applicationError *quic.ApplicationError
		if errors.As(cause, &applicationError) && applicationError.ErrorCode == 0 {
			return nil
		}
		return fmt.Errorf("destination did not close successfully: %w", cause)
	case <-time.After(proofTimeout):
		return fmt.Errorf("destination completion close timed out")
	}
}

// waitUntilStartOfNextSlot waits until the start of the next slot
// this is important to try to start a failover early in the slot to avoid missing it
// It polls getSlot() to detect when the slot changes and returns the new slot number,
// which naturally gets us well within the first few milliseconds of the new slot
// should get us in within the first 10ms of the next slot on average
func (c *Client) waitUntilStartOfNextSlot() (newSlot uint64, err error) {
	c.logger.Debug("waiting until start of next slot")

	// Get the current slot number
	currentSlot, err := c.solanaRPCClient.GetCurrentSlot()
	if err != nil {
		return 0, fmt.Errorf("failed to get current slot: %w", err)
	}

	// Poll getSlot() to detect when the slot changes.
	// getSlot() is a lightweight local RPC call so 10ms polling is cheap and gives
	// ~5ms average detection lag vs ~25ms at the previous 50ms interval.
	// On RPC error use a longer back-off to avoid hammering a struggling local node.
	const (
		pollInterval       = 10 * time.Millisecond
		errorRetryInterval = 50 * time.Millisecond
	)
	for {
		slot, err := c.solanaRPCClient.GetCurrentSlot()
		if err != nil {
			c.logger.Debug("failed to get slot, retrying", "err", err)
			time.Sleep(errorRetryInterval)
			continue
		}

		// Slot has changed, we're now in the next slot
		if slot > currentSlot {
			c.logger.Debug("slot transition detected, proceeding", "old_slot", currentSlot, "new_slot", slot)
			return slot, nil
		}

		// Still in the same slot, continue polling
		time.Sleep(pollInterval)
	}
}

// waitMinTimeToLeaderSlot waits until the next leader slot is at least the minimum time to leader slot
func (c *Client) waitMinTimeToLeaderSlot() (err error) {
	pubkey, err := solanago.PublicKeyFromBase58(c.activeNodeInfo.Identities.Active.PubKey())
	if err != nil {
		return fmt.Errorf("failed to parse active identity pubkey: %w", err)
	}

	if !c.waitMinTimeToLeaderSlotEnabled {
		c.logger.Debug("min time to leader slot check disabled, skipping wait")
		isOnSchedule, timeToNext, queryErr := c.solanaRPCClient.GetTimeToNextLeaderSlotForPubkey(pubkey)
		if queryErr != nil {
			c.logger.Warn("could not query next leader slot", "err", queryErr)
		} else if !isOnSchedule {
			c.logger.Info("not on leader schedule")
		} else {
			c.logger.Infof("next leader slot in %s", timeToNext.Round(time.Second))
		}
		return nil
	}

	c.logger.Debugf("ensuring next leader slot is at least %s in the future", c.minTimeToLeaderSlot.String())
	sp := spinner.New().TitleStyle(style.SpinnerTitleStyle).Title(style.RenderPinkString("checking next leader slot..."))
	maxRetries := 10
	var calculatedTimeToNextLeaderSlot time.Duration
	var isOnLeaderSchedule bool
	sp.ActionWithErr(func(ctx context.Context) error {
		sleepDuration := 2 * time.Second
		remainingRetries := maxRetries
		stringMinTimeToLeaderSlot := c.minTimeToLeaderSlot.Round(time.Second).String()

		for {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			onSchedule, timeToNextLeaderSlot, err := c.solanaRPCClient.GetTimeToNextLeaderSlotForPubkey(pubkey)
			if err != nil {
				if remainingRetries == 0 {
					return fmt.Errorf("failed to get time to next leader slot: %w", err)
				}
				log.Debug("failed to get time to next leader slot", "err", err)
				sp.Title(style.RenderErrorStringf(
					"Failed to get time to next leader slot, retrying in %s (%d retries left): %s",
					sleepDuration.String(),
					remainingRetries,
					err.Error(),
				))
				remainingRetries--
				time.Sleep(sleepDuration)
				continue
			}

			if !onSchedule {
				sp.Title(style.RenderPinkString("not on leader schedule, skipping wait"))
				return nil
			}

			isOnLeaderSchedule = true
			stringTimeToNextLeaderSlot := timeToNextLeaderSlot.Round(time.Second).String()

			if timeToNextLeaderSlot < c.minTimeToLeaderSlot {
				sp.Title(style.RenderPinkString(fmt.Sprintf("next leader slot in %s, waiting for it before proceeding...", stringTimeToNextLeaderSlot)))
				time.Sleep(sleepDuration)
				continue
			}

			calculatedTimeToNextLeaderSlot = timeToNextLeaderSlot
			sp.Title(style.RenderPinkString(fmt.Sprintf("next leader slot in %s > %s, proceeding...", stringTimeToNextLeaderSlot, stringMinTimeToLeaderSlot)))
			return nil
		}
	})

	err = sp.Run()
	if err != nil {
		return fmt.Errorf("failed to wait for next leader slot: %w", err)
	}

	if !isOnLeaderSchedule {
		c.logger.Info("not on leader schedule")
	} else {
		c.logger.Infof("next leader slot in %s", calculatedTimeToNextLeaderSlot.Round(time.Second))
	}

	return nil
}

// getEnvMap returns a map of environment variables to pass to the hooks
func (c *Client) getHookEnvMap(params hookEnvMapParams) (envMap map[string]string) {
	envMap = map[string]string{}

	envMap["IS_DRY_RUN_FAILOVER"] = fmt.Sprintf("%t", params.isDryRunFailover)

	// this node is active
	if params.isPreFailover {
		envMap["THIS_NODE_ROLE"] = constants.NodeRoleActive
		envMap["PEER_NODE_ROLE"] = constants.NodeRolePassive
	}

	// only show switch to passive
	if params.isPostFailover {
		envMap["THIS_NODE_ROLE"] = constants.NodeRolePassive
		envMap["PEER_NODE_ROLE"] = constants.NodeRoleActive
	}

	// this node is active
	envMap["THIS_NODE_NAME"] = c.activeNodeInfo.Hostname
	envMap["THIS_NODE_PUBLIC_IP"] = c.activeNodeInfo.PublicIP
	envMap["THIS_NODE_ACTIVE_IDENTITY_PUBKEY"] = c.activeNodeInfo.Identities.Active.PubKey()
	envMap["THIS_NODE_ACTIVE_IDENTITY_KEYPAIR_FILE"] = c.activeNodeInfo.Identities.Active.KeyFile
	envMap["THIS_NODE_PASSIVE_IDENTITY_PUBKEY"] = c.activeNodeInfo.Identities.Passive.PubKey()
	envMap["THIS_NODE_PASSIVE_IDENTITY_KEYPAIR_FILE"] = c.activeNodeInfo.Identities.Passive.KeyFile
	envMap["THIS_NODE_CLIENT_VERSION"] = c.activeNodeInfo.ClientVersion
	envMap["THIS_NODE_CLIENT_VERSION_LOCAL_RPC"] = c.activeNodeInfo.ClientVersionRPC
	envMap["THIS_NODE_RPC_ADDRESS"] = c.rpcURL

	// peer node
	envMap["PEER_NODE_NAME"] = c.failoverStream.GetPassiveNodeInfo().Hostname
	envMap["PEER_NODE_PUBLIC_IP"] = c.failoverStream.GetPassiveNodeInfo().PublicIP
	envMap["PEER_NODE_ACTIVE_IDENTITY_PUBKEY"] = c.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey()
	envMap["PEER_NODE_PASSIVE_IDENTITY_PUBKEY"] = c.failoverStream.GetPassiveNodeInfo().Identities.Passive.PubKey()
	envMap["PEER_NODE_CLIENT_VERSION"] = c.failoverStream.GetPassiveNodeInfo().ClientVersion
	envMap["PEER_NODE_CLIENT_VERSION_LOCAL_RPC"] = c.failoverStream.GetPassiveNodeInfo().ClientVersionRPC

	return envMap
}

// connectToServer waits until a QUIC server is listening on the given address
// It shows a spinner and attempts the actual QUIC connection, retrying on error until successful
// This allows the client to start independet of the server being ready to accept connections and latches
// onto the server as soon as it is ready
func (c *Client) connectToServer() error {
	ctx, cancel := context.WithTimeout(c.ctx, 2*time.Minute)
	defer cancel()
	var lastErr error
	for {
		if err := c.tryQUICConnectionContext(ctx); err == nil {
			return nil
		} else {
			lastErr = err
			if isALPNMismatch(err) {
				return fmt.Errorf("incompatible peer protocol: %w", err)
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("peer connection deadline: %w (last error: %v)", ctx.Err(), lastErr)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// tryQUICConnection attempts the actual QUIC connection that will be used.
// It uses a basicPacketConn wrapper to avoid quic-go's OOB (recvmsg/sendmsg)
// optimizations that fail on virtual network interfaces like Tailscale/WireGuard.
func (c *Client) tryQUICConnection() error { return c.tryQUICConnectionContext(c.ctx) }

func (c *Client) tryQUICConnectionContext(ctx context.Context) error {
	udpAddr, err := net.ResolveUDPAddr("udp4", c.serverAddress)
	if err != nil {
		c.logger.Debug("failed to resolve server address", "err", err, "address", c.serverAddress)
		return err
	}

	wrapped, err := newBasicPacketConn(":0")
	if err != nil {
		c.logger.Debug("failed to create UDP socket", "err", err)
		return err
	}

	tr := &quic.Transport{Conn: wrapped}

	quicTLSConfig := c.tlsConfig
	if quicTLSConfig == nil {
		quicTLSConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentional fallback when mTLS is not configured
			NextProtos:         []string{ProtocolName},
		}
	}

	attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(attempt, udpAddr, quicTLSConfig, nil)
	if err != nil {
		tr.Close()

		c.logger.Debug("QUIC server not ready, retrying...", "err", err, "address", c.serverAddress)
		return err
	}

	if c.tlsConfig != nil {
		tlsState := conn.ConnectionState().TLS
		if len(tlsState.PeerCertificates) > 0 {
			peer := tlsState.PeerCertificates[0]
			c.logger.Info("mTLS: server certificate verified",
				"remote_addr", conn.RemoteAddr().String(),
				"subject", peer.Subject.String(),
				"issuer", peer.Issuer.String(),
				"expires", peer.NotAfter,
			)
		}
	}

	c.Conn = conn
	c.transport = tr
	return nil
}
