package failover

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"time"

	"github.com/charmbracelet/huh/spinner"
	"github.com/charmbracelet/log"
	"github.com/quic-go/quic-go"
	"github.com/sol-strategies/solana-validator-failover/internal/constants"
	"github.com/sol-strategies/solana-validator-failover/internal/hooks"
	"github.com/sol-strategies/solana-validator-failover/internal/solana"
	"github.com/sol-strategies/solana-validator-failover/internal/style"
	"github.com/sol-strategies/solana-validator-failover/internal/utils"
)

// MonitorConfig holds the configuration for a failover monitor
type MonitorConfig struct {
	CreditSamples CreditSamplesConfig
}

// CreditSamplesConfig holds the configuration for a failover monitor credit samples
type CreditSamplesConfig struct {
	Count            int
	Interval         string
	IntervalDuration time.Duration
}

// ServerConfig is the configuration for the failover server
type ServerConfig struct {
	Safety            safetyReader
	MaxSlotLag        uint64
	Port              int
	HeartbeatInterval string
	StreamTimeout     string
	PassiveNodeInfo   *NodeInfo
	SolanaRPCClient   solana.ClientInterface
	RPCURL            string
	IsDryRunFailover  bool
	Hooks             hooks.FailoverHooks
	MonitorConfig     MonitorConfig
	SkipTowerSync     bool
	AutoConfirm       bool
	Rollback          hooks.RollbackConfig
	// TLSConfig is an optional mTLS config. When non-nil, the server requires
	// connecting clients to present a certificate signed by the configured CA.
	// When nil, an ephemeral self-signed certificate is used (no client auth).
	TLSConfig *tls.Config
}

// Server is the failover server - run by the passive node
type Server struct {
	safety            safetyReader
	maxSlotLag        uint64
	runCommand        func(context.Context, string, bool) error
	voteTimeout       time.Duration
	votePollInterval  time.Duration
	port              int
	listenAddr        string
	tlsConfig         *tls.Config
	transport         *quic.Transport
	listener          *quic.Listener
	heartbeatInterval time.Duration
	streamTimeout     time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
	logger            *log.Logger
	passiveNodeInfo   *NodeInfo
	solanaRPCClient   solana.ClientInterface
	rpcURL            string
	failoverStream    *Stream
	isDryRunFailover  bool
	activeConn        *quic.Conn
	hooks             hooks.FailoverHooks
	monitorConfig     MonitorConfig
	skipTowerSync     bool
	autoConfirm       bool
	rollback          hooks.RollbackConfig
	mtlsEnabled       bool
}

// NewServerFromConfig creates a new failover server from a configuration
func NewServerFromConfig(config ServerConfig) (*Server, error) {
	var serverTLSConfig *tls.Config
	mtlsEnabled := config.TLSConfig != nil
	if mtlsEnabled {
		cloned := config.TLSConfig.Clone()
		cloned.NextProtos = []string{ProtocolName}
		serverTLSConfig = cloned
	} else {
		tlsCert, err := utils.GenerateTLSCertificate()
		if err != nil {
			return nil, err
		}
		serverTLSConfig = &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			NextProtos:   []string{ProtocolName},
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), transactionTimeout)

	s := &Server{
		safety:           config.Safety,
		maxSlotLag:       config.MaxSlotLag,
		runCommand:       runIdentityCommand,
		voteTimeout:      time.Minute,
		votePollInterval: 2 * time.Second,
		port:             config.Port,
		tlsConfig:        serverTLSConfig,
		mtlsEnabled:      mtlsEnabled,
		logger:           log.Default(),
		ctx:              ctx,
		cancel:           cancel,
		passiveNodeInfo:  config.PassiveNodeInfo,
		solanaRPCClient:  config.SolanaRPCClient,
		rpcURL:           config.RPCURL,
		isDryRunFailover: config.IsDryRunFailover,
		hooks:            config.Hooks,
		monitorConfig:    config.MonitorConfig,
		skipTowerSync:    config.SkipTowerSync,
		autoConfirm:      config.AutoConfirm,
		rollback:         config.Rollback,
	}
	if s.maxSlotLag == 0 {
		s.maxSlotLag = DefaultMaxSlotLag
	}

	if s.port == 0 {
		s.port = DefaultPort
	}
	s.listenAddr = fmt.Sprintf(":%d", s.port)

	if config.HeartbeatInterval == "" {
		config.HeartbeatInterval = DefaultHeartbeatIntervalDurationStr
	}

	if config.StreamTimeout == "" {
		config.StreamTimeout = DefaultStreamTimeoutDurationStr
	}

	var err error
	s.heartbeatInterval, err = time.ParseDuration(config.HeartbeatInterval)
	if err != nil {
		return nil, fmt.Errorf("failed to parse heartbeat interval: %v", err)
	}

	s.streamTimeout, err = time.ParseDuration(config.StreamTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to parse stream timeout: %v", err)
	}

	return s, nil
}

// Start starts the failover server
func (s *Server) Start() (err error) {
	defer s.cancel()
	wrapped, err := newBasicPacketConn(fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("create UDP socket: %w", err)
	}
	s.transport = &quic.Transport{Conn: wrapped}
	defer s.transport.Close()
	listener, err := s.transport.Listen(s.tlsConfig, &quic.Config{
		KeepAlivePeriod: s.heartbeatInterval, MaxIdleTimeout: s.streamTimeout,
	})
	if err != nil {
		return fmt.Errorf("create listener: %w", err)
	}
	s.listener = listener
	defer listener.Close()
	s.logger.Infof("listening on port %d for one authenticated handover", s.port)
	// A participant handles one transaction. Shared protocol state is never
	// accessed by concurrent connections or streams.
	conn, err := listener.Accept(s.ctx)
	if err != nil {
		return err
	}
	s.activeConn = conn
	defer func() {
		code := quic.ApplicationErrorCode(0)
		if err != nil {
			code = 1
		}
		_ = conn.CloseWithError(code, "participant finished")
	}()
	stream, err := conn.AcceptStream(s.ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := stream.SetReadDeadline(time.Now().Add(proofTimeout)); err != nil {
		return err
	}
	var kind [1]byte
	if _, err := io.ReadFull(stream, kind[:]); err != nil {
		return err
	}
	if kind[0] != MessageTypeFailoverInitiateRequest {
		return fmt.Errorf("unexpected stream type %d", kind[0])
	}
	if err := readAndCheckWireVersion(stream); err != nil {
		return err
	}
	if err := writeWireVersion(stream); err != nil {
		return err
	}
	s.failoverStream = NewFailoverStream(stream)
	return s.runDestination()
}

func validateActiveGossipIdentity(actualIP, actualPubkey, expectedIP, expectedPubkey string) error {
	if actualIP != expectedIP {
		return fmt.Errorf("active node IP %s does not match expected IP %s", actualIP, expectedIP)
	}
	if actualPubkey != expectedPubkey {
		return fmt.Errorf(
			"active node pubkey %s at IP %s does not match expected pubkey %s",
			actualPubkey,
			actualIP,
			expectedPubkey,
		)
	}
	return nil
}

// confirmGossipNodesPostFailover confirms that the gossip nodes have switched roles post-failover
func (s *Server) confirmGossipNodesPostFailover() {
	var (
		solanaActiveNode                        *solana.Node
		solanaPassiveNode                       *solana.Node
		err                                     error
		isActiveNodeKeySwitchReflectedInGossip  bool
		isPassiveNodeKeySwitchReflectedInGossip bool
	)

	sp := spinner.New().Title(style.RenderPinkString("confirming gossip nodes switched roles..."))
	sp.ActionWithErr(func(ctx context.Context) error {
		maxRetries := 5
		retryCount := 0
		// it can take a few seconds for gossip to update so try to refresh gossip identities a few times before claiming error
		for retryCount < maxRetries {
			retryDelay := time.Duration(1<<(retryCount+1)) * time.Second
			retryCount++
			hasRetriesLeft := retryCount < maxRetries

			// active node is now the old passive node — prefer the expected pubkey to handle
			// dual CRDS entries that briefly coexist during a gossip identity transition
			solanaActiveNode, err = s.solanaRPCClient.NodeFromIPWithExpectedPubkey(
				s.failoverStream.GetPassiveNodeInfo().PublicIP,
				s.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey(),
			)
			if err != nil && hasRetriesLeft {
				sp.Title(style.RenderWarningStringf("(attempt %d of %d) failed to refresh active node info from gossip - retrying", retryCount, maxRetries))
				time.Sleep(retryDelay)
				continue
			}
			if err != nil && !hasRetriesLeft {
				sp.Title(style.RenderErrorStringf("(attempt %d of %d) failed to refresh active node info from gossip - giving up", retryCount, maxRetries))
				s.logger.Error(fmt.Sprintf("(attempt %d of %d) failed to refresh active node info from gossip - giving up", retryCount, maxRetries), "err", err)
				return fmt.Errorf("(attempt %d of %d) failed to refresh active node info from gossip - giving up", retryCount, maxRetries)
			}

			// passive node is now the old active node — prefer the expected pubkey for the same reason
			solanaPassiveNode, err = s.solanaRPCClient.NodeFromIPWithExpectedPubkey(
				s.failoverStream.GetActiveNodeInfo().PublicIP,
				s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey(),
			)
			if err != nil && hasRetriesLeft {
				sp.Title(style.RenderWarningStringf("(attempt %d of %d) failed to refresh fetch passive node info - retrying", retryCount, maxRetries))
				time.Sleep(retryDelay)
				continue
			}
			if err != nil && !hasRetriesLeft {
				sp.Title(style.RenderErrorStringf("(attempt %d of %d) failed to refresh fetch passive node info - giving up", retryCount, maxRetries))
				return fmt.Errorf("(attempt %d of %d) failed to refresh fetch passive node info - giving up", retryCount, maxRetries)
			}

			// check the gossip pubkeys switched
			isActiveNodeKeySwitchReflectedInGossip = solanaActiveNode.PubKey() == s.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey()
			isPassiveNodeKeySwitchReflectedInGossip = solanaPassiveNode.PubKey() == s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey()

			// if the active node key is not reflected in gossip, query gossip again
			if !isActiveNodeKeySwitchReflectedInGossip && hasRetriesLeft {
				sp.Title(style.RenderWarningStringf("(attempt %d of %d) gossip active node %s pubkey does not match expected pubkey: %s != %s - retrying in %s",
					retryCount,
					maxRetries,
					solanaActiveNode.IP(),
					solanaActiveNode.PubKey(),
					s.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey(),
					retryDelay,
				))
				time.Sleep(retryDelay)
				continue
			}

			// if the active node key is not reflected in gossip after retries show error and exit
			if !isActiveNodeKeySwitchReflectedInGossip && !hasRetriesLeft {
				sp.Title(style.RenderErrorStringf("gossip active node %s pubkey does not match expected pubkey: %s != %s - after %d retries",
					solanaActiveNode.IP(),
					solanaActiveNode.PubKey(),
					s.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey(),
					retryCount,
				))
				return fmt.Errorf("gossip active node %s pubkey does not match expected pubkey: %s != %s - after %d retries",
					solanaActiveNode.IP(),
					solanaActiveNode.PubKey(),
					s.failoverStream.GetPassiveNodeInfo().Identities.Active.PubKey(),
					retryCount,
				)
			}

			// if the passive node key is not reflected in gossip, query gossip again
			if !isPassiveNodeKeySwitchReflectedInGossip && hasRetriesLeft {
				sp.Title(style.RenderWarningStringf("(attempt %d of %d) gossip passive node %s pubkey does not match expected pubkey: %s != %s - retrying in %s",
					retryCount,
					maxRetries,
					solanaPassiveNode.IP(),
					solanaPassiveNode.PubKey(),
					s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey(),
					retryDelay,
				))
				time.Sleep(retryDelay)
				continue
			}

			// if the passive node key is not reflected in gossip after retries show error
			if !isPassiveNodeKeySwitchReflectedInGossip && !hasRetriesLeft {
				sp.Title(style.RenderErrorStringf("gossip passive node %s pubkey does not match expected pubkey: %s != %s - after %d retries",
					solanaPassiveNode.IP(),
					solanaPassiveNode.PubKey(),
					s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey(),
					retryCount,
				))
				return fmt.Errorf("gossip passive node %s pubkey does not match expected pubkey: %s != %s - after %d retries",
					solanaPassiveNode.IP(),
					solanaPassiveNode.PubKey(),
					s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey(),
					retryCount,
				)
			}
		}

		return nil
	})

	err = sp.Run()
	if err != nil {
		s.logger.Error("failed to confirm gossip nodes switched roles - potentially serious shit - investigate immediately", "err", err)
	}

	if isActiveNodeKeySwitchReflectedInGossip && isPassiveNodeKeySwitchReflectedInGossip {
		s.logger.Info("gossip confirms nodes switched roles successfully")
	} else {
		s.logger.Error("gossip does not confirm role switch")
	}
}

// getEnvMap returns a map of environment variables to pass to the hooks
func (s *Server) getHookEnvMap(params hookEnvMapParams) (envMap map[string]string) {
	envMap = map[string]string{}

	envMap["IS_DRY_RUN_FAILOVER"] = fmt.Sprintf("%t", params.isDryRunFailover)

	// this node is passive
	if params.isPreFailover {
		envMap["THIS_NODE_ROLE"] = constants.NodeRolePassive
		envMap["PEER_NODE_ROLE"] = constants.NodeRoleActive
	}

	// only show switch to active
	if params.isPostFailover {
		envMap["THIS_NODE_ROLE"] = constants.NodeRoleActive
		envMap["PEER_NODE_ROLE"] = constants.NodeRolePassive
	}

	// this node is passive
	envMap["THIS_NODE_NAME"] = s.passiveNodeInfo.Hostname
	envMap["THIS_NODE_PUBLIC_IP"] = s.passiveNodeInfo.PublicIP
	envMap["THIS_NODE_ACTIVE_IDENTITY_PUBKEY"] = s.passiveNodeInfo.Identities.Active.PubKey()
	envMap["THIS_NODE_ACTIVE_IDENTITY_KEYPAIR_FILE"] = s.passiveNodeInfo.Identities.Active.KeyFile
	envMap["THIS_NODE_PASSIVE_IDENTITY_PUBKEY"] = s.passiveNodeInfo.Identities.Passive.PubKey()
	envMap["THIS_NODE_PASSIVE_IDENTITY_KEYPAIR_FILE"] = s.passiveNodeInfo.Identities.Passive.KeyFile
	envMap["THIS_NODE_CLIENT_VERSION"] = s.passiveNodeInfo.ClientVersion
	envMap["THIS_NODE_CLIENT_VERSION_LOCAL_RPC"] = s.passiveNodeInfo.ClientVersionRPC
	envMap["THIS_NODE_RPC_ADDRESS"] = s.rpcURL

	// peer node is active
	envMap["PEER_NODE_NAME"] = s.failoverStream.GetActiveNodeInfo().Hostname
	envMap["PEER_NODE_PUBLIC_IP"] = s.failoverStream.GetActiveNodeInfo().PublicIP
	envMap["PEER_NODE_ACTIVE_IDENTITY_PUBKEY"] = s.failoverStream.GetActiveNodeInfo().Identities.Active.PubKey()
	envMap["PEER_NODE_PASSIVE_IDENTITY_PUBKEY"] = s.failoverStream.GetActiveNodeInfo().Identities.Passive.PubKey()
	envMap["PEER_NODE_CLIENT_VERSION"] = s.failoverStream.GetActiveNodeInfo().ClientVersion
	envMap["PEER_NODE_CLIENT_VERSION_LOCAL_RPC"] = s.failoverStream.GetActiveNodeInfo().ClientVersionRPC

	return
}
