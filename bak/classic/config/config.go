package config

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
)

const (
	// FuzzModeDrop is a mode in which we randomly drop reads/writes, connections or sleep
	FuzzModeDrop = iota
	// FuzzModeDelay is a mode in which we randomly sleep
	FuzzModeDelay

	// LogFormatPlain is a format for colored text
	LogFormatPlain = "plain"
	// LogFormatJSON is a format for json output
	LogFormatJSON = "json"
)

// NOTE: Most of the structs & relevant comments + the
// default configuration options were used to manually
// generate the config.toml. Please reflect any changes
// made here in the defaultConfigTemplate constant in
// config/toml.go
// NOTE: libs/cli must know to look in the config dir!
var (
	DefaultTendermintDir = ".tendermint"
	defaultConfigDir     = "config"
	defaultDataDir       = "data"

	defaultConfigFileName  = "config.toml"
	defaultGenesisJSONName = "genesis.json"

	defaultPrivValKeyName   = "priv_validator_key.json"
	defaultPrivValStateName = "priv_validator_state.json"

	defaultNodeKeyName  = "node_key.json"
	defaultAddrBookName = "addrbook.json"

	defaultConfigFilePath   = filepath.Join(defaultConfigDir, defaultConfigFileName)
	defaultGenesisJSONPath  = filepath.Join(defaultConfigDir, defaultGenesisJSONName)
	defaultPrivValKeyPath   = filepath.Join(defaultConfigDir, defaultPrivValKeyName)
	defaultPrivValStatePath = filepath.Join(defaultDataDir, defaultPrivValStateName)

	defaultNodeKeyPath  = filepath.Join(defaultConfigDir, defaultNodeKeyName)
	defaultAddrBookPath = filepath.Join(defaultConfigDir, defaultAddrBookName)
)

var (
	oldPrivVal     = "priv_validator.json"
	oldPrivValPath = filepath.Join(defaultConfigDir, oldPrivVal)
)

// Config defines the top level configuration for a Tendermint node
type Config struct {
	// Top level options use an anonymous struct
	BaseConfig `mapstructure:",squash"`

	// Options for services
	RPC       *RPCConfig       `mapstructure:"rpc"`
	P2P       *P2PConfig       `mapstructure:"p2p"`
	Mempool   *MempoolConfig   `mapstructure:"mempool"`
	FastSync  *FastSyncConfig  `mapstructure:"fastsync"`
	Consensus *ConsensusConfig `mapstructure:"consensus"`
	TxIndex   *TxIndexConfig   `mapstructure:"tx_index"`
}

// DefaultConfig returns a default configuration for a Tendermint node
func DefaultConfig() *Config {
	return &Config{
		BaseConfig: DefaultBaseConfig(),
		RPC:        DefaultRPCConfig(),
		P2P:        DefaultP2PConfig(),
		Mempool:    DefaultMempoolConfig(),
		FastSync:   DefaultFastSyncConfig(),
		Consensus:  DefaultConsensusConfig(),
		TxIndex:    DefaultTxIndexConfig(),
	}
}

// TestConfig returns a configuration that can be used for testing
func TestConfig() *Config {
	return &Config{
		BaseConfig: TestBaseConfig(),
		RPC:        TestRPCConfig(),
		P2P:        TestP2PConfig(),
		Mempool:    TestMempoolConfig(),
		FastSync:   TestFastSyncConfig(),
		Consensus:  TestConsensusConfig(),
		TxIndex:    TestTxIndexConfig(),
	}
}

// SetRoot sets the RootDir for all Config structs
func (cfg *Config) SetRoot(root string) *Config {
	cfg.BaseConfig.RootDir = root
	cfg.RPC.RootDir = root
	cfg.P2P.RootDir = root
	cfg.Mempool.RootDir = root
	cfg.Consensus.RootDir = root
	return cfg
}

// ValidateBasic performs basic validation (checking param bounds, etc.) and
// returns an error if any check fails.
func (cfg *Config) ValidateBasic() error {
	if err := cfg.BaseConfig.ValidateBasic(); err != nil {
		return err
	}
	if err := cfg.RPC.ValidateBasic(); err != nil {
		return errors.Wrap(err, "Error in [rpc] section")
	}
	if err := cfg.P2P.ValidateBasic(); err != nil {
		return errors.Wrap(err, "Error in [p2p] section")
	}
	if err := cfg.Mempool.ValidateBasic(); err != nil {
		return errors.Wrap(err, "Error in [mempool] section")
	}
	if err := cfg.FastSync.ValidateBasic(); err != nil {
		return errors.Wrap(err, "Error in [fastsync] section")
	}
	if err := cfg.Consensus.ValidateBasic(); err != nil {
		return errors.Wrap(err, "Error in [consensus] section")
	}
	return nil
}

//-----------------------------------------------------------------------------
// RPCConfig

// RPCConfig defines the configuration options for the Tendermint RPC server
type RPCConfig struct {
	RootDir string `mapstructure:"home"`

	// TCP or UNIX socket address for the RPC server to listen on
	ListenAddress string `mapstructure:"laddr"`

	// A list of origins a cross-domain request can be executed from.
	// If the special '*' value is present in the list, all origins will be allowed.
	// An origin may contain a wildcard (*) to replace 0 or more characters (i.e.: http://*.domain.com).
	// Only one wildcard can be used per origin.
	CORSAllowedOrigins []string `mapstructure:"cors_allowed_origins"`

	// A list of methods the client is allowed to use with cross-domain requests.
	CORSAllowedMethods []string `mapstructure:"cors_allowed_methods"`

	// A list of non simple headers the client is allowed to use with cross-domain requests.
	CORSAllowedHeaders []string `mapstructure:"cors_allowed_headers"`

	// TCP or UNIX socket address for the gRPC server to listen on
	// NOTE: This server only supports /broadcast_tx_commit
	GRPCListenAddress string `mapstructure:"grpc_laddr"`

	// Maximum number of simultaneous connections.
	// Does not include RPC (HTTP&WebSocket) connections. See max_open_connections
	// If you want to accept a larger number than the default, make sure
	// you increase your OS limits.
	// 0 - unlimited.
	GRPCMaxOpenConnections int `mapstructure:"grpc_max_open_connections"`

	// Activate unsafe RPC commands like /dial_persistent_peers and /unsafe_flush_mempool
	Unsafe bool `mapstructure:"unsafe"`

	// Maximum number of simultaneous connections (including WebSocket).
	// Does not include gRPC connections. See grpc_max_open_connections
	// If you want to accept a larger number than the default, make sure
	// you increase your OS limits.
	// 0 - unlimited.
	// Should be < {ulimit -Sn} - {MaxNumInboundPeers} - {MaxNumOutboundPeers} - {N of wal, db and other open files}
	// 1024 - 40 - 10 - 50 = 924 = ~900
	MaxOpenConnections int `mapstructure:"max_open_connections"`

	// Maximum number of unique clientIDs that can /subscribe
	// If you're using /broadcast_tx_commit, set to the estimated maximum number
	// of broadcast_tx_commit calls per block.
	MaxSubscriptionClients int `mapstructure:"max_subscription_clients"`

	// Maximum number of unique queries a given client can /subscribe to
	// If you're using GRPC (or Local RPC client) and /broadcast_tx_commit, set
	// to the estimated maximum number of broadcast_tx_commit calls per block.
	MaxSubscriptionsPerClient int `mapstructure:"max_subscriptions_per_client"`

	// How long to wait for a tx to be committed during /broadcast_tx_commit
	// WARNING: Using a value larger than 10s will result in increasing the
	// global HTTP write timeout, which applies to all connections and endpoints.
	// See https://github.com/tendermint/classic/issues/3435
	TimeoutBroadcastTxCommit time.Duration `mapstructure:"timeout_broadcast_tx_commit"`

	// Maximum size of request body, in bytes
	MaxBodyBytes int64 `mapstructure:"max_body_bytes"`

	// Maximum size of request header, in bytes
	MaxHeaderBytes int `mapstructure:"max_header_bytes"`

	// The path to a file containing certificate that is used to create the HTTPS server.
	// Migth be either absolute path or path related to tendermint's config directory.
	//
	// If the certificate is signed by a certificate authority,
	// the certFile should be the concatenation of the server's certificate, any intermediates,
	// and the CA's certificate.
	//
	// NOTE: both tls_cert_file and tls_key_file must be present for Tendermint to create HTTPS server. Otherwise, HTTP server is run.
	TLSCertFile string `mapstructure:"tls_cert_file"`

	// The path to a file containing matching private key that is used to create the HTTPS server.
	// Migth be either absolute path or path related to tendermint's config directory.
	//
	// NOTE: both tls_cert_file and tls_key_file must be present for Tendermint to create HTTPS server. Otherwise, HTTP server is run.
	TLSKeyFile string `mapstructure:"tls_key_file"`
}

// DefaultRPCConfig returns a default configuration for the RPC server
func DefaultRPCConfig() *RPCConfig {
	return &RPCConfig{
		ListenAddress:          "tcp://127.0.0.1:26657",
		CORSAllowedOrigins:     []string{},
		CORSAllowedMethods:     []string{http.MethodHead, http.MethodGet, http.MethodPost},
		CORSAllowedHeaders:     []string{"Origin", "Accept", "Content-Type", "X-Requested-With", "X-Server-Time"},
		GRPCListenAddress:      "",
		GRPCMaxOpenConnections: 900,

		Unsafe:             false,
		MaxOpenConnections: 900,

		MaxSubscriptionClients:    100,
		MaxSubscriptionsPerClient: 5,
		TimeoutBroadcastTxCommit:  10 * time.Second,

		MaxBodyBytes:   int64(1000000), // 1MB
		MaxHeaderBytes: 1 << 20,        // same as the net/http default

		TLSCertFile: "",
		TLSKeyFile:  "",
	}
}

// TestRPCConfig returns a configuration for testing the RPC server
func TestRPCConfig() *RPCConfig {
	cfg := DefaultRPCConfig()
	cfg.ListenAddress = "tcp://0.0.0.0:36657"
	cfg.GRPCListenAddress = "tcp://0.0.0.0:36658"
	cfg.Unsafe = true
	return cfg
}

// ValidateBasic performs basic validation (checking param bounds, etc.) and
// returns an error if any check fails.
func (cfg *RPCConfig) ValidateBasic() error {
	if cfg.GRPCMaxOpenConnections < 0 {
		return errors.New("grpc_max_open_connections can't be negative")
	}
	if cfg.MaxOpenConnections < 0 {
		return errors.New("max_open_connections can't be negative")
	}
	if cfg.MaxSubscriptionClients < 0 {
		return errors.New("max_subscription_clients can't be negative")
	}
	if cfg.MaxSubscriptionsPerClient < 0 {
		return errors.New("max_subscriptions_per_client can't be negative")
	}
	if cfg.TimeoutBroadcastTxCommit < 0 {
		return errors.New("timeout_broadcast_tx_commit can't be negative")
	}
	if cfg.MaxBodyBytes < 0 {
		return errors.New("max_body_bytes can't be negative")
	}
	if cfg.MaxHeaderBytes < 0 {
		return errors.New("max_header_bytes can't be negative")
	}
	return nil
}

// IsCorsEnabled returns true if cross-origin resource sharing is enabled.
func (cfg *RPCConfig) IsCorsEnabled() bool {
	return len(cfg.CORSAllowedOrigins) != 0
}

func (cfg RPCConfig) KeyFile() string {
	path := cfg.TLSKeyFile
	if filepath.IsAbs(path) {
		return path
	}
	return rootify(filepath.Join(defaultConfigDir, path), cfg.RootDir)
}

func (cfg RPCConfig) CertFile() string {
	path := cfg.TLSCertFile
	if filepath.IsAbs(path) {
		return path
	}
	return rootify(filepath.Join(defaultConfigDir, path), cfg.RootDir)
}

func (cfg RPCConfig) IsTLSEnabled() bool {
	return cfg.TLSCertFile != "" && cfg.TLSKeyFile != ""
}

//-----------------------------------------------------------------------------
// FastSyncConfig

// FastSyncConfig defines the configuration for the Tendermint fast sync service
type FastSyncConfig struct {
	Version string `mapstructure:"version"`
}

// DefaultFastSyncConfig returns a default configuration for the fast sync service
func DefaultFastSyncConfig() *FastSyncConfig {
	return &FastSyncConfig{
		Version: "v0",
	}
}

// TestFastSyncConfig returns a default configuration for the fast sync.
func TestFastSyncConfig() *FastSyncConfig {
	return DefaultFastSyncConfig()
}

// ValidateBasic performs basic validation.
func (cfg *FastSyncConfig) ValidateBasic() error {
	switch cfg.Version {
	case "v0":
		return nil
	default:
		return fmt.Errorf("unknown fastsync version %s", cfg.Version)
	}
}

//-----------------------------------------------------------------------------
// ConsensusConfig

// ConsensusConfig defines the configuration for the Tendermint consensus service,
// including timeouts and details about the WAL and the block structure.
type ConsensusConfig struct {
	RootDir string `mapstructure:"home"`
	WalPath string `mapstructure:"wal_file"`
	walFile string // overrides WalPath if set

	TimeoutPropose        time.Duration `mapstructure:"timeout_propose"`
	TimeoutProposeDelta   time.Duration `mapstructure:"timeout_propose_delta"`
	TimeoutPrevote        time.Duration `mapstructure:"timeout_prevote"`
	TimeoutPrevoteDelta   time.Duration `mapstructure:"timeout_prevote_delta"`
	TimeoutPrecommit      time.Duration `mapstructure:"timeout_precommit"`
	TimeoutPrecommitDelta time.Duration `mapstructure:"timeout_precommit_delta"`
	TimeoutCommit         time.Duration `mapstructure:"timeout_commit"`

	// Make progress as soon as we have all the precommits (as if TimeoutCommit = 0)
	SkipTimeoutCommit bool `mapstructure:"skip_timeout_commit"`

	// EmptyBlocks mode and possible interval between empty blocks
	CreateEmptyBlocks         bool          `mapstructure:"create_empty_blocks"`
	CreateEmptyBlocksInterval time.Duration `mapstructure:"create_empty_blocks_interval"`

	// Reactor sleep duration parameters
	PeerGossipSleepDuration     time.Duration `mapstructure:"peer_gossip_sleep_duration"`
	PeerQueryMaj23SleepDuration time.Duration `mapstructure:"peer_query_maj23_sleep_duration"`
}

// DefaultConsensusConfig returns a default configuration for the consensus service
func DefaultConsensusConfig() *ConsensusConfig {
	return &ConsensusConfig{
		WalPath:                     filepath.Join(defaultDataDir, "cs.wal", "wal"),
		TimeoutPropose:              3000 * time.Millisecond,
		TimeoutProposeDelta:         500 * time.Millisecond,
		TimeoutPrevote:              1000 * time.Millisecond,
		TimeoutPrevoteDelta:         500 * time.Millisecond,
		TimeoutPrecommit:            1000 * time.Millisecond,
		TimeoutPrecommitDelta:       500 * time.Millisecond,
		TimeoutCommit:               1000 * time.Millisecond,
		SkipTimeoutCommit:           false,
		CreateEmptyBlocks:           true,
		CreateEmptyBlocksInterval:   0 * time.Second,
		PeerGossipSleepDuration:     100 * time.Millisecond,
		PeerQueryMaj23SleepDuration: 2000 * time.Millisecond,
	}
}

// TestConsensusConfig returns a configuration for testing the consensus service
func TestConsensusConfig() *ConsensusConfig {
	cfg := DefaultConsensusConfig()
	cfg.TimeoutPropose = 40 * time.Millisecond
	cfg.TimeoutProposeDelta = 1 * time.Millisecond
	cfg.TimeoutPrevote = 10 * time.Millisecond
	cfg.TimeoutPrevoteDelta = 1 * time.Millisecond
	cfg.TimeoutPrecommit = 10 * time.Millisecond
	cfg.TimeoutPrecommitDelta = 1 * time.Millisecond
	cfg.TimeoutCommit = 10 * time.Millisecond
	cfg.SkipTimeoutCommit = true
	cfg.PeerGossipSleepDuration = 5 * time.Millisecond
	cfg.PeerQueryMaj23SleepDuration = 250 * time.Millisecond
	return cfg
}

// WaitForTxs returns true if the consensus should wait for transactions before entering the propose step
func (cfg *ConsensusConfig) WaitForTxs() bool {
	return !cfg.CreateEmptyBlocks || cfg.CreateEmptyBlocksInterval > 0
}

// Propose returns the amount of time to wait for a proposal
func (cfg *ConsensusConfig) Propose(round int) time.Duration {
	return time.Duration(
		cfg.TimeoutPropose.Nanoseconds()+cfg.TimeoutProposeDelta.Nanoseconds()*int64(round),
	) * time.Nanosecond
}

// Prevote returns the amount of time to wait for straggler votes after receiving any +2/3 prevotes
func (cfg *ConsensusConfig) Prevote(round int) time.Duration {
	return time.Duration(
		cfg.TimeoutPrevote.Nanoseconds()+cfg.TimeoutPrevoteDelta.Nanoseconds()*int64(round),
	) * time.Nanosecond
}

// Precommit returns the amount of time to wait for straggler votes after receiving any +2/3 precommits
func (cfg *ConsensusConfig) Precommit(round int) time.Duration {
	return time.Duration(
		cfg.TimeoutPrecommit.Nanoseconds()+cfg.TimeoutPrecommitDelta.Nanoseconds()*int64(round),
	) * time.Nanosecond
}

// Commit returns the amount of time to wait for straggler votes after receiving +2/3 precommits for a single block (ie. a commit).
func (cfg *ConsensusConfig) Commit(t time.Time) time.Time {
	return t.Add(cfg.TimeoutCommit)
}

// WalFile returns the full path to the write-ahead log file
func (cfg *ConsensusConfig) WalFile() string {
	if cfg.walFile != "" {
		return cfg.walFile
	}
	return rootify(cfg.WalPath, cfg.RootDir)
}

// SetWalFile sets the path to the write-ahead log file
func (cfg *ConsensusConfig) SetWalFile(walFile string) {
	cfg.walFile = walFile
}

// ValidateBasic performs basic validation (checking param bounds, etc.) and
// returns an error if any check fails.
func (cfg *ConsensusConfig) ValidateBasic() error {
	if cfg.TimeoutPropose < 0 {
		return errors.New("timeout_propose can't be negative")
	}
	if cfg.TimeoutProposeDelta < 0 {
		return errors.New("timeout_propose_delta can't be negative")
	}
	if cfg.TimeoutPrevote < 0 {
		return errors.New("timeout_prevote can't be negative")
	}
	if cfg.TimeoutPrevoteDelta < 0 {
		return errors.New("timeout_prevote_delta can't be negative")
	}
	if cfg.TimeoutPrecommit < 0 {
		return errors.New("timeout_precommit can't be negative")
	}
	if cfg.TimeoutPrecommitDelta < 0 {
		return errors.New("timeout_precommit_delta can't be negative")
	}
	if cfg.TimeoutCommit < 0 {
		return errors.New("timeout_commit can't be negative")
	}
	if cfg.CreateEmptyBlocksInterval < 0 {
		return errors.New("create_empty_blocks_interval can't be negative")
	}
	if cfg.PeerGossipSleepDuration < 0 {
		return errors.New("peer_gossip_sleep_duration can't be negative")
	}
	if cfg.PeerQueryMaj23SleepDuration < 0 {
		return errors.New("peer_query_maj23_sleep_duration can't be negative")
	}
	return nil
}

//-----------------------------------------------------------------------------
// TxIndexConfig

// TxIndexConfig defines the configuration for the transaction indexer,
// including tags to index.
type TxIndexConfig struct {
	// What indexer to use for transactions
	//
	// Options:
	//   1) "null"
	//   2) TODO other backends will be provided soon.
	Indexer string `mapstructure:"indexer"`
}

// DefaultTxIndexConfig returns a default configuration for the transaction indexer.
func DefaultTxIndexConfig() *TxIndexConfig {
	return &TxIndexConfig{
		Indexer: "null",
	}
}

// TestTxIndexConfig returns a default configuration for the transaction indexer.
func TestTxIndexConfig() *TxIndexConfig {
	return DefaultTxIndexConfig()
}

//-----------------------------------------------------------------------------
// Utils

// helper function to make config creation independent of root dir
func rootify(path, root string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

//-----------------------------------------------------------------------------
// Moniker

var defaultMoniker = getDefaultMoniker()

// getDefaultMoniker returns a default moniker, which is the host name. If runtime
// fails to get the host name, "anonymous" will be returned.
func getDefaultMoniker() string {
	moniker, err := os.Hostname()
	if err != nil {
		moniker = "anonymous"
	}
	return moniker
}
