package config

import (
	"github.com/massnetorg/mass-core/consensus"
	"github.com/massnetorg/mass-core/wire"
)

const (
	defaultChainTag          = "mainnet"
	defaultBlockMinSize      = 0
	defaultBlockMaxSize      = wire.MaxBlockPayload
	defaultBlockPrioritySize = consensus.DefaultBlockPrioritySize
)

var (
	FreeTxRelayLimit         = 15.0
	AddrIndex                = true
	NoRelayPriority          = true
	BlockPrioritySize uint32 = defaultBlockPrioritySize
	BlockMinSize      uint32 = defaultBlockMinSize
	BlockMaxSize      uint32 = defaultBlockMaxSize
	MaxPeers                 = 50
	Moniker                  = "anonymous"
	ChainTag                 = defaultChainTag
)

type Config struct {
	Chain     *Chain     `json:"chain"`
	Metrics   *Metrics   `json:"metrics"`
	P2P       *P2P       `json:"p2p"`
	Log       *Log       `json:"log"`
	Datastore *Datastore `json:"datastore"`
}

type Chain struct {
	DisableCheckpoints bool     `json:"disable_checkpoints"`
	AddCheckpoints     []string `json:"add_checkpoints"`
}

type P2P struct {
	Seeds                string   `json:"seeds"`
	AddPeer              []string `json:"add_peer"`
	SkipUpnp             bool     `json:"skip_upnp"`
	HandshakeTimeout     uint32   `json:"handshake_timeout"`
	DialTimeout          uint32   `json:"dial_timeout"`
	VaultMode            bool     `json:"vault_mode"`
	ListenAddress        string   `json:"listen_address"`
	Whitelist            []string `json:"whitelist"`
	IgnoreTransactionMsg bool     `json:"ignore_transaction_message"`
}

type Log struct {
	LogDir        string `json:"log_dir"`
	LogLevel      string `json:"log_level"`
	DisableCPrint bool   `json:"disable_cprint"`
}

type Datastore struct {
	Dir    string `json:"dir"`
	DBType string `json:"db_type"`
}

type Metrics struct {
	ProfilePort string `json:"profile_port"`
}

var (
	knownDbTypes                 = []string{"leveldb", "memdb"}
	HDCoinTypeTestNet     uint32 = 1
	HDCoinTypeMassMainNet uint32 = 297
)

// validDbType returns whether or not dbType is a supported database type.
func validDbType(dbType string) bool {
	for _, knownType := range knownDbTypes {
		if dbType == knownType {
			return true
		}
	}

	return false
}
