package p2p

import (
	"fmt"
	"net"
	"strconv"

	crypto "github.com/massnetorg/tendermint/go-crypto"
)

const maxNodeInfoSize = 10240 // 10Kb

//NodeInfo peer node info
type NodeInfo struct {
	PubKey     crypto.PubKeyEd25519 `json:"pub_key"`
	Moniker    string               `json:"moniker"`
	Network    string               `json:"network"`
	RemoteAddr string               `json:"remote_addr"`
	ListenAddr string               `json:"listen_addr"`
	Version    string               `json:"version"` // major.minor.revision
	Other      []string             `json:"other"`   // other application specific data
}

// CompatibleWith checks if two NodeInfo are compatible with each other.
func (info *NodeInfo) CompatibleWith(other *NodeInfo) error {
	if info.Network != other.Network {
		return fmt.Errorf("peer is on a different network. Peer network: %v, node network: %v", other.Network, info.Network)
	}
	if len(other.Version) == 0 || info.Version[0] != other.Version[0] {
		return fmt.Errorf("major version is not compatible, peer version: %s, node version: %s", other.Version, info.Version)
	}
	return nil
}

//ListenHost peer listener ip address
func (info *NodeInfo) ListenHost() string {
	host, _, _ := net.SplitHostPort(info.ListenAddr)
	return host
}

//ListenPort peer listener port
func (info *NodeInfo) ListenPort() int {
	_, port, _ := net.SplitHostPort(info.ListenAddr)
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return -1
	}
	return portInt
}

//RemoteAddrHost peer external ip address
func (info *NodeInfo) RemoteAddrHost() string {
	host, _, _ := net.SplitHostPort(info.RemoteAddr)
	return host
}

//String representation
func (info NodeInfo) String() string {
	return fmt.Sprintf("NodeInfo{pk: %v, moniker: %v, network: %v [listen %v], version: %v (%v)}", info.PubKey, info.Moniker, info.Network, info.ListenAddr, info.Version, info.Other)
}
