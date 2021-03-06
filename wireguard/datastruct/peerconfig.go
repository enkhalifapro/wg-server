package datastruct

import (
	"net"
	"time"
)

// A PeerConfig is a WireGuard device peer configuration.
//
// Because the zero value of some Go types may be significant to WireGuard for
// PeerConfig fields, pointer types are used for some of these fields. Only
// pointer fields which are not nil will be applied when configuring a peer.
type PeerConfig struct {
	// PublicKey specifies the public key of this peer.  PublicKey is a
	// mandatory field for all PeerConfigs.
	PublicKey Key

	// Remove specifies if the peer with this public key should be removed
	// from a device's peer list.
	Remove bool

	// UpdateOnly specifies that an operation will only occur on this peer
	// if the peer already exists as part of the interface.
	UpdateOnly bool

	// PresharedKey specifies a peer's preshared key configuration, if not nil.
	//
	// A non-nil, zero-value Key will clear the preshared key.
	PresharedKey *Key

	// Endpoint specifies the endpoint of this peer entry, if not nil.
	Endpoint *net.UDPAddr

	// PersistentKeepaliveInterval specifies the persistent keepalive interval
	// for this peer, if not nil.
	//
	// A non-nil value of 0 will clear the persistent keepalive interval.
	PersistentKeepaliveInterval *time.Duration

	// ReplaceAllowedIPs specifies if the allowed IPs specified in this peer
	// configuration should replace any existing ones, instead of appending them
	// to the allowed IPs list.
	ReplaceAllowedIPs bool

	// AllowedIPs specifies a list of allowed IP addresses in CIDR notation
	// for this peer.
	AllowedIPs []net.IPNet
}

