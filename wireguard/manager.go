package wireguard

import (
	"fmt"
	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nlenc"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"syscall"
	"unsafe"
	"wg-server/wireguard/datastruct"
)

// Manager for controlling wg interface
type Manager struct {
	conn       *genetlink.Conn
	family     genetlink.Family
	interfaces []string
}

// NewManager creates a new wg Manager instance
func NewManager() (*Manager, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	f, err := c.GetFamily(datastruct.GenlName)
	if err != nil {
		return nil, err
	}

	interfaces, err := rtnlInterfaces()
	if err != nil {
		return nil, err
	}

	return &Manager{
		conn:       c,
		family:     f,
		interfaces: interfaces,
	}, nil
}

// Devices gets valid wireGaurd interfaces
func (m *Manager) Devices() ([]*datastruct.Device, error) {

	ds := make([]*datastruct.Device, 0, len(m.interfaces))
	for _, ifi := range m.interfaces {
		d, err := m.Device(ifi)
		if err != nil {
			return nil, err
		}

		ds = append(ds, d)
	}

	return ds, nil
}

// Device implements wginternal.Client.
func (m *Manager) Device(name string) (*datastruct.Device, error) {
	// Don't bother querying netlink with empty input.
	if name == "" {
		return nil, os.ErrNotExist
	}

	flags := netlink.Request | netlink.Dump

	// Fetching a device by interface index is possible as well, but we only
	// support fetching by name as it seems to be more convenient in general.
	b, err := netlink.MarshalAttributes([]netlink.Attribute{{
		Type: datastruct.DeviceAIfname,
		Data: nlenc.Bytes(name),
	}})
	if err != nil {
		return nil, err
	}

	msgs, err := m.execute(datastruct.CmdGetDevice, flags, b)
	if err != nil {
		return nil, err
	}

	return parseDevice(msgs)
}

// ConfigureDevice sets wg configuration
func (m *Manager) ConfigureDevice(name string, cfg datastruct.DeviceConfig) error {
	// Large configurations are split into batches for use with netlink.
	for _, b := range buildBatches(cfg) {
		attrs, err := configAttrs(name, b)
		if err != nil {
			return err
		}

		// Request acknowledgement of our request from netlink, even though the
		// output messages are unused.  The netlink package checks and trims the
		// status code value.
		flags := netlink.Request | netlink.Acknowledge
		if _, err := m.execute(datastruct.CmdSetDevice, flags, attrs); err != nil {
			fmt.Println("errr111111---------")
			fmt.Println(datastruct.CmdSetDevice)
			fmt.Println(flags)
			fmt.Println(attrs)
			fmt.Println("--------")
			return err
		}
	}

	return nil
}

// Close netlink connection
func (m *Manager) Close() error {
	return m.conn.Close()
}

// configAttrs creates the required encoded netlink attributes to configure
// the device specified by name using the non-nil fields in cfg.
func configAttrs(name string, cfg datastruct.DeviceConfig) ([]byte, error) {
	ae := netlink.NewAttributeEncoder()
	fmt.Println("atttttttttttttttrrrrrrrrrr")
	ae.String(datastruct.DeviceAIfname, name)
	fmt.Println(name)
	if cfg.PrivateKey != nil {
		fmt.Println("in priv key")
		fmt.Println(cfg.PrivateKey)
		ae.Bytes(datastruct.DeviceAPrivateKey, (*cfg.PrivateKey)[:])
	}

	if cfg.ListenPort != nil {

		fmt.Println("in poooort")
		fmt.Println(*cfg.ListenPort)
		ae.Uint16(datastruct.DeviceAListenPort, uint16(*cfg.ListenPort))
	}

	if cfg.FirewallMark != nil {
		ae.Uint32(datastruct.DeviceAFwmark, uint32(*cfg.FirewallMark))
	}

	if cfg.ReplacePeers {
		ae.Uint32(datastruct.DeviceAFlags, datastruct.DeviceFReplacePeers)
	}

	// Only apply peer attributes if necessary.
	if len(cfg.Peers) > 0 {
		ae.Nested(datastruct.DeviceAPeers, func(nae *netlink.AttributeEncoder) error {
			// Netlink arrays use type as an array index.
			for i, p := range cfg.Peers {
				nae.Nested(uint16(i), func(nnae *netlink.AttributeEncoder) error {
					return encodePeer(nnae, p)
				})
			}

			return nil
		})
	}

	return ae.Encode()
}

// encodePeer converts a PeerConfig into netlink attribute encoder bytes.
func encodePeer(ae *netlink.AttributeEncoder, p datastruct.PeerConfig) error {
	ae.Bytes(datastruct.PeerAPublicKey, p.PublicKey[:])

	// Flags are stored in a single attribute.
	var flags uint32
	if p.Remove {
		flags |= datastruct.PeerFRemoveMe
	}
	if p.ReplaceAllowedIPs {
		flags |= datastruct.PeerFReplaceAllowedips
	}
	if p.UpdateOnly {
		flags |= datastruct.PeerFUpdateOnly
	}
	if flags != 0 {
		ae.Uint32(datastruct.PeerAFlags, flags)
	}

	if p.PresharedKey != nil {
		ae.Bytes(datastruct.PeerAPresharedKey, (*p.PresharedKey)[:])
	}

	if p.Endpoint != nil {
		ae.Do(datastruct.PeerAEndpoint, func() ([]byte, error) {
			return sockaddrBytes(*p.Endpoint)
		})
	}

	if p.PersistentKeepaliveInterval != nil {
		ae.Uint16(datastruct.PeerAPersistentKeepaliveInterval, uint16(p.PersistentKeepaliveInterval.Seconds()))
	}

	// Only apply allowed IPs if necessary.
	if len(p.AllowedIPs) > 0 {
		ae.Nested(datastruct.PeerAAllowedips, func(nae *netlink.AttributeEncoder) error {
			return encodeAllowedIPs(nae, p.AllowedIPs)
		})
	}

	return nil
}

// sockaddrBytes converts a net.UDPAddr to raw sockaddr_in or sockaddr_in6 bytes.
func sockaddrBytes(endpoint net.UDPAddr) ([]byte, error) {
	if !isValidIP(endpoint.IP) {
		return nil, fmt.Errorf("wglinux: invalid endpoint IP: %s", endpoint.IP.String())
	}

	// Is this an IPv6 address?
	if isIPv6(endpoint.IP) {
		var addr [16]byte
		copy(addr[:], endpoint.IP.To16())

		sa := unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Port:   sockaddrPort(endpoint.Port),
			Addr:   addr,
		}

		return (*(*[unix.SizeofSockaddrInet6]byte)(unsafe.Pointer(&sa)))[:], nil
	}

	// IPv4 address handling.
	var addr [4]byte
	copy(addr[:], endpoint.IP.To4())

	sa := unix.RawSockaddrInet4{
		Family: unix.AF_INET,
		Port:   sockaddrPort(endpoint.Port),
		Addr:   addr,
	}

	return (*(*[unix.SizeofSockaddrInet4]byte)(unsafe.Pointer(&sa)))[:], nil
}

// rtnlInterfaces uses rtnetlink to fetch a list of WireGuard interfaces.
func rtnlInterfaces() ([]string, error) {
	// Use the stdlib's rtnetlink helpers to get ahold of a table of all
	// interfaces, so we can begin filtering it down to just WireGuard devices.
	tab, err := syscall.NetlinkRIB(unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to get list of interfaces from rtnetlink: %v", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, fmt.Errorf("wglinux: failed to parse rtnetlink messages: %v", err)
	}

	return parseRTNLInterfaces(msgs)
}

// parseRTNLInterfaces unpacks rtnetlink messages and returns WireGuard
// interface names.
func parseRTNLInterfaces(msgs []syscall.NetlinkMessage) ([]string, error) {
	var ifis []string
	for _, m := range msgs {
		// Only deal with link messages, and they must have an ifinfomsg
		// structure appear before the attributes.
		if m.Header.Type != unix.RTM_NEWLINK {
			continue
		}

		if len(m.Data) < unix.SizeofIfInfomsg {
			return nil, fmt.Errorf("wglinux: rtnetlink message is too short for ifinfomsg: %d", len(m.Data))
		}

		ad, err := netlink.NewAttributeDecoder(m.Data[syscall.SizeofIfInfomsg:])
		if err != nil {
			return nil, err
		}

		// Determine the interface's name and if it's a WireGuard device.
		var (
			ifi  string
			isWG bool
		)

		for ad.Next() {
			switch ad.Type() {
			case unix.IFLA_IFNAME:
				ifi = ad.String()
			case unix.IFLA_LINKINFO:
				ad.Do(isWGKind(&isWG))
			}
		}

		if err := ad.Err(); err != nil {
			return nil, err
		}

		if isWG {
			// Found one; append it to the list.
			ifis = append(ifis, ifi)
		}
	}

	return ifis, nil
}

// isWGKind parses netlink attributes to determine if a link is a WireGuard
// device, then populates ok with the result.
func isWGKind(ok *bool) func(b []byte) error {
	return func(b []byte) error {
		ad, err := netlink.NewAttributeDecoder(b)
		if err != nil {
			return err
		}

		for ad.Next() {
			if ad.Type() != unix.IFLA_INFO_KIND {
				continue
			}

			if ad.String() == datastruct.GenlName {
				*ok = true
				return nil
			}
		}

		return ad.Err()
	}
}

// execute executes a single WireGuard netlink request with the specified command,
// header flags, and attribute arguments.
func (m *Manager) execute(command uint8, flags netlink.HeaderFlags, attrb []byte) ([]genetlink.Message, error) {
	msg := genetlink.Message{
		Header: genetlink.Header{
			Command: command,
			Version: datastruct.GenlVersion,
		},
		Data: attrb,
	}

	fmt.Println("xxxxxxx")
	fmt.Println(string(msg.Data))
	fmt.Println(m.family.ID)
	fmt.Println(flags)
	msgs, err := m.conn.Execute(msg, m.family.ID, flags)
	if err == nil {
		fmt.Println("xxxxxqqqqq")
		return msgs, nil
	}

	fmt.Println("xxxxxxbbbb")
	fmt.Println(err)
	// We don't want to expose netlink errors directly to callers, so unpack
	// the error for use with os.IsNotExist and similar.
	oerr, ok := err.(*netlink.OpError)
	if !ok {
		// Expect all errors to conform to netlink.OpError.
		return nil, fmt.Errorf("wglinux: netlink operation returned non-netlink error (please file a bug: https://golang.zx2c4.com/wireguard/wgctrl): %v", err)
	}

	switch oerr.Err {
	// Convert "no such device" and "not a wireguard device" to an error
	// compatible with os.IsNotExist for easy checking.
	case unix.ENODEV, unix.ENOTSUP:
		return nil, os.ErrNotExist
	default:
		// Expose the inner error directly (such as EPERM).
		return nil, oerr.Err
	}
}

// buildBatches produces a batch of configs from a single config, if needed.
func buildBatches(cfg datastruct.DeviceConfig) []datastruct.DeviceConfig {
	// Is this a small configuration; no need to batch?
	if !shouldBatch(cfg) {
		return []datastruct.DeviceConfig{cfg}
	}

	// Use most fields of cfg for our "base" configuration, and only differ
	// peers in each batch.
	base := cfg
	base.Peers = nil

	// Track the known peers so that peer IPs are not replaced if a single
	// peer has its allowed IPs split into multiple batches.
	knownPeers := make(map[datastruct.Key]struct{})

	batches := make([]datastruct.DeviceConfig, 0)
	for _, p := range cfg.Peers {
		batch := base

		// Iterate until no more allowed IPs.
		var done bool
		for !done {
			var tmp []net.IPNet
			if len(p.AllowedIPs) < ipBatchChunk {
				// IPs all fit within a batch; we are done.
				tmp = make([]net.IPNet, len(p.AllowedIPs))
				copy(tmp, p.AllowedIPs)
				done = true
			} else {
				// IPs are larger than a single batch, copy a batch out and
				// advance the cursor.
				tmp = make([]net.IPNet, ipBatchChunk)
				copy(tmp, p.AllowedIPs[:ipBatchChunk])

				p.AllowedIPs = p.AllowedIPs[ipBatchChunk:]

				if len(p.AllowedIPs) == 0 {
					// IPs ended on a batch boundary; no more IPs left so end
					// iteration after this loop.
					done = true
				}
			}

			pcfg := datastruct.PeerConfig{
				// PublicKey denotes the peer and must be present.
				PublicKey: p.PublicKey,

				// Apply the update only flag to every chunk to ensure
				// consistency between batches when the kernel module processes
				// them.
				UpdateOnly: p.UpdateOnly,

				// It'd be a bit weird to have a remove peer message with many
				// IPs, but just in case, add this to every peer's message.
				Remove: p.Remove,

				// The IPs for this chunk.
				AllowedIPs: tmp,
			}

			// Only pass certain fields on the first occurrence of a peer, so
			// that subsequent IPs won't be wiped out and space isn't wasted.
			if _, ok := knownPeers[p.PublicKey]; !ok {
				knownPeers[p.PublicKey] = struct{}{}

				pcfg.PresharedKey = p.PresharedKey
				pcfg.Endpoint = p.Endpoint
				pcfg.PersistentKeepaliveInterval = p.PersistentKeepaliveInterval

				// Important: do not move or appending peers won't work.
				pcfg.ReplaceAllowedIPs = p.ReplaceAllowedIPs
			}

			// Add a peer configuration to this batch and keep going.
			batch.Peers = []datastruct.PeerConfig{pcfg}
			batches = append(batches, batch)
		}
	}

	// Do not allow peer replacement beyond the first message in a batch,
	// so we don't overwrite our previous batch work.
	for i := range batches {
		if i > 0 {
			batches[i].ReplacePeers = false
		}
	}

	return batches
}

// peerBatchChunk specifies the number of peers that can appear in a
// configuration before we start splitting it into chunks.
const peerBatchChunk = 32

// ipBatchChunk is a tunable allowed IP batch limit per peer.
//
// Because we don't necessarily know how much space a given peer will occupy,
// we play it safe and use a reasonably small value.  Note that this constant
// is used both in this package and tests, so be aware when making changes.
const ipBatchChunk = 256

// shouldBatch determines if a configuration is sufficiently complex that it
// should be split into batches.
func shouldBatch(cfg datastruct.DeviceConfig) bool {
	if len(cfg.Peers) > peerBatchChunk {
		return true
	}

	var ips int
	for _, p := range cfg.Peers {
		ips += len(p.AllowedIPs)
	}

	return ips > ipBatchChunk
}

// isValidIP determines if IP is a valid IPv4 or IPv6 address.
func isValidIP(ip net.IP) bool {
	return ip.To16() != nil
}

// isIPv6 determines if IP is a valid IPv6 address.
func isIPv6(ip net.IP) bool {
	return isValidIP(ip) && ip.To4() == nil
}

// encodeAllowedIPs converts a slice net.IPNets into netlink attribute encoder
// bytes.
func encodeAllowedIPs(ae *netlink.AttributeEncoder, ipns []net.IPNet) error {
	for i, ipn := range ipns {
		if !isValidIP(ipn.IP) {
			return fmt.Errorf("wglinux: invalid allowed IP: %s", ipn.IP.String())
		}

		family := uint16(unix.AF_INET6)
		if !isIPv6(ipn.IP) {
			// Make sure address is 4 bytes if IPv4.
			family = unix.AF_INET
			ipn.IP = ipn.IP.To4()
		}

		// Netlink arrays use type as an array index.
		ae.Nested(uint16(i), func(nae *netlink.AttributeEncoder) error {
			nae.Uint16(datastruct.AllowedipAFamily, family)
			nae.Bytes(datastruct.AllowedipAIpaddr, ipn.IP)

			ones, _ := ipn.Mask.Size()
			nae.Uint8(datastruct.AllowedipACidrMask, uint8(ones))
			return nil
		})
	}

	return nil
}
