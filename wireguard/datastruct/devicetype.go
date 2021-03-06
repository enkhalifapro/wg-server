package datastruct


// A DeviceType specifies the underlying implementation of a WireGuard device.
type DeviceType int

// Possible DeviceType values.
const (
	Unknown DeviceType = iota
	LinuxKernel
	OpenBSDKernel
	Userspace
)

// String returns the string representation of a DeviceType.
func (dt DeviceType) String() string {
	switch dt {
	case LinuxKernel:
		return "Linux kernel"
	case OpenBSDKernel:
		return "OpenBSD kernel"
	case Userspace:
		return "userspace"
	default:
		return "unknown"
	}
}