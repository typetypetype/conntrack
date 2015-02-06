package conntrack

// hashable IP representation
// IPv6 TODO

import (
	"net"
)

type IP struct {
	len int
	b   [16]byte
}

func NewIP(b []byte) IP {
	if as4 := net.IP(b).To4(); as4 != nil {
		// be sure we format IPv4 bytes the same way as net.IP
		b = as4
	}
	ip := IP{
		len: len(b),
	}
	copy(ip.b[:], b)
	// fmt.Printf("IP %s -> %s (%s)\n", string(b), string(ip.b[:]), ip)
	return ip
}

// Net gives the net.IP version.
func (ip IP) Net() net.IP {
	return net.IP(ip.b[:ip.len])
}

// String gives the 1.2.3.4 notation of the IP.
func (ip IP) String() string {
	// kiss...
	return ip.Net().String()
}
