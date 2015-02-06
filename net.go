package conntrack

import (
	"net"
)

// localIPs gives all IPs we consider local.
func localIPs() map[IP]struct{} {
	var l = map[IP]struct{}{}
	if localNets, err := net.InterfaceAddrs(); err == nil {
		// Not all networks are IP networks.
		for _, localNet := range localNets {
			if net, ok := localNet.(*net.IPNet); ok {
				l[NewIP(net.IP)] = struct{}{}
			}
		}
	}
	return l
}
