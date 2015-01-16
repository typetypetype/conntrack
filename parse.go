package conntrack

import (
	"encoding/xml"
)

func parseLine(l []byte) (Event, error) {
	// example line:
	// <flow type="new"><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>10.10.2.67</src><dst>192.168.178.22</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>42813</sport><dport>9300</dport></layer4></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>192.168.178.22</src><dst>10.10.2.67</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>9300</sport><dport>42813</dport></layer4></meta><meta direction="independent"><state>SYN_SENT</state><timeout>120</timeout><id>2604675736</id><unreplied/></meta></flow>
	var e Event
	err := xml.Unmarshal(l, &e)
	return e, err
}
