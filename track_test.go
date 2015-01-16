package conntrack

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {

	src := `<flow type="new"><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>10.10.2.67</src><dst>192.168.178.22</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>42813</sport><dport>9300</dport></layer4></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>192.168.178.22</src><dst>10.10.2.67</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>9300</sport><dport>42813</dport></layer4></meta><meta direction="independent"><state>SYN_SENT</state><timeout>120</timeout><id>2604675736</id><unreplied/></meta></flow>\n`
	want := Event{
		Type: "new",
		Metas: []Meta{
			{
				Direction: "original",
				Src:       "10.10.2.67",
				SrcPort:   "42813",
				Dst:       "192.168.178.22",
				DstPort:   "9300",
			},
			{
				Direction: "reply",
				Src:       "192.168.178.22",
				SrcPort:   "9300",
				Dst:       "10.10.2.67",
				DstPort:   "42813",
			},
			{
				Direction: "independent",
				State:     "SYN_SENT",
				Timeout:   120,
			},
		},
	}
	have, err := parseLine([]byte(src))
	if err != nil {
		t.Errorf("err: %s", err)
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("have: %+v, want %+v", have, want)
	}
}
