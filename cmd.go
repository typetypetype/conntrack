package conntrack

// deal with the `conntrack` binary

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"os/exec"
)

const (
	// Executable is out conntrack binary
	Executable = "/usr/sbin/conntrack"
)

// XML returned by `conntrack`:
// "<flow type="new"><meta direction="original"><layer3 protonum="2" protoname="ipv4"><src>10.10.2.67</src><dst>192.168.178.22</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>42813</sport><dport>9300</dport></layer4></meta><meta direction="reply"><layer3 protonum="2" protoname="ipv4"><src>192.168.178.22</src><dst>10.10.2.67</dst></layer3><layer4 protonum="6" protoname="tcp"><sport>9300</sport><dport>42813</dport></layer4></meta><meta direction="independent"><state>SYN_SENT</state><timeout>120</timeout><id>2604675736</id><unreplied/></meta></flow>"

// Event is a deserialized XML conntrack event.
type Event struct {
	Type  string `xml:"type,attr"`
	Metas []Meta `xml:"meta"`
}

// Meta is part of an Event
type Meta struct {
	Direction string `xml:"direction,attr"`
	Src       string `xml:"layer3>src"`
	SrcPort   string `xml:"layer4>sport"`
	Dst       string `xml:"layer3>dst"`
	DstPort   string `xml:"layer4>dport"`
	State     string `xml:"state"`
	Timeout   int    `xml:"timeout"`
}

// flowtype finds flow/event type of the event
func (e Event) flowtype() string {
	return e.Type
}

// state finds the of the connection
func (e Event) state() string {
	for _, m := range e.Metas {
		if m.Direction == "independent" {
			return m.State
		}
	}
	return ""
}

// conn transforms an event to a connection.
func (e Event) conn(local map[string]struct{}) *ConnTCP {
	// conntrack gives us all connections, even things passing through, but it
	// doesn't tell us what the local IP is. So we use `local` as a guide
	// what's local.
	for _, m := range e.Metas {
		if m.Direction == "reply" {
			_, srcLocal := local[m.Src]
			_, dstLocal := local[m.Dst]
			// If both are local we must just order things predictably.
			if srcLocal && dstLocal {
				srcLocal = m.SrcPort < m.DstPort
			}
			if srcLocal {
				return &ConnTCP{
					Local:      m.Src,
					LocalPort:  m.SrcPort,
					Remote:     m.Dst,
					RemotePort: m.DstPort,
				}
			}
			if dstLocal {
				return &ConnTCP{
					Local:      m.Dst,
					LocalPort:  m.DstPort,
					Remote:     m.Src,
					RemotePort: m.SrcPort,
				}
			}
			// Neither is local. conntrack also reports NAT connections.
			return nil
		}
	}
	return nil
}

// Follow starts the conntrack binary in follow mode and returns all events.
// The returned callback is used to stop the command.
func Follow() (chan Event, func(), error) {
	cmd := &exec.Cmd{
		Path: Executable,
		Args: []string{
			Executable,
			"-E", // follow
			"-p", "tcp",
			"-o", "xml",
			// --state only accepts a single argument
		},
		Stderr: os.Stderr, // temporary, nice while testing
	}
	stop := func() {
		cmd.Process.Kill()
	}

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, stop, err
	}

	events := make(chan Event, 10)
	go func() {
		defer func() {
			if err := cmd.Wait(); err != nil {
				// log.Printf("Cmd err: %v\n", err)
			}
		}()
		defer close(events)

		b := bufio.NewReader(pipe)
		// The XML is line based.
		for {
			l, err := b.ReadBytes('\n')
			if err != nil {
				return
			}
			if !bytes.HasPrefix(l, []byte("<flow")) {
				continue
			}
			event, err := parseLine(l)
			if err != nil {
				return
			}
			events <- event
		}
	}()

	return events, stop, cmd.Start()
}

// Established returns all ESTABLISHED as reported by conntrack.
func Established() ([]ConnTCP, error) {
	out, err := exec.Command(
		Executable,
		"-L", // list
		"-p", "tcp",
		"-o", "xml",
		"--state", "ESTABLISHED",
	).Output()
	if err != nil {
		return nil, err
	}

	var (
		buf = bytes.NewBuffer(out)
		cs  []ConnTCP
	)

	local := localIPs()
	for {
		l, err := buf.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				return cs, nil
			}
			return nil, err
		}
		if !bytes.HasPrefix(l, []byte("<flow")) {
			continue
		}
		event, err := parseLine(l)
		if err != nil {
			return nil, err
		}
		c := event.conn(local)
		if c == nil {
			continue
		}
		cs = append(cs, *c)
	}
}
