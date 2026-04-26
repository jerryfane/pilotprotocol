package daemon

import (
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

func TestInboundSYNDoesNotEstablishWhenSYNACKSendFails(t *testing.T) {
	d := New(Config{Email: "synack-test@example.com", Public: true})
	ln, err := d.ports.Bind(protocol.PortManagedScore)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}

	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 2},
		Dst:      protocol.Addr{Node: 1},
		SrcPort:  49152,
		DstPort:  protocol.PortManagedScore,
		Seq:      10,
		Window:   512,
	}
	d.handleStreamPacket(pkt)

	if got := d.ports.TotalActiveConnections(); got != 0 {
		t.Fatalf("active connections = %d, want 0 after failed SYN-ACK", got)
	}
	if got := len(d.ports.AllConnections()); got != 0 {
		t.Fatalf("stored connections = %d, want 0 after failed SYN-ACK", got)
	}
	select {
	case conn := <-ln.AcceptCh:
		t.Fatalf("accepted conn after failed SYN-ACK: id=%d state=%s", conn.ID, conn.State)
	default:
	}
}
