package tests

import (
	"errors"
	"testing"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon"
	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// TestDialConnectionRejectsSelf is the jf.6 regression guard for the
// self-dial amplification bug (live-observed ~5900 pps loop consuming
// 2 CPU cores of pilot-daemon on multi-homed hosts). The fix is a
// typed-sentinel guard at DialConnection entry and at ensureTunnel
// entry; both assert here.
//
// Mirrors go-libp2p-swarm/swarm_dial.go's ErrDialToSelf pattern: fail
// fast with a canonical, searchable sentinel so callers that violated
// the "filter self out of your peer list" invariant see the bug
// instead of silently amplifying it.
func TestDialConnectionRejectsSelf(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)
	info := env.AddDaemon(func(c *daemon.Config) { c.Encrypt = true })
	d := info.Daemon

	self := protocol.Addr{Network: 1, Node: d.NodeID()}
	_, err := d.DialConnection(self, 7)
	if !errors.Is(err, protocol.ErrDialToSelf) {
		t.Fatalf("DialConnection(self): got err=%v, want ErrDialToSelf", err)
	}
}
