package daemon

import (
	"bytes"
	"encoding/binary"
	"sync"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// SACKBlock represents a contiguous range of received bytes.
// Left is the seq of the first byte; Right is the seq of the first byte AFTER the range.
type SACKBlock struct {
	Left  uint32
	Right uint32
}

// sackMagic identifies SACK data in ACK payloads.
var sackMagic = []byte("SACK")

// EncodeSACK encodes SACK blocks into a byte slice.
// Format: "SACK" (4 bytes) + count (1 byte) + N * 8 bytes (Left:4, Right:4).
func EncodeSACK(blocks []SACKBlock) []byte {
	if len(blocks) == 0 {
		return nil
	}
	n := len(blocks)
	if n > 4 {
		n = 4 // max 4 SACK blocks (same as TCP)
	}
	buf := make([]byte, 5+n*8)
	copy(buf[0:4], sackMagic)
	buf[4] = byte(n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		binary.BigEndian.PutUint32(buf[off:off+4], blocks[i].Left)
		binary.BigEndian.PutUint32(buf[off+4:off+8], blocks[i].Right)
	}
	return buf
}

// DecodeSACK parses SACK blocks from an ACK payload.
// Returns nil, false if the payload is not SACK data.
func DecodeSACK(data []byte) ([]SACKBlock, bool) {
	if len(data) < 5 || !bytes.Equal(data[0:4], sackMagic) {
		return nil, false
	}
	n := int(data[4])
	if n == 0 || n > 4 || len(data) < 5+n*8 {
		return nil, false
	}
	blocks := make([]SACKBlock, n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		blocks[i] = SACKBlock{
			Left:  binary.BigEndian.Uint32(data[off : off+4]),
			Right: binary.BigEndian.Uint32(data[off+4 : off+8]),
		}
	}
	return blocks, true
}

// MaxConnectionsPerPort and MaxTotalConnections defaults are defined in daemon.go Config.
// The daemon passes resolved values when checking limits.

// PortManager handles virtual port binding and connection tracking.
type PortManager struct {
	mu          sync.RWMutex
	listeners   map[uint16]*Listener
	connections map[uint32]*Connection // conn_id → connection
	nextConnID  uint32
	nextEphPort uint16
}

type Listener struct {
	Port     uint16
	AcceptCh chan *Connection
}

// retxEntry is a sent-but-unacknowledged data segment.
type retxEntry struct {
	data     []byte
	seq      uint32
	sentAt   time.Time
	attempts int
	sacked   bool // true if covered by a SACK block (don't retransmit)
}

// recvSegment is an out-of-order received segment waiting for reassembly.
type recvSegment struct {
	seq  uint32
	data []byte
}

// Default window parameters
const (
	InitialCongWin = 10 * MaxSegmentSize // IW10 initial congestion window (RFC 6928)
	MaxCongWin     = 1024 * 1024         // 1 MB max congestion window
	// MaxSegmentSize is the inner stream payload size. Keep it below the
	// practical UDP/TURN datagram target because Pilot adds packet,
	// encryption, and TURN framing overhead around each segment.
	MaxSegmentSize = 1024
	RecvBufSize    = 512                          // receive buffer channel capacity (segments)
	MaxRecvWin     = RecvBufSize * MaxSegmentSize // max receive window
	MaxOOOBuf      = 128                          // max out-of-order segments buffered per connection
	AcceptQueueLen = 64                           // listener accept channel capacity
	SendBufLen     = 256                          // send buffer channel capacity (segments)
)

// RTO parameters (RFC 6298)
const (
	ClockGranularity = 10 * time.Millisecond  // minimum RTTVAR for RTO calculation
	RTOMin           = 200 * time.Millisecond // minimum retransmission timeout
	RTOMax           = 10 * time.Second       // maximum retransmission timeout
	InitialRTO       = 1 * time.Second        // initial retransmission timeout
)

type Connection struct {
	Mu           sync.Mutex // protects State, SendSeq, RecvAck, LastActivity, Stats
	ID           uint32
	CreatedAt    time.Time
	LocalAddr    protocol.Addr // our virtual address
	LocalPort    uint16
	RemoteAddr   protocol.Addr
	RemotePort   uint16
	State        ConnState
	LastActivity time.Time // updated on send/recv
	// Reliable delivery
	SendSeq uint32
	RecvAck uint32
	SendBuf chan []byte
	RecvBuf chan []byte
	// Sliding window + retransmission (send side)
	RetxMu        sync.Mutex
	Unacked       []*retxEntry           // ordered by seq
	LastAck       uint32                 // highest cumulative ACK received
	DupAckCount   int                    // consecutive duplicate ACKs
	RTO           time.Duration          // retransmission timeout
	SRTT          time.Duration          // smoothed RTT
	RTTVAR        time.Duration          // RTT variance (RFC 6298)
	CongWin       int                    // congestion window in bytes
	SSThresh      int                    // slow-start threshold
	InRecovery    bool                   // true during timeout loss recovery
	RecoveryPoint uint32                 // highest seq sent when entering recovery
	RetxStop      chan struct{}          // closed to stop retx goroutine
	RetxSend      func(*protocol.Packet) // callback to send retransmitted packets
	WindowCh      chan struct{}          // signaled when window opens up
	PeerRecvWin   int                    // peer's advertised receive window (0 = unknown/unlimited)
	// Nagle algorithm (write coalescing)
	NagleBuf []byte        // pending small write data
	NagleMu  sync.Mutex    // protects NagleBuf
	NagleCh  chan struct{} // signaled when Nagle should flush
	NoDelay  bool          // if true, disable Nagle (send immediately)
	// Receive window (reassembly)
	RecvMu      sync.Mutex
	ExpectedSeq uint32         // next in-order seq expected
	OOOBuf      []*recvSegment // out-of-order buffer
	// Delayed ACK
	AckMu       sync.Mutex  // protects PendingACKs and ACKTimer
	PendingACKs int         // count of unacked received segments
	ACKTimer    *time.Timer // delayed ACK timer
	// Keepalive dead-peer detection
	KeepaliveUnacked int // consecutive unanswered keepalive probes
	// Close
	CloseOnce  sync.Once // ensures RecvBuf is closed exactly once
	RecvClosed bool      // true after RecvBuf is closed (guarded by RecvMu)
	// Listener / IPC ownership
	AcceptQueuedAt time.Time // set when an inbound stream is queued to a listener
	AcceptedAt     time.Time // set when an IPC client is notified about this stream
	// Retransmit state
	LastRetxTime time.Time // when last RTO retransmission fired (prevents cascading)
	// Per-connection statistics
	Stats ConnStats
}

// ConnStats tracks per-connection traffic and reliability metrics.
type ConnStats struct {
	BytesSent   uint64 // total user bytes sent
	BytesRecv   uint64 // total user bytes received
	SegsSent    uint64 // data segments sent
	SegsRecv    uint64 // data segments received
	Retransmits uint64 // timeout-based retransmissions
	FastRetx    uint64 // fast retransmissions (3 dup ACKs)
	SACKRecv    uint64 // SACK blocks received from peer
	SACKSent    uint64 // SACK blocks sent to peer
	DupACKs     uint64 // duplicate ACKs received
}

type ConnState uint8

const (
	StateClosed ConnState = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait
	StateCloseWait
	StateTimeWait
)

func (s ConnState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECV"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateTimeWait:
		return "TIME_WAIT"
	default:
		return "unknown"
	}
}
