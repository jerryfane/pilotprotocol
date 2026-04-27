package daemon

import (
	"sort"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

// BytesInFlight returns total unacknowledged bytes.
func (c *Connection) BytesInFlight() int {
	total := 0
	for _, e := range c.Unacked {
		total += len(e.data)
	}
	return total
}

// EffectiveWindow returns the effective send window (minimum of congestion
// window and peer's advertised receive window).
// Must be called with RetxMu held.
func (c *Connection) EffectiveWindow() int {
	win := c.CongWin
	if win <= 0 {
		win = InitialCongWin
	}
	if c.PeerRecvWin > 0 && c.PeerRecvWin < win {
		win = c.PeerRecvWin
	}
	return win
}

// WindowAvailable returns true if the effective window allows more data.
// Must be called with RetxMu held.
func (c *Connection) WindowAvailable() bool {
	return c.BytesInFlight() < c.EffectiveWindow()
}

// TrackSend adds a sent data segment to the retransmission buffer.
func (c *Connection) TrackSend(seq uint32, data []byte) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()
	saved := make([]byte, len(data))
	copy(saved, data)
	c.Unacked = append(c.Unacked, &retxEntry{
		data:     saved,
		seq:      seq,
		sentAt:   time.Now(),
		attempts: 1,
	})
}

// ProcessAck removes segments acknowledged by the given ack number,
// updates RTT estimate, detects duplicate ACKs for fast retransmit,
// and grows the congestion window.
// If pureACK is true, duplicate ACK detection is enabled. Data packets
// with piggybacked ACKs should pass pureACK=false to avoid false
// fast retransmits (RFC 5681 Section 3.2).
type AckResult struct {
	Ack           uint32
	BeforeLastAck uint32
	AfterLastAck  uint32
	BeforeUnacked int
	AfterUnacked  int
	Cleared       int
	Duplicate     bool
	Stale         bool
	PureACK       bool
}

func (c *Connection) ProcessAck(ack uint32, pureACK bool) AckResult {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	res := AckResult{
		Ack:           ack,
		BeforeLastAck: c.LastAck,
		AfterLastAck:  c.LastAck,
		BeforeUnacked: len(c.Unacked),
		AfterUnacked:  len(c.Unacked),
		PureACK:       pureACK,
	}

	if seqAfter(c.LastAck, ack) {
		res.Stale = true
		return res // ack is behind LastAck (wrapping-safe)
	}

	if ack == c.LastAck {
		res.Duplicate = true
		if !pureACK {
			return res // data packets don't count as dup ACKs
		}
		// Duplicate ACK (pure ACK only)
		c.DupAckCount++
		c.Mu.Lock()
		c.Stats.DupACKs++
		c.Mu.Unlock()
		if c.DupAckCount == 3 {
			// Fast retransmit (RFC 5681)
			c.fastRetransmit()
			c.Mu.Lock()
			c.Stats.FastRetx++
			c.Mu.Unlock()
			// Multiplicative decrease
			c.SSThresh = c.CongWin / 2
			if c.SSThresh < MaxSegmentSize {
				c.SSThresh = MaxSegmentSize
			}
			c.CongWin = c.SSThresh + 3*MaxSegmentSize
		} else if c.DupAckCount > 3 {
			// Inflate window for each additional dup ACK
			c.CongWin += MaxSegmentSize
			if c.CongWin > MaxCongWin {
				c.CongWin = MaxCongWin
			}
		}
		res.AfterUnacked = len(c.Unacked)
		return res
	}

	// New ACK — advance
	bytesAcked := int(ack - c.LastAck)
	c.LastAck = ack
	c.DupAckCount = 0
	c.LastRetxTime = time.Time{} // reset retransmit guard so ACK-driven recovery can proceed

	// Exit timeout recovery when all loss-window data is acked
	if c.InRecovery && seqAfterOrEqual(ack, c.RecoveryPoint) {
		c.InRecovery = false
	}

	// Remove acked entries and update RTT from the first one
	var remaining []*retxEntry
	for _, e := range c.Unacked {
		endSeq := e.seq + uint32(len(e.data))
		if seqAfterOrEqual(ack, endSeq) {
			// This segment is fully acked — update RTT if first attempt and not SACKed
			if e.attempts == 1 && !e.sacked {
				rtt := time.Since(e.sentAt)
				c.updateRTT(rtt)
			}
		} else {
			// Reset sacked flag for segments that are still unacked
			// (SACK state is refreshed with each incoming ACK)
			e.sacked = false
			remaining = append(remaining, e)
		}
	}
	c.Unacked = remaining
	res.AfterLastAck = c.LastAck
	res.AfterUnacked = len(c.Unacked)
	res.Cleared = res.BeforeUnacked - res.AfterUnacked

	// Congestion window growth (Appropriate Byte Counting, RFC 3465)
	// Grow based on bytes ACKed, not number of ACKs — avoids delayed ACK penalty.
	if c.CongWin < c.SSThresh {
		// Slow start: grow by acked bytes (exponential)
		c.CongWin += bytesAcked
	} else {
		// Congestion avoidance: grow by ~MSS per RTT (AIMD)
		increment := MaxSegmentSize * bytesAcked / c.CongWin
		if increment < 1 {
			increment = 1
		}
		c.CongWin += increment
	}
	if c.CongWin > MaxCongWin {
		c.CongWin = MaxCongWin
	}

	// Signal that window opened up
	if c.WindowCh != nil {
		select {
		case c.WindowCh <- struct{}{}:
		default:
		}
	}

	// Signal Nagle flush if all data acknowledged
	if len(c.Unacked) == 0 && c.NagleCh != nil {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
	return res
}

// fastRetransmit resends the first unacked-and-not-SACKed segment immediately.
// Must be called with RetxMu held.
func (c *Connection) fastRetransmit() {
	if len(c.Unacked) == 0 || c.RetxSend == nil {
		return
	}
	// Read RecvAck under Mu (L1 fix — RecvAck is protected by Mu, not RetxMu)
	c.Mu.Lock()
	recvAck := c.RecvAck
	c.Mu.Unlock()

	// Find the first unacked segment that hasn't been SACKed
	for _, e := range c.Unacked {
		if e.sacked {
			continue
		}
		e.attempts++
		e.sentAt = time.Now()
		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagACK,
			Protocol: protocol.ProtoStream,
			Src:      c.LocalAddr,
			Dst:      c.RemoteAddr,
			SrcPort:  c.LocalPort,
			DstPort:  c.RemotePort,
			Seq:      e.seq,
			Ack:      recvAck,
			Window:   c.RecvWindow(),
			Payload:  e.data,
		}
		c.RetxSend(pkt)
		return
	}
}

func (c *Connection) updateRTT(rtt time.Duration) {
	if c.SRTT == 0 {
		// First measurement (RFC 6298 Section 2.2)
		c.SRTT = rtt
		c.RTTVAR = rtt / 2
	} else {
		// Subsequent measurements (RFC 6298 Section 2.3)
		// RTTVAR = (1-β)·RTTVAR + β·|SRTT - R|  where β = 1/4
		diff := c.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		c.RTTVAR = c.RTTVAR*3/4 + diff/4
		// SRTT = (1-α)·SRTT + α·R  where α = 1/8
		c.SRTT = c.SRTT*7/8 + rtt/8
	}
	// RTO = SRTT + max(G, K·RTTVAR) where K=4, G=clock granularity
	kvar := c.RTTVAR * 4
	if kvar < ClockGranularity {
		kvar = ClockGranularity
	}
	c.RTO = c.SRTT + kvar
	// Clamp RTO
	if c.RTO < RTOMin {
		c.RTO = RTOMin
	}
	if c.RTO > RTOMax {
		c.RTO = RTOMax
	}
}

// seqAfter returns true if a is after b in the circular uint32 sequence space.
// Uses RFC 1982 serial number arithmetic: a > b iff (a - b) interpreted as
// signed int32 is positive.
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqAfterOrEqual returns true if a >= b in circular uint32 sequence space.
func seqAfterOrEqual(a, b uint32) bool {
	return a == b || int32(a-b) > 0
}

// DeliverInOrder handles an incoming data segment, buffering out-of-order
// segments and delivering in-order data to RecvBuf. Returns the cumulative
// ACK number (next expected seq).
//
// Three-phase design to avoid both deadlock and sequence leaks:
//
//	Phase 1: Collect segments to deliver under RecvMu (don't advance ExpectedSeq).
//	Phase 2: Deliver outside lock (prevents routeLoop deadlock, C1 fix).
//	Phase 3: Re-acquire lock, advance ExpectedSeq only for delivered segments,
//	         re-buffer undelivered OOO segments.
//
// Safe because routeLoop is single-goroutine — no concurrent DeliverInOrder
// calls for the same connection between Phase 2 and Phase 3.
func (c *Connection) DeliverInOrder(seq uint32, data []byte) uint32 {
	c.RecvMu.Lock()

	if c.RecvClosed {
		expectedSeq := c.ExpectedSeq
		c.RecvMu.Unlock()
		return expectedSeq
	}

	type pendingSeg struct {
		seq  uint32
		data []byte
		size uint32
	}
	var toDeliver []pendingSeg

	if seq == c.ExpectedSeq {
		// In order — collect for delivery (don't advance ExpectedSeq yet)
		toDeliver = append(toDeliver, pendingSeg{seq: seq, data: data, size: uint32(len(data))})
		nextSeq := seq + uint32(len(data))

		// Drain any buffered segments that would become contiguous
		for {
			found := false
			for i, seg := range c.OOOBuf {
				if seg.seq == nextSeq {
					toDeliver = append(toDeliver, pendingSeg{seq: seg.seq, data: seg.data, size: uint32(len(seg.data))})
					nextSeq = seg.seq + uint32(len(seg.data))
					c.OOOBuf = append(c.OOOBuf[:i], c.OOOBuf[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	} else if seqAfter(seq, c.ExpectedSeq) {
		// Out of order — buffer it (avoid duplicates, enforce bound)
		if !c.hasOOOSeg(seq) && len(c.OOOBuf) < MaxOOOBuf {
			saved := make([]byte, len(data))
			copy(saved, data)
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seq, data: saved})
		}
	}
	// seq before ExpectedSeq means it's a duplicate — ignore

	c.RecvMu.Unlock()

	// Phase 2: Deliver outside the lock to prevent deadlocking routeLoop
	// when RecvBuf is full (C1 fix). Stop at first failure — remaining
	// segments stay contiguous and will be re-buffered.
	delivered := 0
	for _, seg := range toDeliver {
		ok := func() bool {
			defer func() { recover() }() // handle closed RecvBuf
			select {
			case c.RecvBuf <- seg.data:
				return true
			case <-time.After(1 * time.Second):
				return false
			}
		}()
		if !ok {
			break
		}
		delivered++
	}

	// Phase 3: Commit — advance ExpectedSeq only for successfully delivered
	// segments. Re-buffer any OOO segments that couldn't be delivered.
	c.RecvMu.Lock()
	for i, seg := range toDeliver {
		if i < delivered {
			c.ExpectedSeq = seg.seq + seg.size
		} else if i > 0 {
			// Re-buffer OOO segments we removed in Phase 1.
			// Skip index 0 (the incoming segment) — sender retransmits
			// since we won't ACK it.
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seg.seq, data: seg.data})
		}
	}
	expectedSeq := c.ExpectedSeq
	c.RecvMu.Unlock()

	return expectedSeq
}

// CloseRecvBuf safely closes RecvBuf exactly once. Both the flag set and
// channel close happen under RecvMu so DeliverInOrder can never send to a
// closed channel.
func (c *Connection) CloseRecvBuf() {
	c.CloseOnce.Do(func() {
		c.RecvMu.Lock()
		c.RecvClosed = true
		close(c.RecvBuf)
		c.RecvMu.Unlock()
	})
}

// RecvWindow returns the number of free segments in the receive buffer,
// used as the advertised receive window.
func (c *Connection) RecvWindow() uint16 {
	free := cap(c.RecvBuf) - len(c.RecvBuf)
	if free < 0 {
		free = 0
	}
	if free > 0xFFFF {
		free = 0xFFFF
	}
	return uint16(free)
}

func (c *Connection) hasOOOSeg(seq uint32) bool {
	for _, seg := range c.OOOBuf {
		if seg.seq == seq {
			return true
		}
	}
	return false
}

// SACKBlocks returns SACK blocks describing out-of-order received segments.
// Must be called with RecvMu held.
func (c *Connection) SACKBlocks() []SACKBlock {
	if len(c.OOOBuf) == 0 {
		return nil
	}

	// Sort OOO segments by seq
	sorted := make([]*recvSegment, len(c.OOOBuf))
	copy(sorted, c.OOOBuf)
	sort.Slice(sorted, func(i, j int) bool { return seqAfter(sorted[j].seq, sorted[i].seq) })

	// Merge into contiguous blocks
	var blocks []SACKBlock
	cur := SACKBlock{Left: sorted[0].seq, Right: sorted[0].seq + uint32(len(sorted[0].data))}

	for i := 1; i < len(sorted); i++ {
		seg := sorted[i]
		segEnd := seg.seq + uint32(len(seg.data))
		if seg.seq <= cur.Right {
			// Contiguous or overlapping — extend
			if segEnd > cur.Right {
				cur.Right = segEnd
			}
		} else {
			// Gap — emit current block, start new one
			blocks = append(blocks, cur)
			cur = SACKBlock{Left: seg.seq, Right: segEnd}
		}
	}
	blocks = append(blocks, cur)

	// Limit to 4 blocks (most recent/important first is fine since they're sorted by seq)
	if len(blocks) > 4 {
		blocks = blocks[:4]
	}
	return blocks
}

// ProcessSACK marks unacked segments that are covered by SACK blocks.
// This prevents unnecessary retransmission of segments the peer already has.
func (c *Connection) ProcessSACK(blocks []SACKBlock) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	c.Mu.Lock()
	c.Stats.SACKRecv += uint64(len(blocks))
	c.Mu.Unlock()

	for _, e := range c.Unacked {
		segEnd := e.seq + uint32(len(e.data))
		for _, b := range blocks {
			if e.seq >= b.Left && segEnd <= b.Right {
				e.sacked = true
				break
			}
		}
	}
}
