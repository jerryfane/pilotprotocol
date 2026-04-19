package gossip

import (
	"log/slog"
	"math/rand"
	"time"
)

// tickLoop runs until e.done closes. Each tick triggers one
// anti-entropy round with a random gossip-capable peer. A small
// random jitter on the first tick spreads simultaneous daemon
// restarts across time so we don't stampede a common peer on reboot.
func (e *Engine) tickLoop() {
	defer e.wg.Done()

	// Jitter: up to one full interval on the first tick.
	jitter := time.Duration(rand.Int63n(int64(e.interval)))
	firstTimer := time.NewTimer(jitter)
	defer firstTimer.Stop()

	select {
	case <-e.done:
		return
	case <-firstTimer.C:
	}
	e.Tick()

	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	for {
		select {
		case <-e.done:
			slog.Debug("gossip: tick loop stopping")
			return
		case <-ticker.C:
			e.Tick()
		}
	}
}
