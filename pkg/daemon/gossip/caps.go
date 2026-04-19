package gossip

// Capability bits advertised in the trailing varint of
// authenticated-key-exchange (PILA) frames. Bit assignments are
// stable; new bits are appended but never reassigned.
//
// Older daemons that predate this extension emit no bits at all
// (empty trailing region). Because the PILA parser treats unknown
// trailing bytes as zero caps, mixed-version deployments work
// without negotiation.
const (
	// CapGossip indicates the peer runs the Pilot-fork gossip
	// discovery layer (this package). Daemons only send gossip
	// frames to peers where this bit is set.
	CapGossip uint64 = 1 << 0
)

// HasCap reports whether bit c is set in bitmap.
func HasCap(bitmap, c uint64) bool { return bitmap&c != 0 }
