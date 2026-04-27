package protocol

import "errors"

// Protocol version
const Version uint8 = 1

// Sentinel errors shared across packages.
var (
	ErrNodeNotFound     = errors.New("node not found")
	ErrNetworkNotFound  = errors.New("network not found")
	ErrConnClosed       = errors.New("connection closed")
	ErrConnClosing      = errors.New("connection closing")
	ErrConnRefused      = errors.New("connection refused")
	ErrDialTimeout      = errors.New("dial timeout")
	ErrChecksumMismatch = errors.New("checksum mismatch")
	// ErrDialToSelf is returned when a caller attempts to establish a
	// tunnel or stream to the local node's own NodeID. Triggered e.g.
	// when bootstrap / roster listings contain self and the caller
	// doesn't filter first. Mirrors go-libp2p-swarm's ErrDialToSelf
	// guard: fail fast with a typed sentinel so the bug is visible,
	// rather than silently discarding and masking the caller's
	// invariant violation. Observed live as a ~5900 pps self-
	// amplified packet loop on multi-homed hosts (docker bridge +
	// public IP both fingerprinting as "same-LAN peer" for the local
	// node) that consumed two CPU cores of pilot-daemon. (v1.9.0-jf.6)
	ErrDialToSelf = errors.New("dial to self")
)

// Flags (4 bits, stored in lower nibble of first byte alongside version)
const (
	FlagSYN uint8 = 0x1
	FlagACK uint8 = 0x2
	FlagFIN uint8 = 0x4
	FlagRST uint8 = 0x8
)

// Protocol types
const (
	ProtoStream   uint8 = 0x01 // Reliable, ordered (TCP-like)
	ProtoDatagram uint8 = 0x02 // Unreliable, unordered (UDP-like)
	ProtoControl  uint8 = 0x03 // Internal control
)

// Well-known ports
const (
	PortPing         uint16 = 0
	PortControl      uint16 = 1
	PortEcho         uint16 = 7
	PortNameserver   uint16 = 53
	PortHTTP         uint16 = 80
	PortSecure       uint16 = 443
	PortStdIO        uint16 = 1000
	PortDataExchange uint16 = 1001
	PortEventStream  uint16 = 1002
	PortTaskSubmit   uint16 = 1003
	PortManagedScore uint16 = 1004

	// PortGossip carries peer-membership gossip frames between daemons
	// running the fork's gossip discovery layer. Frames travel as
	// ProtoControl packets on established encrypted tunnels; older
	// daemons see an unknown control port and silently drop, so
	// advertising/consuming this port is backward-compatible.
	PortGossip uint16 = 1005
)

// Port ranges
const (
	PortReservedMax   uint16 = 1023
	PortRegisteredMax uint16 = 49151
	PortEphemeralMin  uint16 = 49152
	PortEphemeralMax  uint16 = 65535
)

// Tunnel magic bytes: "PILT" (0x50494C54)
var TunnelMagic = [4]byte{0x50, 0x49, 0x4C, 0x54}

// Tunnel magic bytes for encrypted packets: "PILS" (0x50494C53)
var TunnelMagicSecure = [4]byte{0x50, 0x49, 0x4C, 0x53}

// Tunnel magic bytes for key exchange: "PILK" (0x50494C4B)
var TunnelMagicKeyEx = [4]byte{0x50, 0x49, 0x4C, 0x4B}

// Tunnel magic bytes for authenticated key exchange: "PILA" (0x50494C41)
var TunnelMagicAuthEx = [4]byte{0x50, 0x49, 0x4C, 0x41}

// Tunnel magic bytes for NAT punch packet: "PILP" (0x50494C50)
var TunnelMagicPunch = [4]byte{0x50, 0x49, 0x4C, 0x50}

// Well-known port for handshake requests
const PortHandshake uint16 = 444

// Beacon message types (single-byte codes, all < 0x10 to avoid collision with tunnel magic)
const (
	BeaconMsgDiscover      byte = 0x01
	BeaconMsgDiscoverReply byte = 0x02
	BeaconMsgPunchRequest  byte = 0x03
	BeaconMsgPunchCommand  byte = 0x04
	BeaconMsgRelay         byte = 0x05
	BeaconMsgRelayDeliver  byte = 0x06
	BeaconMsgSync          byte = 0x07 // gossip: beacon-to-beacon node list exchange
)
