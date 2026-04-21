package driver

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/TeoSlayer/pilotprotocol/pkg/protocol"
)

const DefaultSocketPath = "/tmp/pilot.sock"

// Handshake sub-commands (must match daemon SubHandshake* constants)
const (
	subHandshakeSend    byte = 0x01
	subHandshakeApprove byte = 0x02
	subHandshakeReject  byte = 0x03
	subHandshakePending byte = 0x04
	subHandshakeTrusted byte = 0x05
	subHandshakeRevoke  byte = 0x06
)

// jsonRPC sends an IPC message, waits for the expected response, and
// unmarshals the JSON payload. Most driver methods follow this pattern.
func (d *Driver) jsonRPC(msg []byte, expectCmd byte, label string) (map[string]interface{}, error) {
	resp, err := d.ipc.sendAndWait(msg, expectCmd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("%s unmarshal: %w", label, err)
	}
	return result, nil
}

// Driver is the main entry point for the Pilot Protocol SDK.
type Driver struct {
	ipc        *ipcClient
	socketPath string
}

// Connect creates a new driver connected to the local daemon.
func Connect(socketPath string) (*Driver, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}

	ipc, err := newIPCClient(socketPath)
	if err != nil {
		return nil, err
	}

	return &Driver{ipc: ipc, socketPath: socketPath}, nil
}

// Dial opens a stream connection to a remote address:port.
// addr format: "N:XXXX.YYYY.YYYY:PORT"
func (d *Driver) Dial(addr string) (*Conn, error) {
	sa, err := protocol.ParseSocketAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("parse address: %w", err)
	}

	return d.DialAddr(sa.Addr, sa.Port)
}

// DialAddr opens a stream connection to a remote Addr + port.
func (d *Driver) DialAddr(dst protocol.Addr, port uint16) (*Conn, error) {
	msg := make([]byte, 1+protocol.AddrSize+2)
	msg[0] = cmdDial
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)

	resp, err := d.ipc.sendAndWait(msg, cmdDialOK)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("invalid dial response")
	}

	connID := binary.BigEndian.Uint32(resp[0:4])
	recvCh := d.ipc.registerRecvCh(connID)

	return &Conn{
		id:         connID,
		remoteAddr: protocol.SocketAddr{Addr: dst, Port: port},
		ipc:        d.ipc,
		recvCh:     recvCh,
		deadlineCh: make(chan struct{}),
	}, nil
}

// DialAddrTimeout opens a stream connection with a client-side timeout.
// If the daemon does not respond within the timeout, the dial is cancelled.
func (d *Driver) DialAddrTimeout(dst protocol.Addr, port uint16, timeout time.Duration) (*Conn, error) {
	msg := make([]byte, 1+protocol.AddrSize+2)
	msg[0] = cmdDial
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)

	resp, err := d.ipc.sendAndWaitTimeout(msg, cmdDialOK, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	if len(resp) < 4 {
		return nil, fmt.Errorf("invalid dial response")
	}

	connID := binary.BigEndian.Uint32(resp[0:4])
	recvCh := d.ipc.registerRecvCh(connID)

	return &Conn{
		id:         connID,
		remoteAddr: protocol.SocketAddr{Addr: dst, Port: port},
		ipc:        d.ipc,
		recvCh:     recvCh,
		deadlineCh: make(chan struct{}),
	}, nil
}

// Listen binds a port and returns a Listener that accepts connections.
func (d *Driver) Listen(port uint16) (*Listener, error) {
	msg := make([]byte, 3)
	msg[0] = cmdBind
	binary.BigEndian.PutUint16(msg[1:3], port)

	resp, err := d.ipc.sendAndWait(msg, cmdBindOK)
	if err != nil {
		return nil, fmt.Errorf("bind: %w", err)
	}

	boundPort := binary.BigEndian.Uint16(resp[0:2])

	// H12 fix: register per-port accept channel
	acceptCh := d.ipc.registerAcceptCh(boundPort)

	return &Listener{
		port:     boundPort,
		ipc:      d.ipc,
		acceptCh: acceptCh,
		done:     make(chan struct{}),
	}, nil
}

// SendTo sends an unreliable datagram to the given address:port.
// Use with broadcast addresses (Node=0xFFFFFFFF) to send to all network members.
func (d *Driver) SendTo(dst protocol.Addr, port uint16, data []byte) error {
	msg := make([]byte, 1+protocol.AddrSize+2+len(data))
	msg[0] = cmdSendTo
	dst.MarshalTo(msg, 1)
	binary.BigEndian.PutUint16(msg[1+protocol.AddrSize:], port)
	copy(msg[1+protocol.AddrSize+2:], data)
	return d.ipc.send(msg)
}

// RecvFrom receives the next incoming datagram.
func (d *Driver) RecvFrom() (*Datagram, error) {
	dg, ok := <-d.ipc.dgCh
	if !ok {
		return nil, fmt.Errorf("driver closed")
	}
	return dg, nil
}

// Info returns the daemon's status information.
func (d *Driver) Info() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdInfo}, cmdInfoOK, "info")
}

// Health returns a lightweight health check from the daemon.
func (d *Driver) Health() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHealth}, cmdHealthOK, "health")
}

// Handshake sends a trust handshake request to a remote node.
func (d *Driver) Handshake(nodeID uint32, justification string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(justification))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeSend
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], justification)
	return d.jsonRPC(msg, cmdHandshakeOK, "handshake")
}

// ApproveHandshake approves a pending trust handshake request.
func (d *Driver) ApproveHandshake(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeApprove
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "approve")
}

// RejectHandshake rejects a pending trust handshake request.
func (d *Driver) RejectHandshake(nodeID uint32, reason string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+4+len(reason))
	msg[0] = cmdHandshake
	msg[1] = subHandshakeReject
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	copy(msg[6:], reason)
	return d.jsonRPC(msg, cmdHandshakeOK, "reject")
}

// PendingHandshakes returns pending trust handshake requests.
func (d *Driver) PendingHandshakes() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakePending}, cmdHandshakeOK, "pending")
}

// TrustedPeers returns all trusted peers from the handshake protocol.
func (d *Driver) TrustedPeers() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdHandshake, subHandshakeTrusted}, cmdHandshakeOK, "trusted")
}

// RevokeTrust removes a peer from the trusted set and notifies the registry.
func (d *Driver) RevokeTrust(nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 6)
	msg[0] = cmdHandshake
	msg[1] = subHandshakeRevoke
	binary.BigEndian.PutUint32(msg[2:6], nodeID)
	return d.jsonRPC(msg, cmdHandshakeOK, "revoke")
}

// ResolveHostname resolves a hostname to node info via the daemon.
func (d *Driver) ResolveHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdResolveHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdResolveHostnameOK, "resolve_hostname")
}

// SetHostname sets or clears the daemon's hostname via the registry.
func (d *Driver) SetHostname(hostname string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(hostname))
	msg[0] = cmdSetHostname
	copy(msg[1:], hostname)
	return d.jsonRPC(msg, cmdSetHostnameOK, "set_hostname")
}

// SetVisibility sets the daemon's visibility on the registry.
func (d *Driver) SetVisibility(public bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetVisibility
	if public {
		msg[1] = 1
	}
	return d.jsonRPC(msg, cmdSetVisibilityOK, "set_visibility")
}

// SetTaskExec enables or disables task execution capability on the registry.
func (d *Driver) SetTaskExec(enabled bool) (map[string]interface{}, error) {
	msg := make([]byte, 2)
	msg[0] = cmdSetTaskExec
	if enabled {
		msg[1] = 1
	}
	return d.jsonRPC(msg, cmdSetTaskExecOK, "set_task_exec")
}

// Deregister removes the daemon from the registry.
func (d *Driver) Deregister() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdDeregister}, cmdDeregisterOK, "deregister")
}

// SetTags sets the capability tags for this daemon's node.
func (d *Driver) SetTags(tags []string) (map[string]interface{}, error) {
	data, _ := json.Marshal(tags)
	msg := make([]byte, 1+len(data))
	msg[0] = cmdSetTags
	copy(msg[1:], data)
	return d.jsonRPC(msg, cmdSetTagsOK, "set_tags")
}

// SetWebhook sets or clears the daemon's webhook URL at runtime.
// An empty URL disables the webhook.
func (d *Driver) SetWebhook(url string) (map[string]interface{}, error) {
	msg := make([]byte, 1+len(url))
	msg[0] = cmdSetWebhook
	copy(msg[1:], url)
	return d.jsonRPC(msg, cmdSetWebhookOK, "set_webhook")
}

// Disconnect closes a connection by ID. Used by administrative tools.
func (d *Driver) Disconnect(connID uint32) error {
	msg := make([]byte, 5)
	msg[0] = cmdClose
	binary.BigEndian.PutUint32(msg[1:5], connID)
	_, err := d.ipc.sendAndWait(msg, cmdCloseOK)
	return err
}

// NetworkList returns all networks known to the registry.
func (d *Driver) NetworkList() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdNetwork, subNetworkList}, cmdNetworkOK, "network list")
}

// NetworkJoin joins a network by ID, optionally using a token for token-gated networks.
func (d *Driver) NetworkJoin(networkID uint16, token string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+2+len(token))
	msg[0] = cmdNetwork
	msg[1] = subNetworkJoin
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	copy(msg[4:], token)
	return d.jsonRPC(msg, cmdNetworkOK, "network join")
}

// NetworkLeave leaves a network by ID.
func (d *Driver) NetworkLeave(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdNetwork
	msg[1] = subNetworkLeave
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdNetworkOK, "network leave")
}

// NetworkMembers lists all members of a network.
func (d *Driver) NetworkMembers(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdNetwork
	msg[1] = subNetworkMembers
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdNetworkOK, "network members")
}

// NetworkInvite invites a target node to a network (requires admin token on daemon).
func (d *Driver) NetworkInvite(networkID uint16, targetNodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 8)
	msg[0] = cmdNetwork
	msg[1] = subNetworkInvite
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	binary.BigEndian.PutUint32(msg[4:8], targetNodeID)
	return d.jsonRPC(msg, cmdNetworkOK, "network invite")
}

// NetworkPollInvites returns pending network invites for this node.
func (d *Driver) NetworkPollInvites() (map[string]interface{}, error) {
	return d.jsonRPC([]byte{cmdNetwork, subNetworkPollInvites}, cmdNetworkOK, "network poll-invites")
}

// NetworkRespondInvite accepts or rejects a pending network invite.
func (d *Driver) NetworkRespondInvite(networkID uint16, accept bool) (map[string]interface{}, error) {
	msg := make([]byte, 5)
	msg[0] = cmdNetwork
	msg[1] = subNetworkRespondInvite
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	if accept {
		msg[4] = 1
	}
	return d.jsonRPC(msg, cmdNetworkOK, "network respond-invite")
}

// ManagedScore adjusts a peer's score in a managed network.
func (d *Driver) ManagedScore(networkID uint16, nodeID uint32, delta int, topic string) (map[string]interface{}, error) {
	msg := make([]byte, 1+1+2+4+4+len(topic))
	msg[0] = cmdManaged
	msg[1] = subManagedScore
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	binary.BigEndian.PutUint32(msg[4:8], nodeID)
	binary.BigEndian.PutUint32(msg[8:12], uint32(int32(delta)))
	copy(msg[12:], topic)
	return d.jsonRPC(msg, cmdManagedOK, "managed score")
}

// ManagedStatus returns the status of a managed network engine.
func (d *Driver) ManagedStatus(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedStatus
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed status")
}

// ManagedRankings returns ranked peers in a managed network.
func (d *Driver) ManagedRankings(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedRankings
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed rankings")
}

// ManagedForceCycle forces a prune/fill cycle in a managed network.
func (d *Driver) ManagedForceCycle(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedCycle
	binary.BigEndian.PutUint16(msg[2:4], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "managed cycle")
}

// PolicyGet retrieves the active policy for a network from the daemon.
func (d *Driver) PolicyGet(networkID uint16) (map[string]interface{}, error) {
	msg := make([]byte, 4)
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x00 // get
	// Shift: need [cmd][sub][action][netID_hi][netID_lo]
	msg = make([]byte, 5)
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x00 // get
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	return d.jsonRPC(msg, cmdManagedOK, "policy get")
}

// PolicySet sends a policy document to the daemon for immediate application.
func (d *Driver) PolicySet(networkID uint16, policyJSON []byte) (map[string]interface{}, error) {
	msg := make([]byte, 5+len(policyJSON))
	msg[0] = cmdManaged
	msg[1] = subManagedPolicy
	msg[2] = 0x01 // set
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	copy(msg[5:], policyJSON)
	return d.jsonRPC(msg, cmdManagedOK, "policy set")
}

// MemberTagsGet retrieves admin-assigned member tags for a node in a network.
func (d *Driver) MemberTagsGet(networkID uint16, nodeID uint32) (map[string]interface{}, error) {
	msg := make([]byte, 9)
	msg[0] = cmdManaged
	msg[1] = subManagedMemberTags
	msg[2] = 0x00 // get
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	return d.jsonRPC(msg, cmdManagedOK, "member-tags get")
}

// MemberTagsSet sets admin-assigned member tags for a node in a network.
func (d *Driver) MemberTagsSet(networkID uint16, nodeID uint32, tags []string) (map[string]interface{}, error) {
	tagsJSON, _ := json.Marshal(tags)
	msg := make([]byte, 9+len(tagsJSON))
	msg[0] = cmdManaged
	msg[1] = subManagedMemberTags
	msg[2] = 0x01 // set
	binary.BigEndian.PutUint16(msg[3:5], networkID)
	binary.BigEndian.PutUint32(msg[5:9], nodeID)
	copy(msg[9:], tagsJSON)
	return d.jsonRPC(msg, cmdManagedOK, "member-tags set")
}

// Endpoint describes one transport endpoint for a peer. Network is
// "tcp" or "udp"; Addr is a "host:port" string resolvable by the
// daemon's net.ResolveTCPAddr / net.ResolveUDPAddr.
type Endpoint struct {
	Network string
	Addr    string
}

// SetPeerEndpoints installs externally-sourced endpoints for a peer
// into the daemon's peerTCP map (TCP only — UDP endpoints are ignored
// for now since they're advisory and the daemon's existing dial path
// discovers them). Called by application-layer code when a transport
// advertisement is accepted from out-of-band (e.g. the Entmoot gossip
// layer in v1.2.0). Registry-sourced endpoints take precedence if they
// exist. Safe to call repeatedly with the same nodeID; the latest call
// wins. Returns an error only on IPC transport failure or malformed
// input. (v1.9.0-jf.7)
func (d *Driver) SetPeerEndpoints(nodeID uint32, endpoints []Endpoint) error {
	if len(endpoints) > 8 {
		return fmt.Errorf("set_peer_endpoints: too many endpoints (%d > 8)", len(endpoints))
	}
	// Preflight bounds so we don't hand the daemon a frame it will
	// reject — symmetric with the daemon-side parser limits.
	for i, ep := range endpoints {
		if len(ep.Network) > 16 {
			return fmt.Errorf("set_peer_endpoints: endpoint %d network too long (%d > 16)", i, len(ep.Network))
		}
		if len(ep.Addr) > 255 {
			return fmt.Errorf("set_peer_endpoints: endpoint %d addr too long (%d > 255)", i, len(ep.Addr))
		}
	}

	// Build the TLV payload.
	size := 1 + 4 + 1
	for _, ep := range endpoints {
		size += 1 + len(ep.Network) + 1 + len(ep.Addr)
	}
	msg := make([]byte, size)
	msg[0] = cmdSetPeerEndpoints
	binary.BigEndian.PutUint32(msg[1:5], nodeID)
	msg[5] = byte(len(endpoints))
	off := 6
	for _, ep := range endpoints {
		msg[off] = byte(len(ep.Network))
		off++
		copy(msg[off:], ep.Network)
		off += len(ep.Network)
		msg[off] = byte(len(ep.Addr))
		off++
		copy(msg[off:], ep.Addr)
		off += len(ep.Addr)
	}

	if _, err := d.ipc.sendAndWait(msg, cmdSetPeerEndpointsOK); err != nil {
		return fmt.Errorf("set_peer_endpoints: %w", err)
	}
	return nil
}

// Close disconnects from the daemon.
func (d *Driver) Close() error {
	return d.ipc.close()
}
