// Package main implements pilot-rendezvous: a tiny HTTP service
// that stores ed25519-signed (NodeID -> TURN endpoint) records,
// exactly the shape iroh's iroh-dns-server uses. It is the third
// independent endpoint-distribution channel introduced in Pilot
// v1.9.0-jf.14, complementing the centralized registry and the
// gossip overlay.
//
// Trust model. The service is trusted for AVAILABILITY only.
// Records are signed by each peer's own ed25519 identity (the
// same key pilot-daemon already loads from identity.json), so a
// compromised service cannot inject endpoints. It can enumerate
// NodeIDs that have published and selectively withhold blobs;
// both are strict subsets of leakage already present in the
// gossip layer.
//
// Storage. bbolt at --db; two buckets:
//   - bindings : NodeID(uint32 BE) -> public_key(32 bytes)
//   - blobs    : NodeID(uint32 BE) -> AnnounceBlob(JSON)
//
// First-PUT-wins TOFU on bindings. Subsequent PUTs whose
// PublicKey doesn't match the stored binding return 409
// Conflict. Operator can override out-of-band by deleting the
// binding row in bbolt; future jf.15 will cross-check against
// the entmoot roster automatically.
//
// Rate limiting. 1 PUT per minute per NodeID via an in-process
// token bucket. GET is unmetered (cheap, idempotent).
package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/TeoSlayer/pilotprotocol/pkg/daemon/rendezvous"
)

// HTTP request/body limits. The whole point of this service is
// to be cheap to operate; we cap aggressively.
const (
	maxBodyBytes = 16 * 1024 // 16 KiB; AnnounceBlob is ~256 bytes encoded
	putRateLimit = 1 * time.Minute
)

var (
	bucketBindings = []byte("bindings")
	bucketBlobs    = []byte("blobs")
)

// errKeyMismatch is the 409 Conflict signal: the public key in
// the incoming PUT doesn't match the TOFU binding stored on
// first publish for this NodeID.
var errKeyMismatch = errors.New("public key does not match stored binding")

// Server is the HTTP handler + bbolt store. One per process.
// All exported methods are safe for concurrent use.
type Server struct {
	db    *bolt.DB
	now   func() time.Time // tests inject a fake clock
	rate  *putRateLimiter
	rate2 sync.Mutex // unused but reserved for future fairness queue
}

// NewServer opens the bbolt database, ensures both buckets
// exist, and returns a ready-to-serve handler.
func NewServer(dbPath string) (*Server, error) {
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open db %s: %w", dbPath, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketBindings, bucketBlobs} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init buckets: %w", err)
	}
	return &Server{
		db:   db,
		now:  time.Now,
		rate: newPutRateLimiter(putRateLimit),
	}, nil
}

// Close releases the bbolt handle.
func (s *Server) Close() error { return s.db.Close() }

// Routes wires the three endpoints onto a fresh ServeMux.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/announce/", s.handleAnnounce)
	mux.HandleFunc("/v1/health", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, "ok\n")
}

// handleAnnounce dispatches PUT and GET on /v1/announce/<NodeID>.
func (s *Server) handleAnnounce(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/v1/announce/")
	id64, err := strconv.ParseUint(idStr, 10, 32)
	if err != nil {
		http.Error(w, "invalid node id", http.StatusBadRequest)
		return
	}
	nodeID := uint32(id64)
	switch r.Method {
	case http.MethodPut:
		s.handlePUT(w, r, nodeID)
	case http.MethodGet:
		s.handleGET(w, nodeID)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePUT(w http.ResponseWriter, r *http.Request, nodeID uint32) {
	if ok, retryAfter := s.rate.Allow(nodeID, s.now()); !ok {
		seconds := int((retryAfter + time.Second - time.Nanosecond) / time.Second)
		if seconds < 1 {
			seconds = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var blob rendezvous.AnnounceBlob
	if err := json.Unmarshal(body, &blob); err != nil {
		http.Error(w, "unmarshal: "+err.Error(), http.StatusBadRequest)
		return
	}
	// The path's NodeID must match the body's. Without this
	// check, a PUT to /v1/announce/1 could store a blob for
	// NodeID 2 and break GET /v1/announce/2 in surprising
	// ways.
	if blob.NodeID != nodeID {
		http.Error(w, "node id in path != node id in body", http.StatusBadRequest)
		return
	}
	if err := blob.VerifyPUT(s.now()); err != nil {
		http.Error(w, "verify: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.storeBlob(&blob); err != nil {
		switch {
		case errors.Is(err, errKeyMismatch):
			http.Error(w, "public key conflicts with TOFU binding", http.StatusConflict)
		default:
			slog.Error("rendezvous: store blob", "node_id", nodeID, "error", err)
			http.Error(w, "store: "+err.Error(), http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGET(w http.ResponseWriter, nodeID uint32) {
	blob, ok, err := s.loadBlob(nodeID)
	if err != nil {
		slog.Error("rendezvous: load blob", "node_id", nodeID, "error", err)
		http.Error(w, "load: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(blob)
}

// storeBlob persists an already-VerifyPUT'd blob with TOFU
// binding semantics:
//
//   - If no binding exists for this NodeID: accept the blob,
//     store its PublicKey as the binding.
//   - If a binding exists: the blob's PublicKey MUST equal it.
//     Otherwise return errKeyMismatch.
//   - If a stored blob already exists with a newer IssuedAt
//     than the incoming: leave it alone (monotonic).
//
// All three checks happen inside a single bolt.Update so
// concurrent PUTs serialize cleanly.
func (s *Server) storeBlob(blob *rendezvous.AnnounceBlob) error {
	key := nodeIDKey(blob.NodeID)
	return s.db.Update(func(tx *bolt.Tx) error {
		bindings := tx.Bucket(bucketBindings)
		blobs := tx.Bucket(bucketBlobs)

		if existing := bindings.Get(key); existing != nil {
			if !ed25519.PublicKey(existing).Equal(ed25519.PublicKey(blob.PublicKey)) {
				return errKeyMismatch
			}
		} else {
			pk := make([]byte, len(blob.PublicKey))
			copy(pk, blob.PublicKey)
			if err := bindings.Put(key, pk); err != nil {
				return err
			}
		}
		if existing := blobs.Get(key); existing != nil {
			var prior rendezvous.AnnounceBlob
			if err := json.Unmarshal(existing, &prior); err == nil {
				if prior.IssuedAt > blob.IssuedAt {
					// Newer blob already on file; reject silently
					// (return success to the caller — they didn't
					// do anything wrong; their clock is just behind
					// the latest publish).
					return nil
				}
			}
		}
		encoded, err := json.Marshal(blob)
		if err != nil {
			return err
		}
		return blobs.Put(key, encoded)
	})
}

func (s *Server) loadBlob(nodeID uint32) (*rendezvous.AnnounceBlob, bool, error) {
	key := nodeIDKey(nodeID)
	var blob rendezvous.AnnounceBlob
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketBlobs).Get(key)
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &blob)
	})
	if err != nil {
		return nil, false, err
	}
	if !found {
		return nil, false, nil
	}
	return &blob, true, nil
}

func nodeIDKey(nodeID uint32) []byte {
	var k [4]byte
	binary.BigEndian.PutUint32(k[:], nodeID)
	return k[:]
}

// putRateLimiter is a per-NodeID minimum-interval gate.
// Sufficient for our threat model — an attacker hammering one
// NodeID can't burn server CPU faster than 1/min, and
// attackers spraying many NodeIDs hit the body cap + bbolt
// write throughput as the next bottleneck. We deliberately do
// NOT bound the map size — for a privacy-mesh deployment the
// cardinality of NodeIDs that ever publish is small (< 10^4),
// and operators who run public services should front this with
// a real reverse proxy.
type putRateLimiter struct {
	mu       sync.Mutex
	last     map[uint32]time.Time
	interval time.Duration
}

func newPutRateLimiter(interval time.Duration) *putRateLimiter {
	return &putRateLimiter{
		last:     map[uint32]time.Time{},
		interval: interval,
	}
}

// Allow returns true if a PUT for nodeID is permitted at `now`,
// updating the per-NodeID last-allow timestamp on success. When
// it returns false, the second return value is the remaining
// interval callers should expose as Retry-After.
func (r *putRateLimiter) Allow(nodeID uint32, now time.Time) (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if last, ok := r.last[nodeID]; ok {
		if now.Sub(last) < r.interval {
			return false, r.interval - now.Sub(last)
		}
	}
	r.last[nodeID] = now
	return true, 0
}
