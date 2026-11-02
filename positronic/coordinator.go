// Package positronic maintains authenticated inventory for explicitly enrolled nodes.
// Optional typed workload services share the existing fabric trust boundary.
package positronic

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

const schemaVersion = 1
const maxHeartbeatBytes = 128 << 10
const maxViewBytes = 4 << 20

// Capacity sums measurements from online nodes only. It is not a scheduler lease.
type Capacity struct {
	LogicalCores          int    `json:"logical_cores"`
	MemoryAvailableBytes  uint64 `json:"memory_available_bytes"`
	StorageAvailableBytes uint64 `json:"storage_available_bytes"`
}

type NodeView struct {
	Name       string              `json:"name"`
	NodeID     string              `json:"node_id"`
	Kind       string              `json:"kind"`
	Status     string              `json:"status"`
	Endpoint   *string             `json:"endpoint"`
	LastSeenMS *int64              `json:"last_seen_ms"`
	Error      *string             `json:"error"`
	Resources  *inventory.Snapshot `json:"resources"`
}

type View struct {
	SchemaVersion     int        `json:"schema_version"`
	CollectedAtMS     int64      `json:"collected_at_ms"`
	FabricID          string     `json:"fabric_id"`
	LocalNodeID       string     `json:"local_node_id"`
	Nodes             []NodeView `json:"nodes"`
	AvailableCapacity Capacity   `json:"available_capacity"`
}

type Heartbeat struct {
	SchemaVersion int                `json:"schema_version"`
	FabricID      string             `json:"fabric_id"`
	NodeID        string             `json:"node_id"`
	Resources     inventory.Snapshot `json:"resources"`
}

type observation struct {
	resources inventory.Snapshot
	received  time.Time
}

// Coordinator keeps volatile measurements separate from durable fabric membership.
type Coordinator struct {
	home     string
	ttl      time.Duration
	load     func() (*fabric.State, error)
	now      func() time.Time
	mu       sync.RWMutex
	local    observation
	remote   map[string]observation
	workload func(http.ResponseWriter, *http.Request, string)
}

func New(home string, local inventory.Snapshot, ttl time.Duration) (*Coordinator, error) {
	if ttl <= 0 {
		return nil, errors.New("heartbeat TTL must be positive")
	}
	state, err := fabric.Load(home)
	if err != nil {
		return nil, err
	}
	if state.FabricID == "" {
		return nil, errors.New("initialize a fabric before starting Positronic")
	}
	if state.NodeID != state.OwnerID {
		return nil, errors.New("the fabric owner hosts this Alpha 0.2 coordinator")
	}
	if err := inventory.Validate(local); err != nil {
		return nil, fmt.Errorf("local inventory: %w", err)
	}
	copied, err := copySnapshot(local)
	if err != nil {
		return nil, err
	}
	return &Coordinator{
		home: home, ttl: ttl, load: func() (*fabric.State, error) { return fabric.Load(home) },
		now: time.Now, local: observation{resources: copied, received: time.Now()},
		remote: make(map[string]observation),
	}, nil
}

// UpdateLocal retains the last valid measurement if a collection is invalid.
// Failed collections never extend its liveness.
func (c *Coordinator) UpdateLocal(snapshot inventory.Snapshot) {
	if inventory.Validate(snapshot) != nil {
		return
	}
	copied, err := copySnapshot(snapshot)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.local = observation{resources: copied, received: c.now()}
	c.mu.Unlock()
}

// View authorizes the viewer against current membership, including after revocation.
// The viewing machine is "local"; all other machines are "peer".
func (c *Coordinator) View(viewerID string) (View, error) {
	state, err := c.load()
	if err != nil {
		return View{}, err
	}
	if _, ok := state.Members[viewerID]; !ok {
		return View{}, errors.New("viewer is not a fabric member")
	}
	if state.FabricID == "" {
		return View{}, errors.New("fabric is not initialized")
	}
	now := c.now()
	result := View{
		SchemaVersion: schemaVersion, CollectedAtMS: now.UnixMilli(),
		FabricID: state.FabricID, LocalNodeID: viewerID, Nodes: []NodeView{},
	}
	// Membership, rather than the measurement cache, defines the nodes in the fabric.
	ids := make([]string, 0, len(state.Members))
	for id := range state.Members {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i] == viewerID {
			return ids[j] != viewerID
		}
		if ids[j] == viewerID {
			return false
		}
		return ids[i] < ids[j]
	})
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, id := range ids {
		member := state.Members[id]
		node := NodeView{Name: member.Name, NodeID: id, Kind: "peer", Status: "awaiting"}
		if id == viewerID {
			node.Kind = "local"
		}
		if id == state.OwnerID && id != viewerID {
			endpoint := state.Endpoint
			node.Endpoint = &endpoint
		}
		observed, exists := c.remote[id]
		if id == state.NodeID {
			observed, exists = c.local, true
		}
		if exists && !observed.received.IsZero() {
			resources, err := copySnapshot(observed.resources)
			if err != nil {
				return View{}, err
			}
			node.Resources = &resources
			lastSeen := observed.received.UnixMilli()
			node.LastSeenMS = &lastSeen
			if now.Sub(observed.received) >= c.ttl {
				node.Status = "offline"
				message := "Heartbeat expired; cached resources are excluded from available capacity."
				node.Error = &message
			} else {
				node.Status = "online"
				if err := addCapacity(&result.AvailableCapacity, resources); err != nil {
					return View{}, err
				}
			}
		} else {
			message := "Awaiting the first authenticated heartbeat."
			node.Error = &message
		}
		result.Nodes = append(result.Nodes, node)
	}
	return result, nil
}

// Handler exposes authenticated inventory and an optional typed workload service.
// Every request checks durable membership, even on an already-established TLS socket.
func (c *Coordinator) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		state, nodeID, err := c.authenticate(r)
		if err != nil {
			http.Error(w, "fabric membership required", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/v1/heartbeat" && r.Method == http.MethodPost:
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				http.Error(w, "application/json required", http.StatusUnsupportedMediaType)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxHeartbeatBytes)
			defer r.Body.Close()
			var heartbeat Heartbeat
			if err := decodeJSON(r.Body, &heartbeat); err != nil {
				http.Error(w, "invalid or oversized heartbeat", http.StatusBadRequest)
				return
			}
			if heartbeat.SchemaVersion != schemaVersion || heartbeat.FabricID != state.FabricID || heartbeat.NodeID != nodeID {
				http.Error(w, "heartbeat identity or schema mismatch", http.StatusBadRequest)
				return
			}
			if err := inventory.Validate(heartbeat.Resources); err != nil {
				http.Error(w, "invalid resource inventory", http.StatusBadRequest)
				return
			}
			// A membership change while the body was being read must also take effect.
			latest, latestID, err := c.authenticate(r)
			if err != nil || latestID != nodeID || latest.FabricID != heartbeat.FabricID {
				http.Error(w, "fabric membership changed", http.StatusForbidden)
				return
			}
			copied, err := copySnapshot(heartbeat.Resources)
			if err != nil {
				http.Error(w, "invalid resource inventory", http.StatusBadRequest)
				return
			}
			c.mu.Lock()
			observed := observation{resources: copied, received: c.now()}
			if nodeID == latest.NodeID {
				c.local = observed
			} else {
				c.remote[nodeID] = observed
			}
			c.mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/fabric" && r.Method == http.MethodGet:
			view, err := c.View(nodeID)
			if err != nil {
				http.Error(w, "fabric view unavailable", http.StatusForbidden)
				return
			}
			body, err := json.Marshal(view)
			if err != nil || len(body) > maxViewBytes {
				http.Error(w, "fabric view exceeds limit", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
		case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"service":"positronic","schema_version":1,"state":"private_fabric"}`)
		case r.URL.Path == "/v1/heartbeat" || r.URL.Path == "/v1/fabric" || r.URL.Path == "/healthz":
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		default:
			c.mu.RLock()
			handler := c.workload
			c.mu.RUnlock()
			if handler != nil && strings.HasPrefix(r.URL.Path, "/v1/inference/worker/") {
				handler(w, r, nodeID)
				return
			}
			http.NotFound(w, r)
		}
	})
}

func (c *Coordinator) authenticate(r *http.Request) (*fabric.State, string, error) {
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
		return nil, "", errors.New("mutually authenticated TLS required")
	}
	state, err := c.load()
	if err != nil {
		return nil, "", err
	}
	ca, err := x509.ParseCertificate(state.CACertificate)
	if err != nil {
		return nil, "", err
	}
	// Existing TLS sessions must not cross an on-disk fabric/authority replacement.
	currentRoot := false
	for _, chain := range r.TLS.VerifiedChains {
		if len(chain) > 0 && bytes.Equal(chain[len(chain)-1].Raw, ca.Raw) {
			currentRoot = true
			break
		}
	}
	if !currentRoot {
		return nil, "", errors.New("TLS session belongs to a different fabric")
	}
	cert := r.TLS.PeerCertificates[0]
	now := c.now()
	if len(cert.RawSubjectPublicKeyInfo) == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, "", errors.New("invalid or expired peer certificate")
	}
	nodeID := certificateNodeID(cert)
	member, ok := state.Members[nodeID]
	if !ok || member.NodeID != nodeID {
		return nil, "", errors.New("node is no longer a fabric member")
	}
	return state, nodeID, nil
}

func certificateNodeID(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func copySnapshot(snapshot inventory.Snapshot) (inventory.Snapshot, error) {
	data, err := json.Marshal(snapshot)
	if err != nil {
		return inventory.Snapshot{}, err
	}
	var copied inventory.Snapshot
	if err := json.Unmarshal(data, &copied); err != nil {
		return inventory.Snapshot{}, err
	}
	return copied, nil
}
func addCapacity(capacity *Capacity, snapshot inventory.Snapshot) error {
	maxInt := int(^uint(0) >> 1)
	if snapshot.CPU.LogicalCores > maxInt-capacity.LogicalCores ||
		snapshot.Memory.AvailableBytes > math.MaxUint64-capacity.MemoryAvailableBytes {
		return errors.New("available capacity exceeds numeric limits")
	}
	if snapshot.Storage != nil && snapshot.Storage.AvailableBytes > math.MaxUint64-capacity.StorageAvailableBytes {
		return errors.New("available storage exceeds numeric limits")
	}
	capacity.LogicalCores += snapshot.CPU.LogicalCores
	capacity.MemoryAvailableBytes += snapshot.Memory.AvailableBytes
	if snapshot.Storage != nil {
		capacity.StorageAvailableBytes += snapshot.Storage.AvailableBytes
	}
	return nil
}

// SetWorkloadHandler attaches a typed service after per-request membership checks.
func (c *Coordinator) SetWorkloadHandler(handler func(http.ResponseWriter, *http.Request, string)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workload = handler
}
