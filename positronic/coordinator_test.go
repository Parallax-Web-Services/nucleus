package positronic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

func sample(cores int) inventory.Snapshot {
	return inventory.Snapshot{
		SchemaVersion: 1, CollectedAtMS: time.Now().UnixMilli(),
		Node:    inventory.Node{Name: "measured-node", OperatingSystem: "linux"},
		CPU:     inventory.CPU{LogicalCores: cores},
		Memory:  inventory.Memory{TotalBytes: 1024, AvailableBytes: 768, UsedBytes: 256},
		Storage: &inventory.Storage{Mount: "/", TotalBytes: 8192, AvailableBytes: 4096, UsedBytes: 4096},
		Network: []inventory.NetworkInterface{{Name: "eth0", LinkState: "up"}},
		GPU:     inventory.GPU{Status: "unavailable", Note: "not measured"},
	}
}

type fixture struct {
	coordinator       *Coordinator
	mu                sync.Mutex
	state             *fabric.State
	now               time.Time
	ca, owner, member *x509.Certificate
	ownerID, memberID string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	caKey, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test authority"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64) *x509.Certificate {
		key, err := newKey()
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "test node"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, key.Public(), caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	owner, member := issue(2), issue(3)
	ownerID, memberID := certificateNodeID(owner), certificateNodeID(member)
	f := &fixture{now: now, ca: ca, owner: owner, member: member, ownerID: ownerID, memberID: memberID}
	f.state = &fabric.State{
		Name: "owner", NodeID: ownerID, OwnerID: ownerID, FabricID: strings.Repeat("a", 64),
		Endpoint: "https://127.0.0.1:9443", Certificate: owner.Raw, CACertificate: caDER,
		Members: map[string]fabric.Member{
			ownerID: {Name: "owner", NodeID: ownerID}, memberID: {Name: "worker", NodeID: memberID},
		},
	}
	f.coordinator = &Coordinator{
		ttl: 10 * time.Second, remote: make(map[string]observation),
		local: observation{resources: sample(2), received: now},
		load: func() (*fabric.State, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			encoded, _ := json.Marshal(f.state)
			var copy fabric.State
			if err := json.Unmarshal(encoded, &copy); err != nil {
				return nil, err
			}
			return &copy, nil
		},
		now: func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
	}
	return f
}
func newKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}
func (f *fixture) advance(duration time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(duration)
	f.mu.Unlock()
}
func (f *fixture) body(cores int) Heartbeat {
	return Heartbeat{SchemaVersion: 1, FabricID: f.state.FabricID, NodeID: f.memberID, Resources: sample(cores)}
}
func (f *fixture) request(method, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.TLS = &tls.ConnectionState{
		Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{f.member},
		VerifiedChains: [][]*x509.Certificate{{f.member, f.ca}},
	}
	response := httptest.NewRecorder()
	f.coordinator.Handler().ServeHTTP(response, request)
	return response
}
func (f *fixture) heartbeat(t *testing.T, cores int) {
	t.Helper()
	body, err := json.Marshal(f.body(cores))
	if err != nil {
		t.Fatal(err)
	}
	response := f.request(http.MethodPost, "/v1/heartbeat", body)
	if response.Code != http.StatusNoContent {
		t.Fatalf("heartbeat: %d %s", response.Code, response.Body.String())
	}
}
func nodeByID(t *testing.T, view View, id string) NodeView {
	t.Helper()
	for _, node := range view.Nodes {
		if node.NodeID == id {
			return node
		}
	}
	t.Fatalf("node %s missing", id)
	return NodeView{}
}

func TestHeartbeatLivenessCapacityAndReconnect(t *testing.T) {
	f := newFixture(t)
	initial, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if nodeByID(t, initial, f.memberID).Status != "awaiting" || initial.AvailableCapacity.LogicalCores != 2 {
		t.Fatalf("initial inventory: %+v", initial)
	}
	f.heartbeat(t, 6)
	connected, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if connected.AvailableCapacity.LogicalCores != 8 || connected.AvailableCapacity.MemoryAvailableBytes != 1536 {
		t.Fatalf("connected capacity: %+v", connected.AvailableCapacity)
	}
	lastSeen := *nodeByID(t, connected, f.memberID).LastSeenMS
	f.advance(10 * time.Second)
	f.coordinator.UpdateLocal(sample(2))
	offline, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	cached := nodeByID(t, offline, f.memberID)
	if cached.Status != "offline" || cached.Resources == nil || *cached.LastSeenMS != lastSeen ||
		offline.AvailableCapacity.LogicalCores != 2 || offline.AvailableCapacity.MemoryAvailableBytes != 768 {
		t.Fatalf("offline inventory: %+v", offline)
	}
	f.heartbeat(t, 8)
	reconnected, err := f.coordinator.View(f.memberID)
	if err != nil {
		t.Fatal(err)
	}
	own := nodeByID(t, reconnected, f.memberID)
	owner := nodeByID(t, reconnected, f.ownerID)
	if own.Kind != "local" || own.Status != "online" || owner.Kind != "peer" || owner.Endpoint == nil ||
		reconnected.LocalNodeID != f.memberID || reconnected.AvailableCapacity.LogicalCores != 10 {
		t.Fatalf("reconnected inventory: %+v", reconnected)
	}
}

func TestHeartbeatUsesReceiptTimeAndRejectsSpoofing(t *testing.T) {
	f := newFixture(t)
	heartbeat := f.body(4)
	heartbeat.Resources.CollectedAtMS = time.Now().Add(365 * 24 * time.Hour).UnixMilli()
	body, _ := json.Marshal(heartbeat)
	response := f.request(http.MethodPost, "/v1/heartbeat", body)
	if response.Code != http.StatusNoContent {
		t.Fatal(response.Code, response.Body.String())
	}
	view, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if *nodeByID(t, view, f.memberID).LastSeenMS != f.now.UnixMilli() {
		t.Fatal("worker timestamp used for liveness")
	}
	for name, change := range map[string]func(*Heartbeat){
		"node":   func(h *Heartbeat) { h.NodeID = f.ownerID },
		"fabric": func(h *Heartbeat) { h.FabricID = strings.Repeat("b", 64) },
		"schema": func(h *Heartbeat) { h.SchemaVersion = 2 },
		"memory": func(h *Heartbeat) { h.Resources.Memory.AvailableBytes = h.Resources.Memory.TotalBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			value := f.body(4)
			change(&value)
			data, _ := json.Marshal(value)
			if got := f.request(http.MethodPost, "/v1/heartbeat", data).Code; got != http.StatusBadRequest {
				t.Fatal(got)
			}
		})
	}
}

func TestRevocationAppliesToExistingTLSSession(t *testing.T) {
	f := newFixture(t)
	f.heartbeat(t, 4)
	f.mu.Lock()
	delete(f.state.Members, f.memberID)
	f.mu.Unlock()
	body, _ := json.Marshal(f.body(4))
	// This fixture uses the exact same verified TLS session after membership changes.
	if got := f.request(http.MethodPost, "/v1/heartbeat", body).Code; got != http.StatusForbidden {
		t.Fatal(got)
	}
	if got := f.request(http.MethodGet, "/v1/fabric", nil).Code; got != http.StatusForbidden {
		t.Fatal(got)
	}
	view, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Nodes) != 1 || view.AvailableCapacity.LogicalCores != 2 {
		t.Fatalf("%+v", view)
	}
	if _, err := f.coordinator.View(f.memberID); err == nil {
		t.Fatal("revoked viewer accepted")
	}
}

func TestEndpointRequiresMTLSAndOnlyAllowsTelemetry(t *testing.T) {
	f := newFixture(t)
	for _, session := range []*tls.ConnectionState{
		nil,
		{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{f.member}},
		{Version: tls.VersionTLS12, PeerCertificates: []*x509.Certificate{f.member}, VerifiedChains: [][]*x509.Certificate{{f.member, f.ca}}},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/fabric", nil)
		request.TLS = session
		response := httptest.NewRecorder()
		f.coordinator.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatal(response.Code)
		}
	}
	if got := f.request(http.MethodPost, "/v1/exec", nil).Code; got != http.StatusNotFound {
		t.Fatal(got)
	}
	if got := f.request(http.MethodDelete, "/v1/fabric", nil).Code; got != http.StatusMethodNotAllowed {
		t.Fatal(got)
	}
	if got := f.request(http.MethodGet, "/v1/heartbeat", nil).Code; got != http.StatusMethodNotAllowed {
		t.Fatal(got)
	}
	valid, _ := json.Marshal(f.body(4))
	for _, body := range [][]byte{
		append(append([]byte{}, valid...), []byte("\n{}")...),
		[]byte(strings.Replace(string(valid), `"schema_version":1`, `"unknown":true,"schema_version":1`, 1)),
		bytes.Repeat([]byte(" "), maxHeartbeatBytes+1),
	} {
		if got := f.request(http.MethodPost, "/v1/heartbeat", body).Code; got != http.StatusBadRequest {
			t.Fatal(got)
		}
	}
}

func TestLocalValidationAndViewCopies(t *testing.T) {
	f := newFixture(t)
	value := sample(2)
	f.coordinator.UpdateLocal(value)
	value.Network[0].Name = "mutated"
	view, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if nodeByID(t, view, f.ownerID).Resources.Network[0].Name != "eth0" {
		t.Fatal("caller changed coordinator cache")
	}
	nodeByID(t, view, f.ownerID).Resources.CPU.LogicalCores = 100
	view, err = f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if view.AvailableCapacity.LogicalCores != 2 {
		t.Fatal("view changed coordinator cache")
	}
	f.advance(11 * time.Second)
	invalid := sample(2)
	invalid.Memory.TotalBytes = 0
	f.coordinator.UpdateLocal(invalid)
	stale, err := f.coordinator.View(f.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if stale.AvailableCapacity.LogicalCores != 0 || nodeByID(t, stale, f.ownerID).Status != "offline" {
		t.Fatal("invalid collection extended local liveness")
	}
}

func TestViewValidationExcludesOfflineInventory(t *testing.T) {
	f := newFixture(t)
	f.heartbeat(t, 6)
	view, err := f.coordinator.View(f.memberID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateView(view, f.state.FabricID, f.memberID); err != nil {
		t.Fatal(err)
	}
	view.AvailableCapacity.LogicalCores++
	if err := validateView(view, f.state.FabricID, f.memberID); err == nil {
		t.Fatal("inconsistent capacity accepted")
	}
}

// This test uses independent durable identities and actual TLS sockets. It is a
// two-process-equivalent protocol test, not a claim about two physical machines.
func TestExchangeOverRealMutualTLSAndRevocationOnKeepalive(t *testing.T) {
	ownerHome := filepath.Join(t.TempDir(), "owner")
	memberHome := filepath.Join(t.TempDir(), "member")
	if _, err := fabric.Init(ownerHome, "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := fabric.Init(memberHome, "member"); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	endpoint := "https://" + listener.Addr().String()
	invitation, err := fabric.Invite(ownerHome, endpoint, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := fabric.Join(memberHome, invitation)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fabric.Accept(ownerHome, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := fabric.FinishJoin(memberHome, grant); err != nil {
		t.Fatal(err)
	}
	owner, err := fabric.Load(ownerHome)
	if err != nil {
		t.Fatal(err)
	}
	member, err := fabric.Load(memberHome)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := New(ownerHome, sample(2), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig, err := fabric.ServerTLS(ownerHome)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler: coordinator.Handler(), ReadHeaderTimeout: time.Second,
		ErrorLog: log.New(io.Discard, "", 0),
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(tls.NewListener(listener, serverConfig)) }()
	t.Cleanup(func() { server.Close(); <-done })
	view, err := Exchange(memberHome, sample(6))
	if err != nil {
		t.Fatal(err)
	}
	if owner.FabricID != member.FabricID || owner.NodeID == member.NodeID ||
		view.LocalNodeID != member.NodeID || len(view.Nodes) != 2 || view.AvailableCapacity.LogicalCores != 8 {
		t.Fatalf("unexpected real TLS view: %+v", view)
	}
	restartedBeforeRevoke, err := New(ownerHome, sample(2), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	initialBeforeRevoke, err := restartedBeforeRevoke.View(owner.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if nodeByID(t, initialBeforeRevoke, member.NodeID).Status != "awaiting" || initialBeforeRevoke.AvailableCapacity.LogicalCores != 2 {
		t.Fatal("coordinator restart restored remote capacity without a fresh heartbeat")
	}
	clientConfig, err := fabric.ClientTLS(memberHome)
	if err != nil {
		t.Fatal(err)
	}
	noCertificate := clientConfig.Clone()
	noCertificate.Certificates = nil
	rejected := &http.Client{Transport: &http.Transport{TLSClientConfig: noCertificate, Proxy: nil}, Timeout: 2 * time.Second}
	if response, err := rejected.Get(endpoint + "/v1/fabric"); err == nil {
		response.Body.Close()
		t.Fatal("client without certificate accepted")
	}
	transport := &http.Transport{TLSClientConfig: clientConfig, Proxy: nil, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	get := func(expectReused bool) int {
		reused := false
		request, err := http.NewRequest(http.MethodGet, endpoint+"/v1/fabric", nil)
		if err != nil {
			t.Fatal(err)
		}
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), trace))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if expectReused && !reused {
			t.Fatal("test did not reuse the existing TLS connection")
		}
		return response.StatusCode
	}
	if code := get(false); code != http.StatusOK {
		t.Fatal(code)
	}
	if err := fabric.Revoke(ownerHome, member.NodeID); err != nil {
		t.Fatal(err)
	}
	if code := get(true); code != http.StatusForbidden {
		t.Fatal(code)
	}
	after, err := coordinator.View(owner.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Nodes) != 1 || after.AvailableCapacity.LogicalCores != 2 {
		t.Fatal("revoked node retained capacity")
	}
	if _, err := Exchange(memberHome, sample(6)); err == nil {
		t.Fatal("revoked node opened a new authenticated connection")
	}
	restarted, err := New(ownerHome, sample(2), 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := restarted.View(owner.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.Nodes) != 1 || initial.AvailableCapacity.LogicalCores != 2 {
		t.Fatalf("%+v", initial)
	}
}
