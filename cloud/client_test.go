package cloud

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

type hostedFixture struct {
	t              *testing.T
	server         *httptest.Server
	mu             sync.Mutex
	nodeID         string
	public         ed25519.PublicKey
	proved         bool
	approved       bool
	state          string
	badVerify      bool
	badApproval    bool
	heartbeatCode  int
	heartbeatError string
	heartbeats     int
	deletes        int
	proofs         int
	nonces         map[string]bool
}

func fixture(t *testing.T) *hostedFixture {
	t.Helper()
	f := &hostedFixture{t: t, state: "approved", nonces: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *hostedFixture) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 65537))
	w.Header().Set("Content-Type", "application/json")
	respond := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch r.URL.Path {
	case "/dashboard/api/enroll":
		var body struct {
			NodeID    string  `json:"node_id"`
			PublicKey string  `json:"public_key"`
			FabricID  *string `json:"fabric_id"`
			Hostname  string  `json:"hostname"`
			Platform  string  `json:"platform"`
			Arch      string  `json:"arch"`
			Version   string  `json:"version"`
		}
		if r.Method != "POST" || json.Unmarshal(raw, &body) != nil || body.Hostname == "" ||
			body.Platform != "linux" || body.Arch == "" || body.Version != Version || body.FabricID != nil {
			f.t.Error("invalid enrollment facts")
			w.WriteHeader(400)
			return
		}
		key, err := base64.StdEncoding.DecodeString(body.PublicKey)
		if err != nil || len(key) != ed25519.PublicKeySize {
			f.t.Error("invalid raw public key")
			w.WriteHeader(400)
			return
		}
		der, _ := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
		digest := sha256.Sum256(der)
		if body.NodeID != hex.EncodeToString(digest[:]) {
			f.t.Error("node ID is not the SPKI fingerprint")
		}
		f.nodeID, f.public = body.NodeID, ed25519.PublicKey(key)
		verify := "/dashboard/enroll?code=AB12-CD34"
		if f.badVerify {
			verify = "https://other.example.test/dashboard/enroll?code=AB12-CD34"
		}
		respond(map[string]any{
			"enrollment_id": "a1234567-1234-4567-8123-123456789abc", "user_code": "AB12-CD34",
			"verification_uri": verify, "poll_token": strings.Repeat("a", 64),
			"challenge": strings.Repeat("b", 64), "expires_in": 10, "interval": 1,
		})
	case "/dashboard/api/enroll/a1234567-1234-4567-8123-123456789abc/prove":
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		signature, _ := base64.StdEncoding.DecodeString(body["signature"])
		message := EnrollmentMessage(f.server.URL, "a1234567-1234-4567-8123-123456789abc", f.nodeID, strings.Repeat("b", 64))
		if body["poll_token"] != strings.Repeat("a", 64) || !ed25519.Verify(f.public, []byte(message), signature) {
			f.t.Error("invalid origin-bound key proof")
			w.WriteHeader(400)
			return
		}
		f.proved = true
		f.proofs++
		respond(map[string]bool{"proved": true})
	case "/dashboard/api/enroll/a1234567-1234-4567-8123-123456789abc/poll":
		var body map[string]string
		_ = json.Unmarshal(raw, &body)
		if body["poll_token"] != strings.Repeat("a", 64) || !f.proved {
			w.WriteHeader(403)
			return
		}
		state := f.state
		if state == "approved" && !f.approved {
			state = "pending"
		}
		node := f.nodeID
		if f.badApproval {
			node = strings.Repeat("0", 64)
		}
		respond(map[string]any{
			"state": state, "node_id": node, "organization_id": 123,
			"heartbeat_url":              f.server.URL + "/dashboard/api/nodes/" + f.nodeID + "/heartbeat",
			"heartbeat_interval_seconds": 60,
		})
	default:
		path := "/dashboard/api/nodes/" + f.nodeID
		if r.URL.Path != path && r.URL.Path != path+"/heartbeat" {
			w.WriteHeader(404)
			return
		}
		timestamp := r.Header.Get("X-Nucleus-Timestamp")
		nonce := r.Header.Get("X-Nucleus-Nonce")
		signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Nucleus-Signature"))
		if len(nonce) != 32 || f.nonces[nonce] ||
			!ed25519.Verify(f.public, []byte(RequestMessage(r.Method, f.server.URL, r.URL.Path, timestamp, nonce, raw)), signature) {
			f.t.Error("invalid signed request or repeated nonce")
			w.WriteHeader(400)
			return
		}
		f.nonces[nonce] = true
		if r.Method == "DELETE" && r.URL.Path == path {
			if len(raw) != 0 {
				f.t.Error("disconnect body must be empty")
			}
			f.deletes++
			w.WriteHeader(204)
			return
		}
		if r.Method != "POST" || r.URL.Path != path+"/heartbeat" {
			w.WriteHeader(405)
			return
		}
		if f.heartbeatCode != 0 {
			w.WriteHeader(f.heartbeatCode)
			respond(map[string]string{"error": f.heartbeatError, "message": "private arbitrary diagnostic"})
			return
		}
		var snapshot inventory.Snapshot
		if json.Unmarshal(raw, &snapshot) != nil || inventory.Validate(snapshot) != nil {
			f.t.Error("heartbeat did not contain valid native resource measurements")
			w.WriteHeader(400)
			return
		}
		if strings.Contains(string(raw), strings.Repeat("a", 64)) || strings.Contains(string(raw), "private_key") {
			f.t.Error("telemetry contains enrollment credential")
		}
		f.heartbeats++
		respond(map[string]bool{"received": true})
	}
}

func (f *hostedFixture) approve(notice EnrollmentNotice) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.proved || notice.NodeID != f.nodeID || notice.UserCode != "AB12-CD34" || !strings.HasPrefix(notice.VerificationURI, f.server.URL+"/dashboard/enroll?") {
		f.t.Error("approval notice preceded proof or contained an unexpected URL")
	}
	f.approved = true
}

func nodeHome(t *testing.T) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "node")
	if _, err := fabric.Init(home, "hosted-test"); err != nil {
		t.Fatal(err)
	}
	return home
}

func connect(t *testing.T, f *hostedFixture, home string) (*Client, *Binding) {
	t.Helper()
	client, err := New(home, f.server.URL+"/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	binding, err := client.Connect(context.Background(), f.approve)
	if err != nil {
		t.Fatal(err)
	}
	return client, binding
}

func TestApprovedEnrollmentSignedTelemetryAndRevocation(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	before, _ := os.ReadFile(filepath.Join(home, "state.json"))
	client, binding := connect(t, f, home)
	if binding.OrganizationID != "123" || binding.LastHeartbeatAt != nil {
		t.Fatal("approval must save organization but must not invent a heartbeat")
	}
	info, err := os.Stat(filepath.Join(home, "cloud.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("cloud binding is not private")
	}
	stored, _ := os.ReadFile(filepath.Join(home, "cloud.json"))
	if strings.Contains(string(stored), strings.Repeat("a", 64)) || strings.Contains(string(stored), "poll_token") {
		t.Fatal("poll capability persisted")
	}
	for i := 0; i < 2; i++ {
		if err = client.Heartbeat(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	current, _ := LoadBinding(home)
	if current.LastHeartbeatAt == nil || f.heartbeats != 2 {
		t.Fatal("real acknowledged telemetry was not recorded")
	}
	if err = client.Disconnect(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadBinding(home); !errors.Is(err, ErrNotRegistered) {
		t.Fatal("binding remained after disconnect")
	}
	if f.deletes != 1 {
		t.Fatal("hosted revocation was not requested")
	}
	after, _ := os.ReadFile(filepath.Join(home, "state.json"))
	if string(before) != string(after) {
		t.Fatal("hosted registration changed the private fabric state")
	}
}

func TestSubscriptionRequiredStopsRunWithoutInventingConnectivity(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	client, _ := connect(t, f, home)
	f.heartbeatCode, f.heartbeatError = 402, "subscription_required"
	var messages []string
	err := client.Run(context.Background(), false, func(s string) { messages = append(messages, s) })
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.Status != 402 || strings.Contains(err.Error(), "private arbitrary diagnostic") {
		t.Fatalf("expected safe subscription error, got %v", err)
	}
	binding, _ := LoadBinding(home)
	if binding.LastHeartbeatAt != nil || len(messages) != 0 {
		t.Fatal("unpaid node claimed successful telemetry")
	}
}

func TestRevocationIsRememberedAndPreventsFurtherTelemetry(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	client, _ := connect(t, f, home)
	f.heartbeatCode, f.heartbeatError = 403, "node_revoked"
	if err := client.Heartbeat(context.Background()); err == nil {
		t.Fatal("revoked node accepted")
	}
	binding, _ := LoadBinding(home)
	if !binding.Revoked || binding.LastHeartbeatAt != nil {
		t.Fatal("revocation not remembered")
	}
	f.heartbeatCode = 0
	if err := client.Heartbeat(context.Background()); err == nil || f.heartbeats != 0 {
		t.Fatal("revoked client resumed telemetry")
	}
	if err := client.Disconnect(context.Background(), false); err != nil {
		t.Fatal(err)
	}
}

func TestDeniedExpiredAndMismatchedApprovalDoNotPersistRegistration(t *testing.T) {
	for _, state := range []string{"denied", "expired", "wrong-node"} {
		t.Run(state, func(t *testing.T) {
			f := fixture(t)
			f.state = state
			if state == "wrong-node" {
				f.state, f.badApproval = "approved", true
			}
			home := nodeHome(t)
			client, _ := New(home, f.server.URL+"/dashboard")
			if _, err := client.Connect(context.Background(), f.approve); err == nil {
				t.Fatal("invalid approval accepted")
			}
			if _, err := LoadBinding(home); !errors.Is(err, ErrNotRegistered) {
				t.Fatal("unapproved binding persisted")
			}
		})
	}
}

func TestPendingEnrollmentCancellationDoesNotPersistRegistration(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	client, _ := New(home, f.server.URL+"/dashboard")
	ctx, cancel := context.WithCancel(context.Background())
	_, err := client.Connect(ctx, func(EnrollmentNotice) { cancel() })
	if err == nil {
		t.Fatal("canceled enrollment succeeded")
	}
	if _, err = LoadBinding(home); !errors.Is(err, ErrNotRegistered) {
		t.Fatal("pending registration persisted")
	}
}

func TestCrossOriginApprovalURLIsRejectedBeforeSigning(t *testing.T) {
	f := fixture(t)
	f.badVerify = true
	home := nodeHome(t)
	client, _ := New(home, f.server.URL+"/dashboard")
	if _, err := client.Connect(context.Background(), f.approve); err == nil {
		t.Fatal("cross-origin approval URL accepted")
	}
	if f.proofs != 0 {
		t.Fatal("key proof sent after foreign approval URL")
	}
}

func TestOriginAndBodyArePartOfTheSignedProtocol(t *testing.T) {
	home := nodeHome(t)
	state, public, err := fabric.CloudIdentity(home)
	if err != nil {
		t.Fatal(err)
	}
	first := EnrollmentMessage("https://nucleus.parallax.link", "a1234567-1234-4567-8123-123456789abc", state.NodeID, strings.Repeat("b", 64))
	sig, _ := fabric.SignCloud(home, []byte(first))
	if !ed25519.Verify(public, []byte(first), sig) || ed25519.Verify(public, []byte(strings.Replace(first, "nucleus.parallax.link", "other.example", 1)), sig) {
		t.Fatal("enrollment signature did not bind origin")
	}
	body := []byte(`{"cpu":1}`)
	message := RequestMessage("POST", "https://nucleus.parallax.link", "/dashboard/api/nodes/"+state.NodeID+"/heartbeat", "123", strings.Repeat("c", 32), body)
	sig, _ = fabric.SignCloud(home, []byte(message))
	changed := RequestMessage("POST", "https://nucleus.parallax.link", "/dashboard/api/nodes/"+state.NodeID+"/heartbeat", "123", strings.Repeat("c", 32), []byte(`{"cpu":2}`))
	if ed25519.Verify(public, []byte(changed), sig) {
		t.Fatal("request signature did not bind body hash")
	}
	if _, err = fabric.SignCloud(home, []byte("unrelated-domain\nmessage")); err == nil {
		t.Fatal("generic signing request accepted")
	}
}

func TestCloudURLRestrictionsAndNoRedirects(t *testing.T) {
	for _, value := range []string{
		"http://example.com/dashboard", "https://user:password@example.com/dashboard",
		"https://example.com/other", "https://example.com/dashboard?token=secret",
		"https://example.com/dashboard#fragment", "https://example.com:0/dashboard",
	} {
		if _, err := New(nodeHome(t), value); err == nil {
			t.Fatalf("unsafe service URL accepted: %s", value)
		}
	}
	var received bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/dashboard/api/enroll", http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client, _ := New(nodeHome(t), source.URL+"/dashboard")
	if _, err := client.Connect(context.Background(), nil); err == nil || received {
		t.Fatal("service redirect followed")
	}
}

func TestLocalDisconnectDoesNotCallServerAndPrivateStateCannotBeWorldReadableOrSymlinked(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	client, _ := connect(t, f, home)
	path := filepath.Join(home, "cloud.json")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBinding(home); err == nil {
		t.Fatal("world-readable binding accepted")
	}
	_ = os.Chmod(path, 0600)
	if err := client.Disconnect(context.Background(), true); err != nil || f.deletes != 0 {
		t.Fatal("local-only disconnect called hosted API")
	}
	other := filepath.Join(home, "other.json")
	if err := os.WriteFile(other, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadBinding(home); err == nil {
		t.Fatal("symlinked binding accepted")
	}
}

func TestExistingBindingCannotBeSilentlyReplaced(t *testing.T) {
	f := fixture(t)
	home := nodeHome(t)
	client, first := connect(t, f, home)
	if _, err := client.Connect(context.Background(), f.approve); err == nil {
		t.Fatal("existing organization binding replaced")
	}
	binding, _ := LoadBinding(home)
	if binding.OrganizationID != first.OrganizationID || f.proofs != 1 {
		t.Fatal("existing identity or organization changed")
	}
}

func TestServiceURLAndOrganizationIDValidation(t *testing.T) {
	client, _ := New(nodeHome(t), "https://NUCLEUS.PARALLAX.LINK:443/dashboard/")
	if client.base.origin != "https://nucleus.parallax.link" {
		t.Fatal("default TLS port or hostname not canonicalized")
	}
	if _, err := client.serviceURL("https://other.example/dashboard/enroll?code=AB12-CD34", "/dashboard/enroll", url.Values{"code": {"AB12-CD34"}}); err == nil {
		t.Fatal("foreign service URL accepted")
	}
	for _, raw := range []string{"null", `""`, "1.2", `"bad/id"`} {
		if _, err := decodeOrganizationID(json.RawMessage(raw)); err == nil {
			t.Fatalf("invalid organization ID accepted: %s", raw)
		}
	}
}

func TestUntrustedTLSServiceIsRejected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("untrusted TLS handler must not receive enrollment")
	}))
	defer server.Close()
	client, _ := New(nodeHome(t), server.URL+"/dashboard")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Connect(ctx, nil); err == nil {
		t.Fatal("untrusted service certificate accepted")
	}
}

func TestUserCodeAcceptsEightCharactersWithOptionalDisplaySeparator(t *testing.T) {
	for _, code := range []string{"AB12CD34", "AB12-CD34"} {
		if !userCode.MatchString(code) {
			t.Fatalf("valid user code rejected: %s", code)
		}
	}
	for _, code := range []string{"AB12--CD34", "ab12-cd34", "AB12-CD345", "AB12/CD34"} {
		if userCode.MatchString(code) {
			t.Fatalf("invalid user code accepted: %s", code)
		}
	}
}
