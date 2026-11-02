package nebula

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/fabric"
)

func TestHostedAuthorityUsesExistingOriginBoundSignatureAndDoesNotFollowRedirects(t *testing.T) {
	owner, _ := relayTestPair(t)
	state, public, err := fabric.CloudIdentity(owner)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var redirect atomic.Bool
	var failure atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		proof, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Nucleus-Signature"))
		origin := "http://" + r.Host
		path := "/dashboard/api/nodes/" + state.NodeID + "/nebula/authorize"
		if err != nil || r.Method != "POST" || r.URL.Path != path || !ed25519.Verify(public, []byte(cloud.RequestMessage("POST", origin, path, r.Header.Get("X-Nucleus-Timestamp"), r.Header.Get("X-Nucleus-Nonce"), body)), proof) {
			failure.Store(true)
			http.Error(w, "invalid signature", 401)
			return
		}
		var request CapabilityRequest
		if json.Unmarshal(body, &request) != nil || request.FabricID != state.FabricID || request.Service != "nucleus-fabric" {
			failure.Store(true)
			http.Error(w, "invalid body", 422)
			return
		}
		if redirect.Load() {
			w.Header().Set("Location", "https://example.invalid/never-follow")
			w.WriteHeader(302)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Authorization{SchemaVersion: 1, Capability: "opaque-authority-response", ExpiresAt: time.Now().Unix() + 30, RelayURL: DefaultRelayURL})
	}))
	defer server.Close()
	binding := cloud.Binding{SchemaVersion: 1, Origin: server.URL, BasePath: "/dashboard", NodeID: state.NodeID, OrganizationID: "42", HeartbeatIntervalSeconds: 60, RegisteredAt: time.Now()}
	writeBinding := func() {
		data, _ := json.Marshal(binding)
		if err := os.WriteFile(filepath.Join(owner, "cloud.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeBinding()
	source, err := HostedCapabilitySource(owner)
	if err != nil {
		t.Fatal(err)
	}
	input := CapabilityRequest{FabricID: state.FabricID, Service: "nucleus-fabric", Mode: "listen", ConnectionID: strings.Repeat("c", 64)}
	response, err := source(context.Background(), input)
	if err != nil || response.RelayURL != DefaultRelayURL || failure.Load() {
		t.Fatal("signed hosted authorization failed")
	}
	redirect.Store(true)
	if _, err = source(context.Background(), input); err == nil {
		t.Fatal("redirect authority response accepted")
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected authority request replay")
	}
	binding.Revoked = true
	writeBinding()
	if _, err = source(context.Background(), input); err == nil || calls.Load() != 2 {
		t.Fatal("revoked local registration reached authority")
	}
}
