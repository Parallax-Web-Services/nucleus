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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/positronic"
)

func accountOwner(t *testing.T) (string, *fabric.State) {
	t.Helper()
	home := nodeHome(t)
	if _, err := fabric.Invite(home, "https://127.0.0.1:9461", time.Minute); err != nil {
		t.Fatal(err)
	}
	state, err := fabric.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	return home, state
}

func TestAccountConnectUsesRealCAProofAndReportsOnlyInventory(t *testing.T) {
	home, state := accountOwner(t)
	certificate, _ := x509.ParseCertificate(state.CACertificate)
	public := certificate.PublicKey.(ed25519.PublicKey)
	const id = "a1234567-1234-4567-8123-123456789abc"
	const clusterID = "b1234567-1234-4567-8123-123456789abc"
	code := id + "." + strings.Repeat("c", 64)
	var proved atomic.Bool
	var reported atomic.Bool
	var reject atomic.Bool
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 262145))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/cluster-enrollments/challenge":
			var body map[string]string
			if json.Unmarshal(raw, &body) != nil || body["code"] != code {
				t.Error("connection code changed")
			}
			status := "waiting"
			var connected *string
			if proved.Load() {
				status = "approved"
				value := clusterID
				connected = &value
			}
			_ = json.NewEncoder(w).Encode(accountChallenge{ID: id, TeamID: "7", Name: "My servers", Origin: server.URL, Status: status, ClusterID: connected, ExpiresAt: time.Now().Add(time.Minute)})
		case "/api/cluster-enrollments/claim":
			var body map[string]string
			_ = json.Unmarshal(raw, &body)
			proof, _ := base64.StdEncoding.DecodeString(body["signature"])
			ca, _ := base64.StdEncoding.DecodeString(body["ca_certificate"])
			digest := sha256.Sum256(ca)
			message := strings.Join([]string{"parallax-cluster-connect-v1", server.URL, id, "7", strings.Repeat("c", 64), state.FabricID, "My servers", ""}, "\n")
			if body["fabric_id"] != hex.EncodeToString(digest[:]) || !ed25519.Verify(public, []byte(message), proof) {
				t.Error("CA ownership proof is invalid")
				w.WriteHeader(403)
				return
			}
			proved.Store(true)
			_, _ = io.WriteString(w, `{"status":"awaiting_approval"}`)
		case "/api/clusters/" + clusterID + "/reports":
			digest := sha256.Sum256(raw)
			message := strings.Join([]string{"parallax-cluster-report-v1", server.URL, clusterID, r.Header.Get("X-Cluster-Timestamp"), r.Header.Get("X-Cluster-Nonce"), hex.EncodeToString(digest[:]), ""}, "\n")
			signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Cluster-Signature"))
			if !ed25519.Verify(public, []byte(message), signature) {
				t.Error("report signature is invalid")
				w.WriteHeader(403)
				return
			}
			if strings.Contains(string(raw), "must-not-export") {
				t.Error("report leaked private/irrelevant inventory")
			}
			reported.Store(true)
			if reject.Load() {
				w.WriteHeader(410)
				return
			}
			_, _ = io.WriteString(w, `{"status":"accepted"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	if err := ConnectAccount(context.Background(), home, server.URL, code, io.Discard); err != nil {
		t.Fatal(err)
	}
	binding, err := LoadAccountBinding(home)
	if err != nil || binding.ClusterID != clusterID || binding.FabricID != state.FabricID {
		t.Fatal("incorrect account binding", err)
	}
	info, _ := os.Stat(filepath.Join(home, "parallax-account.json"))
	if info.Mode().Perm() != 0600 {
		t.Fatal("binding is not private")
	}
	endpoint := "must-not-export"
	view := positronic.View{SchemaVersion: 1, FabricID: state.FabricID, LocalNodeID: state.NodeID, Nodes: []positronic.NodeView{{NodeID: state.NodeID, Name: "owner", Status: "awaiting", Endpoint: &endpoint}}}
	if err := ReportAccount(context.Background(), home, view); err != nil || !reported.Load() {
		t.Fatal("signed report failed", err)
	}
	reject.Store(true)
	if err := ReportAccount(context.Background(), home, view); err == nil {
		t.Fatal("server rejection ignored")
	}
	if err := ConnectAccount(context.Background(), home, server.URL, code, io.Discard); err == nil {
		t.Fatal("existing binding overwritten")
	}
	if err := DisconnectAccount(home); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountBinding(home); !errors.Is(err, ErrAccountNotConnected) {
		t.Fatal("local disconnect did not clear binding", err)
	}
	after, _ := fabric.Load(home)
	if after.FabricID != state.FabricID || after.NodeID != state.NodeID {
		t.Fatal("account connection changed fabric identity")
	}
}

func TestAccountBindingRejectsAnotherFabricSymlinksAndLoosePermissions(t *testing.T) {
	home, state := accountOwner(t)
	binding := &AccountBinding{Version: 1, Origin: "https://parallax.example", ClusterID: "a1234567-1234-4567-8123-123456789abc", FabricID: state.FabricID, TeamID: "7", Name: "servers"}
	if err := saveAccountBinding(home, binding); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "parallax-account.json")
	raw, _ := os.ReadFile(path)
	other, _ := accountOwner(t)
	if err := os.WriteFile(filepath.Join(other, "parallax-account.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountBinding(other); err == nil {
		t.Fatal("another fabric accepted this account binding")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountBinding(home); err == nil {
		t.Fatal("loose permissions accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	_ = os.WriteFile(target, raw, 0600)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAccountBinding(home); err == nil {
		t.Fatal("symlink binding accepted")
	}
}

func TestAccountOriginsAndRedirectsFailClosed(t *testing.T) {
	for _, raw := range []string{"http://remote.example", "https://user:pass@parallax.example", "https://parallax.example/path", "https://parallax.example?token=x", "https://parallax.example#fragment"} {
		if _, err := accountOrigin(raw); err == nil {
			t.Errorf("accepted unsafe origin %s", raw)
		}
	}
	for _, raw := range []string{"https://parallax.example", "http://127.0.0.1:8000"} {
		if _, err := accountOrigin(raw); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/not-followed", 302)
	}))
	defer server.Close()
	if err := accountPost(context.Background(), accountHTTP(), server.URL, map[string]string{}, nil); err == nil {
		t.Fatal("redirect was followed")
	}
}

func TestAccountConnectRejectsForeignChallengeAndCanceledApproval(t *testing.T) {
	home, _ := accountOwner(t)
	const id = "a1234567-1234-4567-8123-123456789abc"
	code := id + "." + strings.Repeat("c", 64)
	var foreign atomic.Bool
	foreign.Store(true)
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/cluster-enrollments/claim" {
			_, _ = io.WriteString(w, `{"status":"awaiting_approval"}`)
			return
		}
		origin := server.URL
		if foreign.Load() {
			origin = "https://wrong.example"
		}
		_ = json.NewEncoder(w).Encode(accountChallenge{ID: id, TeamID: "7", Name: "servers", Origin: origin, Status: "waiting", ExpiresAt: time.Now().Add(time.Minute)})
	}))
	defer server.Close()
	if err := ConnectAccount(context.Background(), home, server.URL, code, io.Discard); err == nil {
		t.Fatal("foreign challenge accepted")
	}
	foreign.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := ConnectAccount(ctx, home, server.URL, code, io.Discard); err == nil {
		t.Fatal("unapproved connection completed")
	}
	if _, err := LoadAccountBinding(home); !errors.Is(err, ErrAccountNotConnected) {
		t.Fatal("unapproved binding saved", err)
	}
}
