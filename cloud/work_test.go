package cloud

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
)

const workID = "a1234567-1234-4567-8123-123456789abc"

func workFixture(t *testing.T, handler func(http.ResponseWriter, *http.Request, []byte)) (*Client, *httptest.Server) {
	t.Helper()
	home := t.TempDir()
	_ = os.Chmod(home, 0700)
	if _, err := fabric.Init(home, "signed-worker"); err != nil {
		t.Fatal(err)
	}
	state, public, err := fabric.CloudIdentity(home)
	if err != nil {
		t.Fatal(err)
	}
	var server *httptest.Server
	var mu sync.Mutex
	nonces := map[string]bool{}
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		nonce := r.Header.Get("X-Nucleus-Nonce")
		timestamp := r.Header.Get("X-Nucleus-Timestamp")
		signature, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Nucleus-Signature"))
		valid := r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/dashboard/api/nodes/"+state.NodeID+"/work/") && len(nonce) == 32 && ed25519.Verify(ed25519.PublicKey(public), []byte(RequestMessage("POST", server.URL, r.URL.Path, timestamp, nonce, raw)), signature)
		mu.Lock()
		if nonces[nonce] {
			valid = false
		}
		nonces[nonce] = true
		mu.Unlock()
		if !valid {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid_signature"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		handler(w, r, raw)
	}))
	t.Cleanup(server.Close)
	client, err := New(home, server.URL+"/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	err = saveBinding(home, &Binding{SchemaVersion: 1, Origin: server.URL, BasePath: "/dashboard", NodeID: state.NodeID, OrganizationID: "7", HeartbeatIntervalSeconds: 60, RegisteredAt: time.Now()}, true)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}
func offeredWork() WorkLease {
	now := time.Now()
	return WorkLease{ID: workID, Type: "infer", LeaseID: "b1234567-1234-4567-8123-123456789abc", LeaseToken: strings.Repeat("a", 64), LeaseExpiresAtMS: now.Add(60 * time.Second).UnixMilli(), DeadlineAtMS: now.Add(120 * time.Second).UnixMilli(), Payload: json.RawMessage(`{"request":{"model":"approved"}}`)}
}
func workCaps() WorkCapabilities {
	return WorkCapabilities{JobTypes: []string{"infer"}, Models: []WorkModel{{ID: "approved", SHA256: strings.Repeat("b", 64), Revision: strings.Repeat("c", 40)}}, MaxConcurrentJobs: 1}
}
func TestSignedWorkLeaseRenewAndEvents(t *testing.T) {
	var calls atomic.Int32
	job := offeredWork()
	client, _ := workFixture(t, func(w http.ResponseWriter, r *http.Request, raw []byte) {
		calls.Add(1)
		if strings.HasSuffix(r.URL.Path, "/lease") {
			var body struct {
				Schema       int              `json:"schema_version"`
				Capabilities WorkCapabilities `json:"capabilities"`
			}
			if json.Unmarshal(raw, &body) != nil || body.Schema != 1 || body.Capabilities.MaxConcurrentJobs != 1 {
				t.Error("bad capabilities")
			}
			_ = json.NewEncoder(w).Encode(WorkPoll{Work: &job, RetryAfterSeconds: 5})
		} else if strings.HasSuffix(r.URL.Path, "/renew") {
			var body struct {
				LeaseID string `json:"lease_id"`
				Token   string `json:"lease_token"`
				Seq     int64  `json:"last_sequence"`
			}
			_ = json.Unmarshal(raw, &body)
			if body.LeaseID != job.LeaseID || body.Token != job.LeaseToken || body.Seq != 1 {
				t.Error("bad lease proof")
			}
			_ = json.NewEncoder(w).Encode(WorkRenewal{State: "leased", LeaseExpiresAtMS: time.Now().Add(60 * time.Second).UnixMilli()})
		} else {
			var body struct {
				Events []WorkEvent `json:"events"`
			}
			_ = json.Unmarshal(raw, &body)
			if len(body.Events) != 1 || body.Events[0].Sequence != 1 || body.Events[0].Type != "started" {
				t.Error("bad sequence")
			}
			_ = json.NewEncoder(w).Encode(WorkAcknowledgment{AcceptedSequence: 1, State: "leased"})
		}
	})
	poll, err := client.LeaseWork(context.Background(), workCaps())
	if err != nil || poll.Work == nil {
		t.Fatalf("lease: %v", err)
	}
	if _, err = client.RenewWork(context.Background(), *poll.Work, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = client.SendWorkEvents(context.Background(), *poll.Work, []WorkEvent{{Sequence: 1, Type: "started"}}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 3 {
		t.Fatal(calls.Load())
	}
	if _, err = client.request(context.Background(), "POST", "/dashboard/api/nodes/"+strings.Repeat("f", 64)+"/work/lease", []byte("{}"), true); err == nil {
		t.Fatal("signed another node path")
	}
}
func TestWorkResponseHasBoundAndStrictDeadline(t *testing.T) {
	var stateMu sync.Mutex
	job := offeredWork()
	job.Payload = json.RawMessage(`{"large":"` + strings.Repeat("x", 33000) + `"}`)
	client, _ := workFixture(t, func(w http.ResponseWriter, r *http.Request, raw []byte) {
		stateMu.Lock()
		defer stateMu.Unlock()
		_ = json.NewEncoder(w).Encode(WorkPoll{Work: &job, RetryAfterSeconds: 5})
	})
	if _, err := client.LeaseWork(context.Background(), workCaps()); err != nil {
		t.Fatal("bounded >16KiB lease rejected:", err)
	}
	stateMu.Lock()
	job.Payload = json.RawMessage(`{"large":"` + strings.Repeat("x", 65000) + `"}`)
	stateMu.Unlock()
	if _, err := client.LeaseWork(context.Background(), workCaps()); err == nil {
		t.Fatal("oversized lease accepted")
	}
	stateMu.Lock()
	job = offeredWork()
	job.DeadlineAtMS = time.Now().Add(time.Hour).UnixMilli()
	stateMu.Unlock()
	if _, err := client.LeaseWork(context.Background(), workCaps()); err == nil {
		t.Fatal("unbounded inference deadline accepted")
	}
}

type tamperTransport struct{ base http.RoundTripper }

func (t tamperTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Body = io.NopCloser(strings.NewReader(`{"tampered":true}`))
	r.ContentLength = int64(len(`{"tampered":true}`))
	return t.base.RoundTrip(r)
}
func TestWorkBodyTamperAndRedirectFailClosed(t *testing.T) {
	job := offeredWork()
	client, _ := workFixture(t, func(w http.ResponseWriter, r *http.Request, raw []byte) {
		_ = json.NewEncoder(w).Encode(WorkPoll{Work: &job, RetryAfterSeconds: 5})
	})
	client.http.Transport = tamperTransport{client.http.Transport}
	if _, err := client.LeaseWork(context.Background(), workCaps()); err == nil {
		t.Fatal("tampered signed body accepted")
	}
	var redirected atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer foreign.Close()
	redirectClient, _ := workFixture(t, func(w http.ResponseWriter, r *http.Request, raw []byte) { http.Redirect(w, r, foreign.URL, 307) })
	if _, err := redirectClient.LeaseWork(context.Background(), workCaps()); err == nil {
		t.Fatal("work redirect accepted")
	}
	if redirected.Load() != 0 {
		t.Fatal("signed work followed cross-origin redirect")
	}
}

func TestInferenceLeaseAcceptsAsync600ButRejectsBeyondBound(t *testing.T) {
	now := time.Now()
	job := offeredWork()
	job.DeadlineAtMS = now.Add(600 * time.Second).UnixMilli()
	if err := ValidateWorkLease(job, now); err != nil {
		t.Fatal(err)
	}
	job.DeadlineAtMS = now.Add(606 * time.Second).UnixMilli()
	if err := ValidateWorkLease(job, now); err == nil {
		t.Fatal("unbounded asynchronous inference accepted")
	}
}
