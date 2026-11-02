package inference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// These manifests describe fictional tensor-free protocol fixtures. They are
// never approvals for real pretrained weights or evidence of model performance.
func meldManifestFixture(workload, backend, alias string) (MeldRuntimeManifest, []ModelApproval) {
	component := schedulerModel()
	component.ID = "media-protocol-component"
	component.Source = "https://example.org/nucleus/model-fixture"
	component.Format = "safetensors"
	component.Runtime = "fixture-media-runtime"
	component.Workloads = []string{workload}
	manifest := MeldRuntimeManifest{SchemaVersion: 1, RuntimeVersion: "media-protocol-fixture-1", Backend: backend, Workload: workload, Model: alias, ArtifactSetComplete: true, Artifacts: []MeldRuntimeArtifact{{Path: "component/weights.safetensors", Model: component}}}
	return manifest, testModelApprovals(component)
}

func TestApprovedMeldRoutesBindManifestNonceAndExactResult(t *testing.T) {
	for _, test := range []struct{ path, workload, backend, alias string }{
		{"/v1/generations", meldGenerationWorkload, "sdxl_img2img", "sdxl-test"},
		{"/v1/reviews", meldReviewWorkload, "transformers_vlm", "review-test"},
	} {
		t.Run(test.workload, func(t *testing.T) {
			manifest, approvals := meldManifestFixture(test.workload, test.backend, test.alias)
			raw, _ := json.Marshal(manifest)
			pin := ManifestDigest(raw)
			body, contentType, picture := meldFixture(t, test.path)
			nonce := strings.Repeat("c", 64)
			var probes, posts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer runtime-secret" || r.Header.Get("Cookie") != "" || r.Header.Get("Idempotency-Key") != "" {
					t.Error("incorrect credentials or client headers forwarded")
				}
				if r.URL.Path == "/v1/runtime-manifest" {
					probes.Add(1)
					if r.Method != "GET" {
						t.Error("manifest inspection is not GET")
					}
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(MeldManifestHeader, pin)
					_, _ = w.Write(raw)
					return
				}
				posts.Add(1)
				got, _ := io.ReadAll(r.Body)
				if r.URL.Path != test.path || r.Method != "POST" || !bytes.Equal(got, body) {
					t.Error("approved request changed route or multipart bytes")
				}
				if r.Header.Get(MeldManifestHeader) != pin || r.Header.Get(MeldNonceHeader) != nonce {
					t.Error("runtime request omitted binding headers")
				}
				var result []byte
				if test.path == "/v1/generations" {
					meldResponseHeaders(w)
					w.Header().Set("X-Image-Backend", test.backend)
					result = picture
				} else {
					digest := sha256.Sum256(picture)
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-Reviewer-Backend", test.backend)
					w.Header().Set("X-Reviewer-Model", test.alias)
					w.Header().Set("X-Candidate-SHA256", hex.EncodeToString(digest[:]))
					result = []byte(`{"accepted":true,"issues":[],"summary":"Protocol fixture only","quality_score":90}`)
				}
				w.Header().Set(MeldManifestHeader, pin)
				w.Header().Set(MeldNonceHeader, nonce)
				w.Header().Set(MeldResultHeader, ManifestDigest(result))
				_, _ = w.Write(result)
			}))
			defer upstream.Close()
			cfg := MeldConfig{ApprovedModels: approvals}
			if test.path == "/v1/generations" {
				cfg.GenerationURL = upstream.URL
				cfg.GenerationToken = "runtime-secret"
				cfg.GenerationManifestSHA256 = pin
			} else {
				cfg.ReviewURL = upstream.URL
				cfg.ReviewToken = "runtime-secret"
				cfg.ReviewModel = test.alias
				cfg.ReviewManifestSHA256 = pin
			}
			adapter, err := NewMeldAdapter(cfg)
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("POST", test.path, bytes.NewReader(body))
			request.Header.Set("Content-Type", contentType)
			request.Header.Set("Authorization", "Bearer client-secret")
			request.Header.Set("Cookie", "private-client-session")
			request.Header.Set(MeldManifestHeader, pin)
			request.Header.Set(MeldNonceHeader, nonce)
			response := httptest.NewRecorder()
			adapter.ServeHTTP(response, request)
			if response.Code != 200 || probes.Load() != 1 || posts.Load() != 1 {
				t.Fatalf("approved call: %d %s probes=%d posts=%d", response.Code, response.Body.String(), probes.Load(), posts.Load())
			}
			if response.Header().Get(MeldManifestHeader) != pin || response.Header().Get(MeldNonceHeader) != nonce || response.Header().Get(MeldResultHeader) != ManifestDigest(response.Body.Bytes()) {
				t.Fatal("client response lost exact result binding")
			}
		})
	}
}

func TestMeldManifestAdmissionRejectsPolicyAndIdentityBeforePayload(t *testing.T) {
	for _, test := range []struct {
		name                                            string
		mutate                                          func(*MeldRuntimeManifest)
		noApproval, wrongPin, wrongHeader, unknownField bool
	}{
		{name: "missing owner approval", noApproval: true},
		{name: "unknown provenance", mutate: func(m *MeldRuntimeManifest) { m.Artifacts[0].Model.Provenance = nil }},
		{name: "blocked publisher", mutate: func(m *MeldRuntimeManifest) { m.Artifacts[0].Model.Provenance.Country = "CN" }},
		{name: "blocked renamed artifact", mutate: func(m *MeldRuntimeManifest) { m.Artifacts[0].Model.SHA256 = blockedQwenSHA256 }},
		{name: "unapproved artifact", mutate: func(m *MeldRuntimeManifest) { m.Artifacts[0].Model.SHA256 = strings.Repeat("b", 64) }},
		{name: "incomplete set", mutate: func(m *MeldRuntimeManifest) { m.ArtifactSetComplete = false }},
		{name: "wrong purpose", mutate: func(m *MeldRuntimeManifest) { m.Workload = meldReviewWorkload }},
		{name: "traversal", mutate: func(m *MeldRuntimeManifest) { m.Artifacts[0].Path = "../weights.safetensors" }},
		{name: "duplicate file", mutate: func(m *MeldRuntimeManifest) { m.Artifacts = append(m.Artifacts, m.Artifacts[0]) }},
		{name: "runtime swap", wrongPin: true}, {name: "header differs from bytes", wrongHeader: true}, {name: "unknown manifest field", unknownField: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest, approvals := meldManifestFixture(meldGenerationWorkload, "sdxl_img2img", "sdxl-test")
			if test.mutate != nil {
				test.mutate(&manifest)
			}
			raw, _ := json.Marshal(manifest)
			if test.unknownField {
				raw = append(raw[:len(raw)-1], []byte(`,"allow_unknown_origin":true}`)...)
			}
			pin := ManifestDigest(raw)
			header := pin
			if test.wrongHeader {
				header = strings.Repeat("b", 64)
			}
			var probes, posts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
					t.Error("unapproved inference dispatched")
					return
				}
				probes.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set(MeldManifestHeader, header)
				_, _ = w.Write(raw)
			}))
			defer upstream.Close()
			if test.wrongPin {
				pin = strings.Repeat("d", 64)
			}
			if test.noApproval {
				approvals = nil
			}
			adapter, err := NewMeldAdapter(MeldConfig{GenerationURL: upstream.URL, GenerationManifestSHA256: pin, ApprovedModels: approvals})
			if err != nil {
				t.Fatal(err)
			}
			body := new(meldUnreadPolicyBody)
			request := httptest.NewRequest("POST", "/v1/generations", body)
			response := httptest.NewRecorder()
			adapter.ServeHTTP(response, request)
			if response.Code != 403 || body.reads != 0 || posts.Load() != 0 {
				t.Fatalf("admission: %d reads=%d posts=%d %s", response.Code, body.reads, posts.Load(), response.Body.String())
			}
			if test.noApproval && probes.Load() != 0 {
				t.Fatal("runtime without any owner approvals was contacted")
			}
		})
	}
}

func TestMeldApprovedResponseRejectsMissingOrReplayedProof(t *testing.T) {
	for _, header := range []string{MeldManifestHeader, MeldNonceHeader, MeldResultHeader} {
		t.Run(header, func(t *testing.T) {
			manifest, approvals := meldManifestFixture(meldGenerationWorkload, "sdxl_img2img", "sdxl-test")
			raw, _ := json.Marshal(manifest)
			pin := ManifestDigest(raw)
			body, contentType, picture := meldFixture(t, "/v1/generations")
			var posts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/runtime-manifest" {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set(MeldManifestHeader, pin)
					_, _ = w.Write(raw)
					return
				}
				posts.Add(1)
				meldResponseHeaders(w)
				w.Header().Set("X-Image-Backend", "sdxl_img2img")
				w.Header().Set(MeldManifestHeader, pin)
				w.Header().Set(MeldNonceHeader, r.Header.Get(MeldNonceHeader))
				w.Header().Set(MeldResultHeader, ManifestDigest(picture))
				w.Header().Set(header, strings.Repeat("0", 64))
				_, _ = w.Write(picture)
			}))
			defer upstream.Close()
			adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: upstream.URL, GenerationManifestSHA256: pin, ApprovedModels: approvals})
			request := httptest.NewRequest("POST", "/v1/generations", bytes.NewReader(body))
			request.Header.Set("Content-Type", contentType)
			request.Header.Set(MeldNonceHeader, strings.Repeat("e", 64))
			response := httptest.NewRecorder()
			adapter.ServeHTTP(response, request)
			if response.Code != 502 || posts.Load() != 1 || bytes.Equal(response.Body.Bytes(), picture) {
				t.Fatalf("bad response binding accepted or replayed: %d calls=%d", response.Code, posts.Load())
			}
		})
	}
}

func TestMeldManifestCannotRedirectAndClientPinCannotOverrideOwner(t *testing.T) {
	manifest, approvals := meldManifestFixture(meldGenerationWorkload, "sdxl_img2img", "sdxl-test")
	raw, _ := json.Marshal(manifest)
	pin := ManifestDigest(raw)
	var targetCalls, sourceCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sourceCalls.Add(1); http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: source.URL, GenerationManifestSHA256: pin, ApprovedModels: approvals})
	for _, clientPin := range []string{"", strings.Repeat("f", 64)} {
		body := new(meldUnreadPolicyBody)
		request := httptest.NewRequest("POST", "/v1/generations", body)
		request.Header.Set(MeldManifestHeader, clientPin)
		response := httptest.NewRecorder()
		adapter.ServeHTTP(response, request)
		expected := 503
		if clientPin != "" {
			expected = 403
		}
		if response.Code != expected || targetCalls.Load() != 0 || body.reads != 0 {
			t.Fatalf("manifest redirect/client override: %d target=%d reads=%d", response.Code, targetCalls.Load(), body.reads)
		}
	}
	if sourceCalls.Load() != 1 {
		t.Fatal("client override contacted runtime")
	}
}

func TestApprovedMeldCancellationReachesRuntime(t *testing.T) {
	manifest, approvals := meldManifestFixture(meldGenerationWorkload, "sdxl_img2img", "sdxl-test")
	raw, _ := json.Marshal(manifest)
	pin := ManifestDigest(raw)
	body, contentType, _ := meldFixture(t, "/v1/generations")
	started, canceled := make(chan struct{}), make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/runtime-manifest" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(MeldManifestHeader, pin)
			_, _ = w.Write(raw)
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
		close(canceled)
	}))
	defer upstream.Close()
	adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: upstream.URL, GenerationManifestSHA256: pin, ApprovedModels: approvals})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest("POST", "/v1/generations", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", contentType)
	done := make(chan struct{})
	go func() { adapter.ServeHTTP(httptest.NewRecorder(), request); close(done) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("approved runtime never started")
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime did not observe cancellation")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway did not stop")
	}
}

func TestMeldApprovalsComeFromAuthoritativeFleetConfig(t *testing.T) {
	manifest, approvals := meldManifestFixture(meldGenerationWorkload, "sdxl_img2img", "sdxl-test")
	cfg := FleetConfig{ApprovedModels: approvals, Meld: &MeldConfig{GenerationURL: "http://127.0.0.1:8010"}}
	if err := cfg.defaults(); err != nil {
		t.Fatal(err)
	}
	if err := ApproveModel(manifest.Artifacts[0].Model, cfg.Meld.ApprovedModels); err != nil {
		t.Fatal("fleet approval not propagated", err)
	}
	cfg.ApprovedModels[0].Provenance.Country = "CN"
	if cfg.Meld.ApprovedModels[0].Provenance.Country != "US" {
		t.Fatal("gateway approvals share mutable owner metadata")
	}
}

func TestMeldManifestPublisherDisclosureNeedsPerArtifactOwnerApproval(t *testing.T) {
	manifest, _ := meldManifestFixture(meldReviewWorkload, "llama_cpp_vlm", "review-test")
	m, approval := publisherDisclosedFixture()
	m.Workloads = []string{meldReviewWorkload}
	m.ID = "publisher-disclosed-media-fixture"
	m.Revision = "fixture-release-1"
	m.License = "fixture-only"
	m.Format = "GGUF"
	m.Runtime = "llama.cpp"
	m.SizeBytes = 128
	manifest.Artifacts[0].Model = m
	if err := ValidateMeldManifest(manifest, meldReviewWorkload, []ModelApproval{approval}); err != nil {
		t.Fatal(err)
	}
	approval.AllowPublisherDisclosedLineage = false
	if err := ValidateMeldManifest(manifest, meldReviewWorkload, []ModelApproval{approval}); err == nil {
		t.Fatal("runtime manifest self-approved incomplete lineage")
	}
	approval.AllowPublisherDisclosedLineage = true
	second := manifest.Artifacts[0]
	second.Path = "second/mmproj.gguf"
	second.Model = cloneProvenanceFixture(t, m)
	second.Model.SHA256 = strings.Repeat("b", 64)
	manifest.Artifacts = append(manifest.Artifacts, second)
	if err := ValidateMeldManifest(manifest, meldReviewWorkload, []ModelApproval{approval}); err == nil {
		t.Fatal("one artifact disclosure exception approved a second artifact hash")
	}
}
