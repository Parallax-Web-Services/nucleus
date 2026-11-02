package inference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"image"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Transport tests call only the private forwardProtocol method with fixtures. Public-route policy denial is tested separately. No test executes or benchmarks AI models.
func meldFixture(t *testing.T, path string) ([]byte, string, []byte) {
	t.Helper()
	var picture bytes.Buffer
	if err := png.Encode(&picture, image.NewRGBA(image.Rect(0, 0, 2, 3))); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, pair := range [][2]string{{"prompt", "protocol test"}, {"model", "sdxl-test"}, {"width", "2"}, {"height", "3"}, {"names", "one"}, {"names", "two"}, {"weights_basis_points", "5000"}, {"weights_basis_points", "5000"}} {
		if err := writer.WriteField(pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
	}
	name := "sources"
	if path == "/v1/reviews" {
		name = "candidate"
	}
	part, err := writer.CreateFormFile(name, "candidate.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(picture.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType(), picture.Bytes()
}

func meldResponseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("X-Image-Preview", "false")
	w.Header().Set("X-Image-AI", "true")
	w.Header().Set("X-Image-Backend", "sdxl_ip_adapter")
	w.Header().Set("X-Image-Model", "sdxl-test")
	w.Header().Set("X-Image-Seed", "4294967295")
	w.Header().Set("X-Image-Provenance", "sha256:"+strings.Repeat("a", 64))
	w.Header().Set("X-Request-ID", "fixture-request")
}

func meldCall(adapter *MeldAdapter, path string, body []byte, contentType string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", "Bearer owner-secret")
	request.Header.Set("Cookie", "session=private")
	request.Header.Set("Idempotency-Key", "do-not-forward")
	response := httptest.NewRecorder()
	adapter.forwardProtocol(response, request)
	return response
}

func TestMeldGenerationPreservesMultipartAndAttestation(t *testing.T) {
	body, contentType, picture := meldFixture(t, "/v1/generations")
	var calls atomic.Int32
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		got, _ := io.ReadAll(request.Body)
		if request.URL.Path != "/v1/generations" || !bytes.Equal(got, body) || request.Header.Get("Content-Type") != contentType {
			t.Error("multipart bytes or route changed")
		}
		if request.Header.Get("Authorization") != "Bearer runtime-secret" || request.Header.Get("Cookie") != "" || request.Header.Get("Idempotency-Key") != "" {
			t.Error("incorrect credentials or client headers forwarded")
		}
		meldResponseHeaders(w)
		w.Header().Set("Set-Cookie", "upstream=private")
		_, _ = w.Write(picture)
	}))
	defer runtime.Close()
	adapter, err := NewMeldAdapter(MeldConfig{GenerationURL: runtime.URL, GenerationToken: "runtime-secret"})
	if err != nil {
		t.Fatal(err)
	}
	result := meldCall(adapter, "/v1/generations", body, contentType)
	if result.Code != 200 || !bytes.Equal(result.Body.Bytes(), picture) || calls.Load() != 1 {
		t.Fatalf("generation: %d %s calls=%d", result.Code, result.Body.String(), calls.Load())
	}
	if result.Header().Get("X-Image-Model") != "sdxl-test" || result.Header().Get("X-Request-ID") != "fixture-request" || result.Header().Get("Set-Cookie") != "" {
		t.Fatal("attestation lost or upstream cookie forwarded")
	}
}

func TestMeldImageRejectsPreviewAndIncompatibleProof(t *testing.T) {
	_, _, picture := meldFixture(t, "/v1/generations")
	for _, change := range []struct{ name, header, value string }{
		{"preview", "X-Image-Preview", "true"}, {"AI missing", "X-Image-AI", ""}, {"backend", "X-Image-Backend", "gguf"},
		{"model", "X-Image-Model", "another"}, {"seed", "X-Image-Seed", "4294967296"}, {"provenance", "X-Image-Provenance", "missing"},
	} {
		t.Run(change.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			meldResponseHeaders(recorder)
			recorder.Header().Set(change.header, change.value)
			if err := validateMeldImage(recorder.Header(), picture, meldRequest{model: "sdxl-test", width: 2, height: 3}); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
	recorder := httptest.NewRecorder()
	meldResponseHeaders(recorder)
	if validateMeldImage(recorder.Header(), picture, meldRequest{model: "sdxl-test", width: 3, height: 2}) == nil {
		t.Fatal("wrong dimensions accepted")
	}
}

func TestMeldReviewBindsVerdictToCandidateAndModel(t *testing.T) {
	body, contentType, picture := meldFixture(t, "/v1/reviews")
	digest := sha256.Sum256(picture)
	candidateHash := hex.EncodeToString(digest[:])
	verdict := `{"accepted":false,"issues":["malformed_anatomy"],"summary":"Fixture verdict","quality_score":30}`
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Reviewer-Backend", "qwen_vllm")
		w.Header().Set("X-Reviewer-Model", "qwen-test")
		w.Header().Set("X-Candidate-SHA256", candidateHash)
		_, _ = io.WriteString(w, verdict)
	}))
	defer runtime.Close()
	adapter, err := NewMeldAdapter(MeldConfig{ReviewURL: runtime.URL, ReviewModel: "qwen-test"})
	if err != nil {
		t.Fatal(err)
	}
	result := meldCall(adapter, "/v1/reviews", body, contentType)
	if result.Code != 200 || result.Body.String() != verdict {
		t.Fatalf("review: %d %s", result.Code, result.Body.String())
	}
	for _, bad := range []string{
		`{"accepted":true,"issues":["malformed_anatomy"],"summary":"bad","quality_score":30}`,
		`{"accepted":false,"issues":[],"summary":"bad","quality_score":30}`,
		`{"accepted":false,"issues":["unknown"],"summary":"bad","quality_score":30}`,
		`{"accepted":false,"issues":["malformed_anatomy","malformed_anatomy"],"summary":"bad","quality_score":30}`,
		`{"accepted":true,"issues":[],"summary":"bad","quality_score":101}`,
		`{"accepted":true,"issues":[],"summary":"bad","quality_score":1.5}`,
	} {
		if validateMeldReview(result.Header(), []byte(bad), candidateHash, "qwen-test") == nil {
			t.Fatalf("invalid verdict accepted: %s", bad)
		}
	}
	if validateMeldReview(result.Header(), []byte(verdict), strings.Repeat("0", 64), "qwen-test") == nil {
		t.Fatal("wrong candidate hash accepted")
	}
	if validateMeldReview(result.Header(), []byte(verdict), candidateHash, "another") == nil {
		t.Fatal("wrong reviewer model accepted")
	}
}

func TestMeldLimitsAndUnavailableWorkloads(t *testing.T) {
	body, contentType, _ := meldFixture(t, "/v1/generations")
	empty, err := NewMeldAdapter(MeldConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got := meldCall(empty, "/v1/generations", body, contentType); got.Code != 503 || !strings.Contains(got.Body.String(), "GGUF") {
		t.Fatalf("missing runtime: %d %s", got.Code, got.Body.String())
	}
	var calls atomic.Int32
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "too large")
	}))
	defer runtime.Close()
	adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: runtime.URL, MaxRequestBytes: 2})
	if got := meldCall(adapter, "/v1/generations", body, contentType); got.Code != 413 || calls.Load() != 0 {
		t.Fatal("oversized request dispatched")
	}
	adapter, _ = NewMeldAdapter(MeldConfig{GenerationURL: runtime.URL, MaxResponseBytes: 2})
	if got := meldCall(adapter, "/v1/generations", body, contentType); got.Code != 502 || calls.Load() != 1 {
		t.Fatal("response limit not enforced")
	}
}

func TestMeldNeverFollowsRedirectOrRetriesPost(t *testing.T) {
	body, contentType, _ := meldFixture(t, "/v1/generations")
	var calls atomic.Int32
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/continued")
		w.WriteHeader(303)
	}))
	defer runtime.Close()
	adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: runtime.URL})
	if got := meldCall(adapter, "/v1/generations", body, contentType); got.Code != 502 || calls.Load() != 1 {
		t.Fatalf("redirect replayed: %d calls=%d", got.Code, calls.Load())
	}
}

func TestMeldConcurrencyAndCancellation(t *testing.T) {
	body, contentType, _ := meldFixture(t, "/v1/generations")
	started := make(chan struct{})
	canceled := make(chan struct{})
	runtime := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		close(started)
		<-request.Context().Done()
		close(canceled)
	}))
	defer runtime.Close()
	adapter, _ := NewMeldAdapter(MeldConfig{GenerationURL: runtime.URL, MaxConcurrent: 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "/v1/generations", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Content-Type", contentType)
	finished := make(chan struct{})
	go func() { adapter.forwardProtocol(httptest.NewRecorder(), request); close(finished) }()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime never started")
	}
	if got := meldCall(adapter, "/v1/generations", body, contentType); got.Code != 429 {
		t.Fatalf("concurrency limit: %d", got.Code)
	}
	cancel()
	select {
	case <-canceled:
	case <-time.After(3 * time.Second):
		t.Fatal("runtime request not canceled")
	}
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("adapter did not stop")
	}
}

func TestMeldRejectsArbitraryUpstreamsAndInvalidConfig(t *testing.T) {
	for _, endpoint := range []string{"https://example.com:443", "http://192.168.1.2:8010", "http://localhost:8010", "http://127.0.0.1:8010/path", "http://user:pass@127.0.0.1:8010", "http://127.0.0.1:8010?token=secret", "http://0.0.0.0:8010", "http://127.0.0.1:0", "http://127.0.0.1:8010#fragment"} {
		if _, err := NewMeldAdapter(MeldConfig{GenerationURL: endpoint}); err == nil {
			t.Fatalf("unsafe runtime URL accepted: %s", endpoint)
		}
	}
	for _, config := range []MeldConfig{{MaxConcurrent: -1}, {MaxRequestBytes: 129 << 20}, {TimeoutSeconds: 1801}, {ReviewURL: "http://127.0.0.1:8011"}, {GenerationToken: "secret\ninjection"}} {
		if _, err := NewMeldAdapter(config); err == nil {
			t.Fatalf("invalid config accepted: %#v", config)
		}
	}
}

type meldUnreadPolicyBody struct{ reads int }

func (body *meldUnreadPolicyBody) Read([]byte) (int, error) { body.reads++; return 0, io.EOF }
func (body *meldUnreadPolicyBody) Close() error             { return nil }

func TestMeldPublicRoutesRejectUnverifiedModelsBeforeReadingOrDispatch(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) { calls.Add(1); w.WriteHeader(200) }))
	defer upstream.Close()
	for _, alias := range []string{"Qwen/Qwen3-VL-32B-Instruct-FP8", "approved-looking-local-review"} {
		adapter, err := NewMeldAdapter(MeldConfig{GenerationURL: upstream.URL, ReviewURL: upstream.URL, ReviewModel: alias})
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/v1/generations", "/v1/reviews"} {
			body := new(meldUnreadPolicyBody)
			request := httptest.NewRequest(http.MethodPost, path, body)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Model-Origin", "US")
			request.Header.Set("X-Model-Provenance", "approved")
			response := httptest.NewRecorder()
			adapter.ServeHTTP(response, request)
			if response.Code != 403 || !strings.Contains(response.Body.String(), "model_policy_rejected") {
				t.Fatalf("%s policy response: %d %s", path, response.Code, response.Body.String())
			}
			if body.reads != 0 || calls.Load() != 0 {
				t.Fatalf("unapproved request read body %d times or dispatched %d times", body.reads, calls.Load())
			}
			forged := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"model":"friendly-alias","provenance":{"origin_country":"US","approved":true},"allow_unverified_models":true}`))
			forged.Header.Set("Content-Type", "application/json")
			response = httptest.NewRecorder()
			adapter.ServeHTTP(response, forged)
			if response.Code != 403 || calls.Load() != 0 {
				t.Fatal("caller metadata or alias bypassed public model policy")
			}
		}
	}
}

func TestMeldPublicUnconfiguredRoutesFailWithoutReadingPayload(t *testing.T) {
	adapter, err := NewMeldAdapter(MeldConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/generations", "/v1/reviews"} {
		body := new(meldUnreadPolicyBody)
		request := httptest.NewRequest(http.MethodPost, path, body)
		response := httptest.NewRecorder()
		adapter.ServeHTTP(response, request)
		if response.Code != 503 || !strings.Contains(response.Body.String(), "workload_unavailable") || body.reads != 0 {
			t.Fatalf("%s unavailable response: %d reads=%d", path, response.Code, body.reads)
		}
	}
}
