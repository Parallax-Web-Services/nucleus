package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func apiFixture(t *testing.T) (*Service, *httptest.Server) {
	t.Helper()
	cfg := FleetConfig{WorkerTTLSeconds: 3, RequestTimeoutSeconds: 3}
	s, err := NewScheduler("owner", cfg, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{Scheduler: s, APIKey: strings.Repeat("s", 32)}
	server := httptest.NewServer(svc.Handler())
	t.Cleanup(server.Close)
	return svc, server
}
func apiCall(t *testing.T, server *httptest.Server, key, method, path string, body any) *http.Response {
	t.Helper()
	var b io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		b = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, server.URL+path, b)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}
func TestAPIRequiresBearerAndLoopback(t *testing.T) {
	svc, server := apiFixture(t)
	for _, path := range []string{"/v1/inference/policy", "/v1/models", "/healthz", "/v1/inference/status", "/v1/generations", "/v1/reviews"} {
		resp := apiCall(t, server, "", "GET", path, nil)
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("%s unauthorized=%d", path, resp.StatusCode)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := StartAPI(ctx, "0.0.0.0:0", svc); err == nil {
		t.Fatal("wildcard accepted")
	}
	if _, err := StartAPI(ctx, "localhost:0", svc); err == nil {
		t.Fatal("DNS accepted")
	}
	if _, err := StartAPI(ctx, "127.0.0.1:0", svc); err != nil {
		t.Fatal(err)
	}
	resp := apiCall(t, server, svc.APIKey, "POST", "/v1/generations", nil)
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal(resp.StatusCode)
	}
}
func TestAPIRejectsUnsupportedPayloadAndNoSuitableNode(t *testing.T) {
	svc, server := apiFixture(t)
	for _, body := range []any{map[string]any{"model": "m", "messages": []Message{{Role: "user", Content: "hello"}}, "tools": []any{}}, Request{Model: "m", Messages: []Message{{Role: "tool", Content: "x"}}}} {
		resp := apiCall(t, server, svc.APIKey, "POST", "/v1/chat/completions", body)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal(resp.StatusCode)
		}
	}
	resp := apiCall(t, server, svc.APIKey, "POST", "/v1/chat/completions", Request{Model: "missing", Messages: []Message{{Role: "user", Content: "hello"}}})
	defer resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatal(resp.StatusCode)
	}
}
func TestWorkerRoutesCannotBeUsedViaClientAPI(t *testing.T) {
	svc, server := apiFixture(t)
	resp := apiCall(t, server, svc.APIKey, "POST", workerPrefix+"register", Advertisement{})
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal(resp.StatusCode)
	}
}
func TestJSONBodyBounds(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader(`{"x":"`+strings.Repeat("a", 1024)+`"}`))
	req.Header.Set("Content-Type", "application/json")
	var body map[string]string
	if readJSON(rec, req, &body, 32) {
		t.Fatal("oversize accepted")
	}
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
}
func TestRemoteControlRedirectDisabled(t *testing.T) {
	targetCalls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls++; w.WriteHeader(204) }))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer source.Close()
	control := &RemoteControl{endpoint: source.URL, client: &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if err := control.Register(context.Background(), Advertisement{}); err == nil {
		t.Fatal("redirect accepted")
	}
	if targetCalls != 0 {
		t.Fatal("request replayed")
	}
}

func TestAPIWriteBudgetAccommodatesEnabledMeldRuntime(t *testing.T) {
	for _, test := range []struct {
		name        string
		textSeconds int
		meld        *MeldConfig
		want        time.Duration
	}{
		{name: "text only", textSeconds: 300, want: 330 * time.Second},
		{name: "disabled bridge", textSeconds: 300, meld: &MeldConfig{}, want: 330 * time.Second},
		{name: "image outlasts text", textSeconds: 300, meld: &MeldConfig{GenerationURL: "http://127.0.0.1:8010", TimeoutSeconds: 900}, want: 930 * time.Second},
		{name: "review outlasts text", textSeconds: 300, meld: &MeldConfig{ReviewURL: "http://127.0.0.1:8011", ReviewModel: "qwen-test", TimeoutSeconds: 1200}, want: 1230 * time.Second},
		{name: "text outlasts image", textSeconds: 1800, meld: &MeldConfig{GenerationURL: "http://127.0.0.1:8010", TimeoutSeconds: 900}, want: 1830 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			scheduler, err := NewScheduler("owner", FleetConfig{RequestTimeoutSeconds: test.textSeconds}, func(string) bool { return true })
			if err != nil {
				t.Fatal(err)
			}
			service := &Service{Scheduler: scheduler}
			if test.meld != nil {
				adapter, err := NewMeldAdapter(*test.meld)
				if err != nil {
					t.Fatal(err)
				}
				service.Meld = adapter
			}
			if got := apiWriteTimeout(service); got != test.want {
				t.Fatalf("API write budget %s expires before expected workload budget %s", got, test.want)
			}
		})
	}
}
