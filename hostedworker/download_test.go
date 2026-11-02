package hostedworker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/inference"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func syntheticModel() (inference.Model, []byte) {
	data := append([]byte("GGUF"), bytes.Repeat([]byte{7}, 60)...)
	return inference.Model{ID: "approved-example", Revision: strings.Repeat("a", 40), Source: "https://huggingface.co/example/approved", License: "test-only", Architecture: "llama", Format: "GGUF", Quantization: "Q4_0", SHA256: sum(data), SizeBytes: uint64(len(data)), RequiredMemoryBytes: 256 << 20, Workloads: []string{"text-generation"}, Runtime: "llama.cpp", Provenance: &inference.ModelProvenance{Publisher: "Example reviewer", Country: "US", Evidence: []string{"https://example.com/review"}, LineageComplete: true, BaseModels: []inference.ModelOrigin{}}}, data
}
func artifactURL(model inference.Model) string {
	return model.Source + "/resolve/" + model.Revision + "/model.gguf"
}
func mockedDownload(data []byte, calls *int) *downloader {
	return &downloader{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		*calls++
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			panic("download leaked credentials")
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(data)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
	})}}
}
func TestModelDownloadHashFailureCleansTemporaryAndFinalFiles(t *testing.T) {
	model, data := syntheticModel()
	bad := append([]byte(nil), data...)
	bad[20] ^= 1
	root := filepath.Join(t.TempDir(), "models")
	calls := 0
	if _, _, err := mockedDownload(bad, &calls).fetch(context.Background(), root, model, artifactURL(model), 1<<30); err == nil {
		t.Fatal("tampered bytes installed")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 || calls != 1 {
		t.Fatal("failed download left artifacts", len(entries), calls)
	}
}
func TestImmutableURLAndRedirectPolicyFailClosed(t *testing.T) {
	model, data := syntheticModel()
	root := filepath.Join(t.TempDir(), "models")
	calls := 0
	download := mockedDownload(data, &calls)
	for _, address := range []string{model.Source + "/resolve/main/model.gguf", "http://huggingface.co/example/approved/resolve/" + model.Revision + "/model.gguf", "https://evil.example/model.gguf", artifactURL(model) + "?token=secret"} {
		if _, _, err := download.fetch(context.Background(), root, model, address, 1<<30); err == nil {
			t.Fatal("mutable/untrusted URL accepted", address)
		}
	}
	if calls != 0 {
		t.Fatal("rejected URL reached network")
	}
	client := newDownloader().client
	for _, address := range []string{"https://evil.example/model", "http://huggingface.co/model", "https://user:password@huggingface.co/model", "https://127.0.0.1/model"} {
		parsed, _ := url.Parse(address)
		if client.CheckRedirect(&http.Request{URL: parsed, Header: make(http.Header)}, []*http.Request{{}}) == nil {
			t.Fatal("untrusted redirect accepted")
		}
	}
	parsed, _ := url.Parse("https://cas-bridge.xethub.hf.co/signed-path?signature=opaque")
	request := &http.Request{URL: parsed, Header: make(http.Header)}
	request.Header.Set("Authorization", "must-not-forward")
	request.Header.Set("Cookie", "must-not-forward")
	if err := client.CheckRedirect(request, []*http.Request{{}}); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("Authorization") != "" || request.Header.Get("Cookie") != "" {
		t.Fatal("redirect kept credentials")
	}
}

type cancellingReader struct {
	data   []byte
	cancel context.CancelFunc
}

func (r *cancellingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data[:8])
	r.data = r.data[n:]
	r.cancel()
	return n, nil
}
func TestCancelledAndSymlinkModelDownloadsLeaveNoPartialFiles(t *testing.T) {
	model, data := syntheticModel()
	root := filepath.Join(t.TempDir(), "models")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	download := &downloader{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, ContentLength: int64(len(data)), Header: make(http.Header), Body: io.NopCloser(&cancellingReader{data: data, cancel: cancel}), Request: r}, nil
	})}}
	if _, _, err := download.fetch(ctx, root, model, artifactURL(model), 1<<30); err == nil {
		t.Fatal("cancelled download installed")
	}
	entries, _ := os.ReadDir(root)
	if len(entries) != 0 {
		t.Fatal("cancelled download left files")
	}
	target := filepath.Join(t.TempDir(), "foreign")
	_ = os.WriteFile(target, data, 0600)
	_ = os.Symlink(target, filepath.Join(root, model.SHA256+".gguf"))
	calls := 0
	if _, _, err := mockedDownload(data, &calls).fetch(context.Background(), root, model, artifactURL(model), 1<<30); err == nil {
		t.Fatal("model symlink accepted")
	}
	if calls != 0 {
		t.Fatal("symlink case reached network")
	}
}

type modelBackend struct {
	models []inference.Model
	closed bool
}

func (b *modelBackend) Models() []inference.Model { return b.models }
func (b *modelBackend) Run(context.Context, inference.Request, func(inference.Event) error) error {
	return nil
}
func (b *modelBackend) Close() error { b.closed = true; return nil }
func managerFixture(t *testing.T) (*Manager, inference.Model, []byte) {
	t.Helper()
	model, data := syntheticModel()
	home := t.TempDir()
	path := filepath.Join(home, "fleet.json")
	cfg := inference.FleetConfig{ApprovedModels: []inference.ModelApproval{{SHA256: model.SHA256, Provenance: *model.Provenance}}, Runtime: &inference.RuntimeConfig{Binary: "/bin/true", Threads: 1, ContextLength: 128, MaxTokens: 32, MemoryLimitBytes: 1 << 30, Models: []inference.InstalledModel{}}}
	raw, _ := json.Marshal(cfg)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(context.Background(), path, filepath.Join(home, "models"), true)
	if err != nil {
		t.Fatal(err)
	}
	manager.factory = func(_ context.Context, cfg inference.RuntimeConfig) (inference.Backend, error) {
		backend := &modelBackend{}
		for _, installed := range cfg.Models {
			if err := hashModel(context.Background(), installed.Path, installed.SizeBytes, installed.SHA256); err != nil {
				return nil, err
			}
			backend.models = append(backend.models, installed.Model)
		}
		return backend, nil
	}
	t.Cleanup(func() { manager.Close() })
	return manager, model, data
}
func installPayload(model inference.Model) json.RawMessage {
	raw, _ := json.Marshal(struct {
		Model inference.Model `json:"model"`
		URL   string          `json:"download_url"`
	}{model, artifactURL(model)})
	return raw
}
func TestUnapprovedModelNeverDownloadsAndConfigChangeIsNotOverwritten(t *testing.T) {
	manager, model, data := managerFixture(t)
	calls := 0
	manager.downloader = mockedDownload(data, &calls)
	wrong := model
	wrong.SHA256 = strings.Repeat("f", 64)
	if _, err := manager.Execute(context.Background(), cloud.WorkLease{Type: "install", Payload: installPayload(wrong)}, nil); err == nil {
		t.Fatal("unapproved model installed")
	}
	if calls != 0 {
		t.Fatal("unapproved model triggered network")
	}
	operatorBytes := []byte("operator changed config\n")
	manager.downloader = &downloader{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_ = os.WriteFile(manager.configPath, operatorBytes, 0600)
		return &http.Response{StatusCode: 200, ContentLength: int64(len(data)), Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
	})}}
	if _, err := manager.Execute(context.Background(), cloud.WorkLease{Type: "install", Payload: installPayload(model)}, nil); err == nil {
		t.Fatal("overwrote operator config")
	}
	current, _ := os.ReadFile(manager.configPath)
	if !bytes.Equal(current, operatorBytes) {
		t.Fatal("operator config was changed")
	}
	entries, _ := os.ReadDir(manager.modelRoot)
	for _, entry := range entries {
		if entry.Name() != "hosted-models.lock" {
			t.Fatal("aborted model commit left downloaded artifact", entry.Name())
		}
	}
}
func TestApprovedSyntheticInstallRevalidatesTamperAndRemovesOnlyManagedFile(t *testing.T) {
	manager, model, data := managerFixture(t)
	calls := 0
	manager.downloader = mockedDownload(data, &calls)
	if _, err := manager.Execute(context.Background(), cloud.WorkLease{Type: "install", Payload: installPayload(model)}, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(manager.modelRoot, model.SHA256+".gguf")
	info, _ := os.Stat(manager.configPath)
	if info.Mode().Perm() != 0600 {
		t.Fatal("config not private")
	}
	caps := manager.Capabilities()
	if len(caps.Models) != 1 || caps.Models[0].SHA256 != model.SHA256 {
		t.Fatal("installed capabilities missing")
	}
	tampered := append([]byte(nil), data...)
	tampered[40] ^= 1
	_ = os.WriteFile(path, tampered, 0600)
	if _, err := manager.Execute(context.Background(), cloud.WorkLease{Type: "install", Payload: installPayload(model)}, nil); err == nil {
		t.Fatal("installed artifact tamper went unnoticed")
	}
	_ = os.WriteFile(path, data, 0600)
	removal, _ := json.Marshal(map[string]string{"model_id": model.ID, "sha256": model.SHA256})
	if _, err := manager.Execute(context.Background(), cloud.WorkLease{Type: "remove", Payload: removal}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("managed model not removed")
	}
	if len(manager.cfg.Runtime.Models) != 0 {
		t.Fatal("model remains registered")
	}
}

func TestDownloadAddressesRejectSpecialUseAndFullArtifactSourcePinsExactPath(t *testing.T) {
	for _, address := range []string{"100.100.100.200", "100.64.0.1", "169.254.169.254", "127.0.0.1", "192.0.2.1", "198.18.0.1", "2001:db8::1", "64:ff9b::a9fe:a9fe", "::ffff:100.100.100.200"} {
		if publicDownloadIP(net.ParseIP(address)) {
			t.Fatal("special-use download address admitted", address)
		}
	}
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicDownloadIP(net.ParseIP(address)) {
			t.Fatal("public address refused", address)
		}
	}
	model, _ := syntheticModel()
	full := artifactURL(model)
	model.Source = full
	if _, err := immutableURL(model, full); err != nil {
		t.Fatal(err)
	}
	if _, err := immutableURL(model, strings.Replace(full, "model.gguf", "different.gguf", 1)); err == nil {
		t.Fatal("changed exact artifact source accepted")
	}
}

func TestHostedCapabilityTokenCapDoesNotChangeOperatorBudget(t *testing.T) {
	manager, _, _ := managerFixture(t)
	manager.cfg.Runtime.MaxTokens = 16384
	if manager.Capabilities().RuntimeLimits.MaxTokens != 8192 {
		t.Fatal("hosted wire cap not applied")
	}
	if manager.cfg.Runtime.MaxTokens != 16384 {
		t.Fatal("operator runtime budget mutated")
	}
}
