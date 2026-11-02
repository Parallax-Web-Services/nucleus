package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fictional metadata for tensor-free protocol fixtures, never a real approval.
func testModelProvenance() *ModelProvenance {
	return &ModelProvenance{Publisher: "Nucleus protocol test fixture", Country: "US", Evidence: []string{"https://example.org/nucleus/test-fixture"}, LineageComplete: true, BaseModels: []ModelOrigin{}}
}
func testModelApprovals(m Model) []ModelApproval {
	return []ModelApproval{{SHA256: m.SHA256, Provenance: *cloneModel(m).Provenance}}
}

type policyBackend struct {
	models []Model
	runs   int
}

func (b *policyBackend) Models() []Model                                       { return b.models }
func (b *policyBackend) Run(context.Context, Request, func(Event) error) error { b.runs++; return nil }
func (b *policyBackend) Close() error                                          { return nil }

type policyControl struct{ calls int }

func (c *policyControl) Register(context.Context, Advertisement) error { c.calls++; return nil }
func (c *policyControl) Acquire(context.Context) (*Lease, error)       { c.calls++; return nil, nil }
func (c *policyControl) Push(context.Context, string, Event) error     { c.calls++; return nil }
func (c *policyControl) Job(context.Context, string) (JobView, error) {
	c.calls++
	return JobView{}, nil
}

func TestPolicyRequiresOwnerApprovalAtWorkerAndBenchmarkBoundaries(t *testing.T) {
	backend := &policyBackend{models: []Model{schedulerModel()}}
	control := new(policyControl)
	if err := RunWorker(context.Background(), backend, control, RuntimeConfig{}, nil, nil); err == nil || !strings.Contains(err.Error(), "owner-approved") {
		t.Fatalf("unapproved worker: %v", err)
	}
	if control.calls != 0 || backend.runs != 0 {
		t.Fatal("unapproved worker contacted coordinator or ran backend")
	}
	if _, err := BenchmarkBackend(context.Background(), backend, "text-model", "benign fixture", 4, nil); err == nil {
		t.Fatal("standalone benchmark bypassed owner approval")
	}
	if backend.runs != 0 {
		t.Fatal("unapproved benchmark ran backend")
	}
}
func TestPolicyOwnerRejectsWorkerClaimsAndRechecksPlacement(t *testing.T) {
	scheduler, _, _ := newSchedulerFixture(t, FleetConfig{})
	for _, change := range []func(*Model){
		func(m *Model) { m.Provenance = nil },
		func(m *Model) { m.Provenance.Country = "CN" },
		func(m *Model) {
			m.Provenance.Publisher = "Third-party repackager"
			m.Provenance.BaseModels = []ModelOrigin{{ID: "Qwen/Qwen2.5", Revision: "fixed", Publisher: "Alibaba Cloud", Country: "CN", Source: "https://huggingface.co/Qwen/Qwen2.5", Evidence: []string{"https://github.com/QwenLM"}}}
		},
		func(m *Model) {
			m.SHA256 = blockedQwenSHA256
			m.ID = "friendly-name"
			m.Source = "https://example.org/renamed"
		},
		func(m *Model) { m.Provenance.Publisher = "Different unreviewed publisher" },
		func(m *Model) { m.SHA256 = strings.Repeat("c", 64) },
	} {
		ad := schedulerAdvertisement()
		change(&ad.Models[0])
		if err := scheduler.Register("a", ad); err == nil {
			t.Fatal("unapproved or disallowed remote model registered")
		}
	}
	ad := schedulerAdvertisement()
	schedulerRegister(t, scheduler, "a", ad)
	// A cached capability cannot bypass a later owner-policy restriction.
	scheduler.mu.Lock()
	scheduler.cfg.ApprovedModels = nil
	scheduler.mu.Unlock()
	if _, _, err := scheduler.Submit(context.Background(), schedulerRequest()); err == nil {
		t.Fatal("placement ignored absent model approval")
	}
}
func TestPolicyLocalRuntimeAndWarmCacheCannotBypassApproval(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.ApprovedModels = nil
	if _, err := NewLlama(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "owner-approved") {
		t.Fatalf("runtime admission: %v", err)
	}
	t.Setenv("NUCLEUS_TEST_LLAMA", "1")
	cfg = fixtureConfig(t)
	backend, err := NewLlama(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	request := Request{Model: "fixture", Messages: []Message{{Role: "user", Content: "benign fixture"}}, MaxTokens: 4}
	if err = backend.Run(context.Background(), request, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	// Returned capabilities must not grant mutable access to validated provenance.
	returned := backend.Models()
	returned[0].Provenance.Country = "CN"
	returned[0].Provenance.Evidence[0] = "https://example.org/changed"
	if backend.Models()[0].Provenance.Country != "US" {
		t.Fatal("capability metadata mutated runtime provenance")
	}
	runtime := backend.(*Llama)
	runtime.cfg.ApprovedModels = nil
	emitted := false
	if err = backend.Run(context.Background(), request, func(Event) error { emitted = true; return nil }); err == nil {
		t.Fatal("warm model bypassed policy")
	}
	if emitted {
		t.Fatal("disallowed warm model emitted output")
	}
}
func TestPolicyPreflightRejectsKnownArtifactBeforeFileAccess(t *testing.T) {
	m := fixtureModel(t)
	m.SHA256 = blockedQwenSHA256
	m.ID = "renamed-friendly-model"
	m.Source = "https://example.org/model"
	m.Path = "/this-file-does-not-exist/model.gguf"
	cfg := FleetConfig{Runtime: &RuntimeConfig{Models: []InstalledModel{m}, ContextLength: 128, MemoryLimitBytes: 1 << 30}}
	if err := ValidateConfiguredModels(cfg); err == nil || !strings.Contains(err.Error(), "Qwen artifact") {
		t.Fatalf("known artifact was not rejected before file access: %v", err)
	}
}
func TestPolicyPrivateConfigurationPropagatesReviewedApprovals(t *testing.T) {
	runtime := fixtureConfig(t)
	m := runtime.Models[0]
	config := FleetConfig{Runtime: &runtime, ApprovedModels: testModelApprovals(m.Model)}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fleet.json")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFleetConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateConfiguredModels(loaded); err != nil {
		t.Fatal(err)
	}
	if err = ApproveModel(loaded.Runtime.Models[0].Model, loaded.Runtime.ApprovedModels); err != nil {
		t.Fatal("runtime did not receive authoritative config approvals:", err)
	}
}
func TestPolicyOperationalAPIRequiresAuthAndExplainsDefaultDeny(t *testing.T) {
	svc, server := apiFixture(t)
	response := apiCall(t, server, svc.APIKey, http.MethodGet, "/v1/inference/policy", nil)
	defer response.Body.Close()
	var body struct {
		Scope    string   `json:"scope"`
		Unknown  string   `json:"unknown_provenance"`
		Approved []string `json:"approved_sha256"`
		Basis    string   `json:"approval_basis"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Basis, "exact-SHA256") || !strings.Contains(body.Basis, "identical provenance") {
		t.Fatalf("policy API omitted the bounded owner exception: %+v", body)
	}
	if response.StatusCode != 200 || body.Scope != "models_and_model_derivatives" || body.Unknown != "deny" || len(body.Approved) != 0 {
		t.Fatalf("unexpected policy API: %+v", body)
	}
}
