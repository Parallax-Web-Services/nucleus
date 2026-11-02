package inference

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fictional metadata over a tensor-free GGUF fixture. These tests do not approve
// any real Google artifact and do not grant a publisher-wide exception.
func disclosedInstalledFixture(t *testing.T) (InstalledModel, []ModelApproval) {
	t.Helper()
	m := fixtureModel(t)
	m.Provenance.Publisher = "Google"
	m.Provenance.Evidence = []string{"https://ai.google.dev/gemma/docs/core/model_card_3"}
	m.Provenance.LineageComplete = false
	m.Provenance.LineageDisclosure = "publisher-disclosed"
	approval := ModelApproval{
		SHA256:                         m.SHA256,
		Provenance:                     *cloneModel(m.Model).Provenance,
		AllowPublisherDisclosedLineage: true,
		ReviewNote:                     "Fictional tensor-free protocol fixture only; exact artifact and disclosed provenance reviewed for this test.",
	}
	return m, []ModelApproval{approval}
}

func TestApprovedInstalledDisclosureKeepsStandaloneValidationStrict(t *testing.T) {
	m, approvals := disclosedInstalledFixture(t)
	if err := ValidateModel(m.Model); err == nil {
		t.Fatal("standalone model validation accepted incomplete lineage")
	}
	if _, err := validateInstalled(m, 128); err == nil {
		t.Fatal("standalone installed validation accepted incomplete lineage")
	}
	checked, err := validateApprovedInstalled(m, 128, approvals)
	if err != nil {
		t.Fatal("exact owner-approved installed fixture rejected:", err)
	}
	if checked.SHA256 != m.SHA256 || checked.RequiredMemoryBytes != m.RequiredMemoryBytes {
		t.Fatal("approved validation altered immutable model metadata")
	}
}

func TestApprovedInstalledDeniesBeforeModelFileIO(t *testing.T) {
	cases := map[string]func(*InstalledModel, *[]ModelApproval){
		"no owner entry": func(_ *InstalledModel, approvals *[]ModelApproval) { *approvals = nil },
		"missing exception flag": func(_ *InstalledModel, approvals *[]ModelApproval) {
			(*approvals)[0].AllowPublisherDisclosedLineage = false
		},
		"missing review note":     func(_ *InstalledModel, approvals *[]ModelApproval) { (*approvals)[0].ReviewNote = "" },
		"different approved hash": func(_ *InstalledModel, approvals *[]ModelApproval) { (*approvals)[0].SHA256 = strings.Repeat("a", 64) },
		"changed provenance": func(m *InstalledModel, _ *[]ModelApproval) {
			m.Provenance.Evidence = []string{"https://example.org/different-disclosure"}
		},
		"unknown origin":           func(m *InstalledModel, _ *[]ModelApproval) { m.Provenance.Country = "" },
		"blocked artifact renamed": func(m *InstalledModel, _ *[]ModelApproval) { m.SHA256 = blockedQwenSHA256 },
		"blocked upstream ancestor": func(m *InstalledModel, approvals *[]ModelApproval) {
			m.Provenance.BaseModels = []ModelOrigin{{ID: "Qwen/Qwen2.5", Revision: "fixed", Publisher: "Alibaba Cloud", Country: "CN", Source: "https://huggingface.co/Qwen/Qwen2.5", Evidence: []string{"https://github.com/QwenLM"}}}
			(*approvals)[0].Provenance = *cloneModel(m.Model).Provenance
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m, approvals := disclosedInstalledFixture(t)
			m.Path = filepath.Join(t.TempDir(), "unopened-missing-model.gguf")
			change(&m, &approvals)
			_, err := validateApprovedInstalled(m, 128, approvals)
			var pathErr *os.PathError
			if err == nil || errors.As(err, &pathErr) || strings.Contains(err.Error(), m.Path) {
				t.Fatalf("policy did not reject before model file access: %v", err)
			}
			cfg := FleetConfig{Runtime: &RuntimeConfig{Models: []InstalledModel{m}, ContextLength: 128, MemoryLimitBytes: 1 << 30}, ApprovedModels: approvals}
			err = ValidateConfiguredModels(cfg)
			if err == nil || errors.As(err, &pathErr) || strings.Contains(err.Error(), m.Path) {
				t.Fatalf("configured preflight reached a denied model file: %v", err)
			}
		})
	}
}

func TestApprovedInstalledRetainsMetadataIntegrityGGUFAndMemoryChecks(t *testing.T) {
	cases := map[string]func(*InstalledModel){
		"missing identifier":          func(m *InstalledModel) { m.ID = "" },
		"unsupported format":          func(m *InstalledModel) { m.Format = "ONNX" },
		"unsupported runtime":         func(m *InstalledModel) { m.Runtime = "another-runtime" },
		"wrong quantization":          func(m *InstalledModel) { m.Quantization = "Q5_0" },
		"wrong architecture":          func(m *InstalledModel) { m.Architecture = "gemma3" },
		"wrong file size":             func(m *InstalledModel) { m.SizeBytes++ },
		"wrong file hash":             func(m *InstalledModel) { m.SHA256 = strings.Repeat("a", 64) },
		"insufficient context memory": func(m *InstalledModel) { m.RequiredMemoryBytes = m.SizeBytes },
		"unsupported workload":        func(m *InstalledModel) { m.Workloads = []string{"vision-review"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m, approvals := disclosedInstalledFixture(t)
			change(&m)
			// The operator can approve this declared hash, but that never skips
			// actual file inspection or the independent runtime metadata checks.
			approvals[0].SHA256 = m.SHA256
			if err := ApproveModel(m.Model, approvals); err != nil {
				t.Fatal("fixture must reach post-admission validation:", err)
			}
			if _, err := validateApprovedInstalled(m, 128, approvals); err == nil {
				t.Fatal("approved model bypassed runtime or file validation")
			}
		})
	}
	m, approvals := disclosedInstalledFixture(t)
	if _, err := validateApprovedInstalled(m, 8192, approvals); err == nil {
		t.Fatal("owner approval bypassed GGUF training context limit")
	}
	if err := os.WriteFile(m.Path, []byte("not a GGUF"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateApprovedInstalled(m, 128, approvals); err == nil {
		t.Fatal("owner approval bypassed GGUF inspection")
	}
}

func TestApprovedInstalledPreflightRuntimeAndLazyLoadUseExactOwnerEntry(t *testing.T) {
	t.Setenv("NUCLEUS_TEST_LLAMA", "1")
	cfg := fixtureConfig(t)
	m, approvals := disclosedInstalledFixture(t)
	cfg.Models, cfg.ApprovedModels = []InstalledModel{m}, approvals
	if err := ValidateConfiguredModels(FleetConfig{Runtime: &cfg, ApprovedModels: approvals}); err != nil {
		t.Fatal("owner-configured preflight rejected exact disclosure exception:", err)
	}
	backend, err := NewLlama(context.Background(), cfg)
	if err != nil {
		t.Fatal("runtime admission rejected exact disclosure exception:", err)
	}
	defer backend.Close()
	// The child is the existing tensor-free fake llama-server, not a neural model.
	if err = backend.Run(context.Background(), Request{Model: m.ID, Messages: []Message{{Role: "user", Content: "benign fixture"}}, MaxTokens: 4}, func(Event) error { return nil }); err != nil {
		t.Fatal("lazy-load revalidation rejected an admitted fixture:", err)
	}
}

func TestApprovedInstalledLazyLoadRechecksOwnerBeforeModelFileIO(t *testing.T) {
	t.Setenv("NUCLEUS_TEST_LLAMA", "1")
	cfg := fixtureConfig(t)
	m, approvals := disclosedInstalledFixture(t)
	cfg.Models, cfg.ApprovedModels = []InstalledModel{m}, approvals
	backend, err := NewLlama(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	runtime := backend.(*Llama)
	runtime.cfg.ApprovedModels = nil
	if err = os.Remove(m.Path); err != nil {
		t.Fatal(err)
	}
	_, _, err = runtime.ensure(context.Background(), m.ID)
	var pathErr *os.PathError
	if err == nil || errors.As(err, &pathErr) || !strings.Contains(err.Error(), "owner-approved") {
		t.Fatalf("lazy-load did not reject revoked approval before file I/O: %v", err)
	}
}
