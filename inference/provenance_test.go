package inference

import (
	"encoding/json"
	"strings"
	"testing"
)

func reviewedProvenanceFixture() ModelProvenance {
	return ModelProvenance{
		Publisher: "Example Research Lab", Country: "US",
		Evidence:        []string{"https://example.org/model-card", "https://example.org/organization"},
		LineageComplete: true, BaseModels: []ModelOrigin{},
	}
}
func provenanceModelFixture() Model {
	p := reviewedProvenanceFixture()
	return Model{ID: "example-original", Source: "https://example.org/models/original", SHA256: strings.Repeat("a", 64), Provenance: &p}
}
func cloneProvenanceFixture(t *testing.T, m Model) Model {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var copy Model
	if err = json.Unmarshal(data, &copy); err != nil {
		t.Fatal(err)
	}
	return copy
}
func upstreamProvenanceFixture() ModelOrigin {
	return ModelOrigin{ID: "example/base-model", Revision: "immutable-base-revision", Publisher: "Example Base Lab", Country: "GB", Source: "https://example.org/base-model", Evidence: []string{"https://example.org/base-card"}}
}
func TestModelProvenanceRequiresCompleteKnownOrigin(t *testing.T) {
	allowed := provenanceModelFixture()
	if err := ValidateModelProvenance(allowed); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(*Model)
	}{
		{"missing provenance", func(m *Model) { m.Provenance = nil }},
		{"unknown publisher", func(m *Model) { m.Provenance.Publisher = "unknown" }},
		{"missing publisher", func(m *Model) { m.Provenance.Publisher = "" }},
		{"unknown country", func(m *Model) { m.Provenance.Country = "XX" }},
		{"non-code country", func(m *Model) { m.Provenance.Country = "AA" }},
		{"country alias", func(m *Model) { m.Provenance.Country = "UK" }},
		{"lowercase country", func(m *Model) { m.Provenance.Country = "us" }},
		{"missing origin proof", func(m *Model) { m.Provenance.Evidence = nil }},
		{"unattested lineage", func(m *Model) { m.Provenance.LineageComplete = false }},
		{"omitted base declaration", func(m *Model) { m.Provenance.BaseModels = nil }},
		{"missing artifact hash", func(m *Model) { m.SHA256 = "" }},
		{"uppercase artifact hash", func(m *Model) { m.SHA256 = strings.Repeat("A", 64) }},
		{"invalid artifact hash", func(m *Model) { m.SHA256 = strings.Repeat("g", 64) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := cloneProvenanceFixture(t, allowed)
			tc.change(&m)
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("unreviewable provenance was accepted")
			}
		})
	}
	for _, country := range []string{"US", "GB", "FR", "DE", "JP", "IN", "SG", "TW", "CA", "AU", "NZ", "ZA", "BR"} {
		m := cloneProvenanceFixture(t, allowed)
		m.Provenance.Country = country
		if err := ValidateModelProvenance(m); err != nil {
			t.Fatalf("recognized country %s rejected: %v", country, err)
		}
	}
}
func TestModelProvenanceBlocksOriginAndEveryDerivative(t *testing.T) {
	for _, country := range []string{"CN", "HK", "MO"} {
		t.Run(country, func(t *testing.T) {
			m := provenanceModelFixture()
			m.Provenance.Country = country
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("blocked publisher jurisdiction accepted")
			}
			m = provenanceModelFixture()
			base := upstreamProvenanceFixture()
			base.Country = country
			m.Provenance.BaseModels = []ModelOrigin{base}
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("derivative of blocked upstream jurisdiction accepted")
			}
		})
	}
	for _, identity := range []string{"Qwen2.5-0.5B", "Q_W_E_N-quantized", "DeepSeek-R1-Distill", "MiniMax-M2", "GLM-4", "Kimi-K2", "Yi-1.5", "BAAI/bge-small", "Tencent-Hunyuan", "h94/IP-Adapter", "IP_Adapter-SDXL", "seed-1.5", "step-3"} {
		t.Run(identity, func(t *testing.T) {
			m := provenanceModelFixture()
			m.ID = identity
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("known model family accepted")
			}
			m = provenanceModelFixture()
			base := upstreamProvenanceFixture()
			base.ID = identity
			m.Provenance.BaseModels = []ModelOrigin{base}
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("known upstream family accepted behind a different quantizer")
			}
		})
	}
	for _, publisher := range []string{"Alibaba Cloud", "Tencent AI Lab", "ByteDance", "Zhipu AI", "Z.AI", "Moonshot AI", "ModelBest", "Shanghai AI Lab", "OpenBMB", "01.AI"} {
		m := provenanceModelFixture()
		m.Provenance.Publisher = publisher
		if err := ValidateModelProvenance(m); err == nil {
			t.Fatalf("known publisher %q accepted with spoofed country US", publisher)
		}
	}
	m := provenanceModelFixture()
	m.Source = "https://example.org/models/qw%65n.gguf"
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("escaped known model source accepted")
	}
	m = provenanceModelFixture()
	m.Provenance.BaseModels = []ModelOrigin{upstreamProvenanceFixture()}
	m.Provenance.BaseModels[0].Source = "https://huggingface.co/h94/IP-Adapter"
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("blocked adapter source accepted")
	}
}
func TestModelProvenanceBlocksRenamedKnownArtifact(t *testing.T) {
	m := provenanceModelFixture()
	m.SHA256 = blockedQwenSHA256
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("renamed Qwen bytes accepted")
	}
	approval := ModelApproval{SHA256: m.SHA256, Provenance: *m.Provenance}
	if err := ValidateModelApproval(approval); err == nil {
		t.Fatal("known forbidden hash can be owner-approved")
	}
	if err := ApproveModel(m, []ModelApproval{approval}); err == nil {
		t.Fatal("spoofed approval bypassed known hash deny")
	}
	m = provenanceModelFixture()
	base := upstreamProvenanceFixture()
	base.SHA256 = blockedQwenSHA256
	m.Provenance.BaseModels = []ModelOrigin{base}
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("renamed blocked teacher hash accepted")
	}
}
func TestModelProvenanceValidatesEvidenceLocally(t *testing.T) {
	for _, evidence := range []string{"http://example.org/card", "file:///tmp/model-card", "https://user:password@example.org/card", "https://example.org/card#fragment", "https:///missing-host", "https://example.org/%0aheader", "https://example.org/card?bad=%GG", "https://example.org:99999/card"} {
		t.Run(evidence, func(t *testing.T) {
			m := provenanceModelFixture()
			m.Provenance.Evidence = []string{evidence}
			if err := ValidateModelProvenance(m); err == nil {
				t.Fatal("unsafe or invalid evidence URL accepted")
			}
		})
	}
	m := provenanceModelFixture()
	m.Provenance.Evidence = []string{"https://example.org/model", "https://EXAMPLE.ORG/model"}
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("duplicate canonical evidence accepted")
	}
	m = provenanceModelFixture()
	base := upstreamProvenanceFixture()
	base.Revision = ""
	m.Provenance.BaseModels = []ModelOrigin{base}
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("unversioned upstream accepted")
	}
	m = provenanceModelFixture()
	base = upstreamProvenanceFixture()
	m.Provenance.BaseModels = []ModelOrigin{base, base}
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("duplicate base lineage accepted")
	}
	m = provenanceModelFixture()
	base = upstreamProvenanceFixture()
	base.Country = ""
	m.Provenance.BaseModels = []ModelOrigin{base}
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("unknown upstream origin accepted")
	}
}
func TestModelProvenanceScopeExcludesSoftwareAndArchitecture(t *testing.T) {
	m := provenanceModelFixture()
	m.Architecture = "qwen2"        // Compatibility labels do not prove weight origin.
	m.Runtime = "a-runtime-from-CN" // Runtime implementation is outside this policy.
	m.Source = "https://example.cn/an-independently-trained-original"
	m.Provenance.Evidence = []string{"https://example.cn/original-model-proof"}
	if err := ValidateModelProvenance(m); err != nil {
		t.Fatalf("runtime, architecture or hosting geography inferred as weight provenance: %v", err)
	}
	if err := ApproveModel(m, []ModelApproval{{SHA256: m.SHA256, Provenance: *m.Provenance}}); err != nil {
		t.Fatal(err)
	}
}
func TestModelApprovalPinsHashAndFullReviewedProvenance(t *testing.T) {
	original := provenanceModelFixture()
	original.Provenance.BaseModels = []ModelOrigin{upstreamProvenanceFixture()}
	approval := ModelApproval{SHA256: original.SHA256, Provenance: *original.Provenance}
	if err := ApproveModel(original, []ModelApproval{approval}); err != nil {
		t.Fatal(err)
	}
	if err := ApproveModel(original, nil); err == nil {
		t.Fatal("empty owner policy implicitly approved a worker model")
	}
	changed := cloneProvenanceFixture(t, original)
	changed.SHA256 = strings.Repeat("b", 64)
	if err := ApproveModel(changed, []ModelApproval{approval}); err == nil {
		t.Fatal("worker's new bytes bypassed pinned approval")
	}
	changes := []func(*Model){
		func(m *Model) { m.Provenance.Country = "CA" },
		func(m *Model) { m.Provenance.Publisher = "Another Quantizer" },
		func(m *Model) { m.Provenance.Evidence = []string{"https://example.org/different-proof"} },
		func(m *Model) { m.Provenance.BaseModels = []ModelOrigin{} },
		func(m *Model) { m.Provenance.BaseModels[0].Revision = "changed-revision" },
		func(m *Model) { m.Provenance.BaseModels[0].Country = "FR" },
	}
	for i, change := range changes {
		m := cloneProvenanceFixture(t, original)
		change(&m)
		if err := ApproveModel(m, []ModelApproval{approval}); err == nil {
			t.Fatalf("worker altered reviewed provenance case %d", i)
		}
	}
	if err := ApproveModel(original, []ModelApproval{approval, approval}); err == nil {
		t.Fatal("duplicate owner approval accepted")
	}
	invalid := approval
	invalid.SHA256 = blockedQwenSHA256
	if err := ApproveModel(original, []ModelApproval{approval, invalid}); err == nil {
		t.Fatal("invalid owner policy entry silently ignored")
	}
}
func TestModelApprovalCanonicalOrderingDoesNotMutateInputs(t *testing.T) {
	m := provenanceModelFixture()
	first := upstreamProvenanceFixture()
	second := upstreamProvenanceFixture()
	second.ID = "example/second-base"
	second.Source = "https://example.org/second-base"
	m.Provenance.BaseModels = []ModelOrigin{first, second}
	owner := cloneProvenanceFixture(t, m)
	owner.Provenance.Evidence[0], owner.Provenance.Evidence[1] = owner.Provenance.Evidence[1], owner.Provenance.Evidence[0]
	owner.Provenance.BaseModels[0], owner.Provenance.BaseModels[1] = owner.Provenance.BaseModels[1], owner.Provenance.BaseModels[0]
	before, _ := json.Marshal(m)
	if err := ApproveModel(m, []ModelApproval{{SHA256: m.SHA256, Provenance: *owner.Provenance}}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(m)
	if string(before) != string(after) {
		t.Fatal("approval validation mutated worker-owned metadata")
	}
}

// Fictional metadata only: these fixtures contain no real model weights and do
// not grant publisher-wide or family-wide exceptions for any pretrained model.
func publisherDisclosedFixture() (Model, ModelApproval) {
	m := provenanceModelFixture()
	m.Provenance.LineageComplete = false
	m.Provenance.LineageDisclosure = "publisher-disclosed"
	m.Provenance.BaseModels = []ModelOrigin{upstreamProvenanceFixture()}
	ownerProvenance := *m.Provenance
	ownerProvenance.BaseModels = []ModelOrigin{upstreamProvenanceFixture()}
	return m, ModelApproval{SHA256: m.SHA256, Provenance: ownerProvenance,
		AllowPublisherDisclosedLineage: true,
		ReviewNote:                     "Owner explicitly accepts this exact artifact's published lineage despite undisclosed training teacher checkpoints."}
}

func TestPublisherDisclosedLineageRequiresExactOwnerException(t *testing.T) {
	m, approval := publisherDisclosedFixture()
	if err := ValidateModelProvenance(m); err == nil {
		t.Fatal("strict standalone validation accepted an incomplete publisher disclosure")
	}
	if err := ValidateModelApproval(approval); err != nil {
		t.Fatal(err)
	}
	if err := ApproveModel(m, []ModelApproval{approval}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		mutateModel    func(*Model)
		mutateApproval func(*ModelApproval)
		noApproval     bool
	}{
		{name: "missing owner approval", noApproval: true},
		{name: "owner flag absent", mutateApproval: func(a *ModelApproval) { a.AllowPublisherDisclosedLineage = false }},
		{name: "owner note absent", mutateApproval: func(a *ModelApproval) { a.ReviewNote = "" }},
		{name: "owner note whitespace", mutateApproval: func(a *ModelApproval) { a.ReviewNote = "  " }},
		{name: "owner note unbounded", mutateApproval: func(a *ModelApproval) { a.ReviewNote = strings.Repeat("x", 2001) }},
		{name: "owner note controls", mutateApproval: func(a *ModelApproval) { a.ReviewNote = "approval\nwithout review" }},
		{name: "wrong approved artifact", mutateApproval: func(a *ModelApproval) { a.SHA256 = strings.Repeat("b", 64) }},
		{name: "new artifact bytes", mutateModel: func(m *Model) { m.SHA256 = strings.Repeat("c", 64) }},
		{name: "changed publisher", mutateModel: func(m *Model) { m.Provenance.Publisher = "Another Publisher" }},
		{name: "changed ancestor", mutateModel: func(m *Model) { m.Provenance.BaseModels[0].Revision = "unreviewed-release" }},
		{name: "removed ancestor", mutateModel: func(m *Model) { m.Provenance.BaseModels = []ModelOrigin{} }},
		{name: "unknown disclosure", mutateModel: func(m *Model) { m.Provenance.LineageDisclosure = "anything-goes" }},
		{name: "missing disclosure", mutateModel: func(m *Model) { m.Provenance.LineageDisclosure = "" }},
		{name: "falsely complete disclosure", mutateModel: func(m *Model) { m.Provenance.LineageComplete = true }},
		{name: "missing declared ancestor array", mutateModel: func(m *Model) { m.Provenance.BaseModels = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			model, owner := publisherDisclosedFixture()
			if tc.mutateModel != nil {
				tc.mutateModel(&model)
			}
			if tc.mutateApproval != nil {
				tc.mutateApproval(&owner)
			}
			approvals := []ModelApproval{owner}
			if tc.noApproval {
				approvals = nil
			}
			if err := ApproveModel(model, approvals); err == nil {
				t.Fatal("disclosure bypassed exact owner approval")
			}
		})
	}
}

func TestPublisherDisclosureCannotOverrideBlockedOrUnknownOrigins(t *testing.T) {
	changes := []struct {
		name   string
		mutate func(*Model)
	}{
		{"blocked model bytes", func(m *Model) { m.SHA256 = blockedQwenSHA256 }},
		{"blocked model identity", func(m *Model) { m.ID = "Qwen-renamed-derivative" }},
		{"blocked source", func(m *Model) { m.Source = "https://example.org/h94/IP-Adapter" }},
		{"blocked publisher country", func(m *Model) { m.Provenance.Country = "CN" }},
		{"unknown publisher country", func(m *Model) { m.Provenance.Country = "XX" }},
		{"blocked publisher", func(m *Model) { m.Provenance.Publisher = "Tencent AI Lab" }},
		{"blocked teacher country", func(m *Model) { m.Provenance.BaseModels[0].Country = "HK" }},
		{"blocked teacher identity", func(m *Model) { m.Provenance.BaseModels[0].ID = "DeepSeek-distillation-teacher" }},
		{"blocked teacher bytes", func(m *Model) { m.Provenance.BaseModels[0].SHA256 = blockedQwenSHA256 }},
		{"unknown teacher origin", func(m *Model) { m.Provenance.BaseModels[0].Country = "" }},
	}
	for _, tc := range changes {
		t.Run(tc.name, func(t *testing.T) {
			m, a := publisherDisclosedFixture()
			tc.mutate(&m)
			// Even an owner exception matching the rejected metadata cannot override a
			// known prohibited artifact or upstream origin, nor an unknown declared one.
			a.SHA256 = m.SHA256
			a.Provenance = *m.Provenance
			if err := ApproveModel(m, []ModelApproval{a}); err == nil {
				t.Fatal("owner disclosure exception overrode model-origin guard")
			}
			if err := ValidateModelApproval(a); err == nil && tc.name != "blocked model identity" && tc.name != "blocked source" {
				t.Fatal("invalid exception entered owner catalog")
			}
		})
	}
}
