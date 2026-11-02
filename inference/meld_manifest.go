package inference

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	MeldManifestHeader     = "X-Nucleus-Manifest-SHA256"
	MeldNonceHeader        = "X-Nucleus-Request-Nonce"
	MeldResultHeader       = "X-Nucleus-Result-SHA256"
	meldGenerationWorkload = "image-generation"
	meldReviewWorkload     = "image-review"
	maxMeldManifestBytes   = 1 << 20
)

// MeldRuntimeManifest is the exact operator-provisioned JSON document served by
// an authenticated, cooperating loopback runtime. Its raw file bytes, including
// whitespace, are SHA-256 pinned by the gateway; it has no embedded digest field.
// Every model-associated file (weights, model configuration and tokenizers) is
// listed with its owning model's reviewed provenance and lineage disclosure. Software and
// hardware publisher origin are not part of this model-only policy.
type MeldRuntimeManifest struct {
	SchemaVersion       int                   `json:"schema_version"`
	RuntimeVersion      string                `json:"runtime_version"`
	Backend             string                `json:"backend"`
	Workload            string                `json:"workload"`
	Model               string                `json:"model"`
	ArtifactSetComplete bool                  `json:"artifact_set_complete"`
	Artifacts           []MeldRuntimeArtifact `json:"artifacts"`
}

type MeldRuntimeArtifact struct {
	Path  string `json:"path"`
	Model Model  `json:"model"`
}

type meldManifestBinding struct {
	manifest MeldRuntimeManifest
	digest   string
	nonce    string
}

type meldAdmissionError struct {
	status        int
	code, message string
}

func (err *meldAdmissionError) Error() string { return err.message }
func meldPolicyError(message string) error {
	return &meldAdmissionError{403, "model_policy_rejected", message}
}

func validMeldDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

// ValidateMeldManifest uses the same owner-controlled approvals as CPU inference.
// A runtime can report its artifacts but cannot approve its own model files.
// It does not call the GGUF-specific catalog validator: media model artifacts
// may use other formats and runtime implementations.
func ValidateMeldManifest(manifest MeldRuntimeManifest, workload string, approvals []ModelApproval) error {
	if manifest.SchemaVersion != 1 || !manifest.ArtifactSetComplete || manifest.Workload != workload ||
		!validProvenanceText(manifest.RuntimeVersion, 2048) || !validProvenanceText(manifest.Backend, 128) ||
		!validProvenanceText(manifest.Model, 256) || len(manifest.Artifacts) < 1 || len(manifest.Artifacts) > 256 {
		return errors.New("runtime manifest requires schema 1, matching workload, runtime/backend/model identity and an explicitly complete artifact set")
	}
	if workload != meldGenerationWorkload && workload != meldReviewWorkload {
		return errors.New("unsupported Meld manifest workload")
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.Artifacts {
		relative := artifact.Path
		if !validProvenanceText(relative, 1024) || path.IsAbs(relative) || path.Clean(relative) != relative || strings.ContainsAny(relative, "\\:") {
			return errors.New("manifest artifact paths must be bounded relative POSIX paths")
		}
		for _, component := range strings.Split(relative, "/") {
			if component == ".." || component == "." || component == "" {
				return errors.New("manifest artifact path traversal is forbidden")
			}
		}
		if seen[relative] {
			return errors.New("duplicate runtime artifact path")
		}
		seen[relative] = true
		model := artifact.Model
		if !validProvenanceText(model.ID, 256) || !validProvenanceText(model.Revision, 256) ||
			!validProvenanceText(model.License, 2048) || !validProvenanceText(model.Format, 128) ||
			!validProvenanceText(model.Runtime, 128) || model.SizeBytes == 0 || !contains(model.Workloads, workload) {
			return fmt.Errorf("artifact %q requires model identity, revision, license, format, runtime, size and matching workload", relative)
		}
		if _, err := evidenceURL(model.Source); err != nil {
			return fmt.Errorf("artifact %q requires an HTTPS model source: %w", relative, err)
		}
		if err := ApproveModel(model, approvals); err != nil {
			return fmt.Errorf("artifact %q: %w", relative, err)
		}
	}
	return nil
}

func (adapter *MeldAdapter) admitRuntime(request *http.Request) (*meldManifestBinding, error) {
	endpoint, token, pin, workload := adapter.config.GenerationURL, adapter.config.GenerationToken, adapter.config.GenerationManifestSHA256, meldGenerationWorkload
	if request.URL.Path == "/v1/reviews" {
		endpoint, token, pin, workload = adapter.config.ReviewURL, adapter.config.ReviewToken, adapter.config.ReviewManifestSHA256, meldReviewWorkload
	}
	if !validMeldDigest(pin) || len(adapter.config.ApprovedModels) == 0 {
		return nil, meldPolicyError("Meld execution requires an operator-pinned runtime manifest and owner-approved exact model artifacts with eligible reviewed lineage or an explicit scoped publisher-disclosure exception; unknown models and Chinese-origin models or derivatives are not eligible")
	}
	if supplied := strings.TrimSpace(request.Header.Get(MeldManifestHeader)); supplied != "" && supplied != pin {
		return nil, meldPolicyError("client manifest pin differs from the operator-approved runtime manifest")
	}
	nonce := strings.TrimSpace(request.Header.Get(MeldNonceHeader))
	if nonce != "" && !validMeldDigest(nonce) {
		return nil, &meldAdmissionError{400, "invalid_request", "X-Nucleus-Request-Nonce must be 64 lowercase hexadecimal characters"}
	}
	if nonce == "" {
		var bytes [32]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return nil, err
		}
		nonce = hex.EncodeToString(bytes[:])
	}
	ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
	defer cancel()
	probe, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(endpoint, "/")+"/v1/runtime-manifest", nil)
	if err != nil {
		return nil, err
	}
	probe.Header.Set("Accept", "application/json")
	if token != "" {
		probe.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := adapter.client.Do(probe)
	if err != nil {
		return nil, &meldAdmissionError{503, "runtime_manifest_unavailable", "unable to inspect the authenticated local runtime manifest; no model request was dispatched"}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, &meldAdmissionError{503, "runtime_manifest_unavailable", fmt.Sprintf("local runtime manifest returned HTTP %d; no model request was dispatched", response.StatusCode)}
	}
	media, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return nil, meldPolicyError("runtime manifest must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxMeldManifestBytes+1))
	if err != nil || len(body) > maxMeldManifestBytes {
		return nil, meldPolicyError("runtime manifest is incomplete or exceeds 1 MiB")
	}
	digest := sha256.Sum256(body)
	actual := hex.EncodeToString(digest[:])
	if actual != pin || strings.TrimSpace(response.Header.Get(MeldManifestHeader)) != pin {
		return nil, meldPolicyError("runtime manifest bytes or digest differ from the operator-approved pin")
	}
	var manifest MeldRuntimeManifest
	if err = decodeStrict(strings.NewReader(string(body)), &manifest); err != nil {
		return nil, meldPolicyError("runtime manifest contains invalid or unsupported fields: " + err.Error())
	}
	if err = ValidateMeldManifest(manifest, workload, adapter.config.ApprovedModels); err != nil {
		return nil, meldPolicyError(err.Error())
	}
	if workload == meldReviewWorkload && manifest.Model != adapter.config.ReviewModel {
		return nil, meldPolicyError("review runtime manifest model differs from configured review_model")
	}
	return &meldManifestBinding{manifest: manifest, digest: pin, nonce: nonce}, nil
}

func validateMeldResultProof(headers http.Header, body []byte, binding *meldManifestBinding) error {
	digest := sha256.Sum256(body)
	if strings.TrimSpace(headers.Get(MeldManifestHeader)) != binding.digest ||
		strings.TrimSpace(headers.Get(MeldNonceHeader)) != binding.nonce ||
		strings.TrimSpace(headers.Get(MeldResultHeader)) != hex.EncodeToString(digest[:]) {
		return errors.New("runtime response is not bound to the approved manifest, request nonce and exact result bytes")
	}
	return nil
}

// ManifestDigest helps operators pin exact bytes; it does not approve a model.
func ManifestDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
