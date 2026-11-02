package inference

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	_ "image/png"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// MeldConfig describes loopback Positronic endpoints; configuration alone does not authorize model execution.
// They are independent from the GGUF text backend. Remote image execution is
// not implemented by this adapter.
type MeldConfig struct {
	GenerationURL            string          `json:"generation_url,omitempty"`
	GenerationToken          string          `json:"generation_token,omitempty"`
	ReviewURL                string          `json:"review_url,omitempty"`
	ReviewToken              string          `json:"review_token,omitempty"`
	ReviewModel              string          `json:"review_model,omitempty"`
	GenerationManifestSHA256 string          `json:"generation_manifest_sha256,omitempty"`
	ReviewManifestSHA256     string          `json:"review_manifest_sha256,omitempty"`
	ApprovedModels           []ModelApproval `json:"-"`
	MaxRequestBytes          int64           `json:"max_request_bytes,omitempty"`
	MaxResponseBytes         int64           `json:"max_response_bytes,omitempty"`
	MaxConcurrent            int             `json:"max_concurrent,omitempty"`
	TimeoutSeconds           int             `json:"timeout_seconds,omitempty"`
}

// MeldAdapter retains Meld's protocol contract while rejecting unverified model execution. Mount behind
// the owner's inference API authentication. It does not implement image models,
// start runtimes, provision weights, or replay requests.
type MeldAdapter struct {
	config MeldConfig
	client *http.Client
	slots  chan struct{}
}

func NewMeldAdapter(config MeldConfig) (*MeldAdapter, error) {
	for name, endpoint := range map[string]string{"generation_url": config.GenerationURL, "review_url": config.ReviewURL} {
		if endpoint != "" {
			if err := validateMeldURL(endpoint); err != nil {
				return nil, fmt.Errorf("meld %s: %w", name, err)
			}
		}
	}
	if config.ReviewURL != "" && strings.TrimSpace(config.ReviewModel) == "" {
		return nil, errors.New("meld review_model is required for runtime attestation")
	}
	if strings.ContainsAny(config.GenerationToken+config.ReviewToken, "\r\n") {
		return nil, errors.New("meld runtime tokens cannot contain line breaks")
	}
	for _, pin := range []string{config.GenerationManifestSHA256, config.ReviewManifestSHA256} {
		if pin != "" && !validMeldDigest(pin) {
			return nil, errors.New("Meld runtime manifest pins must be 64 lowercase hexadecimal characters")
		}
	}
	config.ApprovedModels = cloneApprovals(config.ApprovedModels)
	if config.MaxRequestBytes == 0 {
		config.MaxRequestBytes = 32 << 20
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 64 << 20
	}
	if config.MaxConcurrent == 0 {
		config.MaxConcurrent = 1
	}
	if config.TimeoutSeconds == 0 {
		config.TimeoutSeconds = 900
	}
	if config.MaxRequestBytes < 1 || config.MaxRequestBytes > 128<<20 || config.MaxResponseBytes < 1 || config.MaxResponseBytes > 128<<20 || config.MaxConcurrent < 1 || config.MaxConcurrent > 16 || config.TimeoutSeconds < 1 || config.TimeoutSeconds > 1800 {
		return nil, errors.New("meld limits require request/response bytes 1..128MiB, concurrency 1..16, timeout 1..1800 seconds")
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false,
		DialContext:     (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 3 * time.Second, MaxResponseHeaderBytes: 32 << 10}
	return &MeldAdapter{config: config, slots: make(chan struct{}, config.MaxConcurrent), client: &http.Client{
		Transport: transport, Timeout: time.Duration(config.TimeoutSeconds) * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func validateMeldURL(raw string) error {
	endpoint, err := url.Parse(raw)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Opaque != "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawPath != "" {
		return errors.New("runtime URL must be http(s)://LOOPBACK_IP:PORT without a path or credentials")
	}
	host, port, err := net.SplitHostPort(endpoint.Host)
	ip := net.ParseIP(host)
	number, portErr := strconv.Atoi(port)
	if err != nil || ip == nil || !ip.IsLoopback() || portErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("runtime URL requires a literal loopback IP and port 1..65535")
	}
	return nil
}

// ServeHTTP admits model execution only when a runtime-bound, approved manifest
// establishes the exact provenance of every weight, adapter and encoder. A
// backend name, request alias or caller-supplied origin label cannot grant this.
func (adapter *MeldAdapter) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != "/v1/generations" && request.URL.Path != "/v1/reviews" {
		http.NotFound(w, request)
		return
	}
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		meldError(w, 405, "method_not_allowed", "Meld generation and review require POST")
		return
	}
	endpoint := adapter.config.GenerationURL
	if request.URL.Path == "/v1/reviews" {
		endpoint = adapter.config.ReviewURL
	}
	if endpoint == "" {
		meldError(w, 503, "workload_unavailable", "No compatible approved Meld model runtime is configured. GGUF text generation cannot execute image generation or vision review.")
		return
	}
	binding, err := adapter.admitRuntime(request)
	if err != nil {
		var admission *meldAdmissionError
		if errors.As(err, &admission) {
			meldError(w, admission.status, admission.code, admission.message)
		} else {
			meldError(w, 503, "runtime_manifest_unavailable", "unable to admit the configured runtime")
		}
		return
	}
	adapter.forward(w, request, binding)
}

// forwardProtocol retains the transport contract for nonproduction protocol
// fixtures. ServeHTTP never calls this fixture entry point; it invokes the
// forwarding implementation only with an independently admitted binding.
func (adapter *MeldAdapter) forwardProtocol(w http.ResponseWriter, request *http.Request) {
	adapter.forward(w, request, nil)
}

func (adapter *MeldAdapter) forward(w http.ResponseWriter, request *http.Request, binding *meldManifestBinding) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if request.URL.Path != "/v1/generations" && request.URL.Path != "/v1/reviews" {
		http.NotFound(w, request)
		return
	}
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		meldError(w, 405, "method_not_allowed", "Meld generation and review require POST")
		return
	}
	endpoint, token := adapter.config.GenerationURL, adapter.config.GenerationToken
	if request.URL.Path == "/v1/reviews" {
		endpoint, token = adapter.config.ReviewURL, adapter.config.ReviewToken
	}
	if endpoint == "" {
		meldError(w, 503, "workload_unavailable", "No compatible local Positronic runtime is configured. GGUF text generation cannot execute Meld image generation or vision review. Provision and validate an authorized runtime first.")
		return
	}
	select {
	case adapter.slots <- struct{}{}:
		defer func() { <-adapter.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		meldError(w, 429, "resource_limit", "Meld runtime concurrency limit reached; request was not dispatched")
		return
	}
	defer request.Body.Close()
	body, err := io.ReadAll(io.LimitReader(request.Body, adapter.config.MaxRequestBytes+1))
	if err != nil {
		meldError(w, 400, "invalid_request", "Unable to read multipart request")
		return
	}
	if int64(len(body)) > adapter.config.MaxRequestBytes {
		meldError(w, 413, "resource_limit", "Meld request exceeds max_request_bytes; request was not dispatched")
		return
	}
	contract, err := parseMeldRequest(request.Header.Get("Content-Type"), body, request.URL.Path)
	if err != nil {
		meldError(w, 400, "invalid_request", err.Error())
		return
	}
	if binding != nil && request.URL.Path == "/v1/generations" && contract.model != binding.manifest.Model {
		meldError(w, 400, "invalid_request", "requested model does not match the operator-approved runtime manifest")
		return
	}
	upstream, err := http.NewRequestWithContext(request.Context(), http.MethodPost, strings.TrimRight(endpoint, "/")+request.URL.Path, bytes.NewReader(body))
	if err != nil {
		meldError(w, 502, "runtime_unavailable", "Unable to construct local runtime request")
		return
	}
	upstream.Header.Set("Content-Type", request.Header.Get("Content-Type"))
	if binding != nil {
		upstream.Header.Set(MeldManifestHeader, binding.digest)
		upstream.Header.Set(MeldNonceHeader, binding.nonce)
	}
	if request.URL.Path == "/v1/generations" {
		upstream.Header.Set("Accept", "image/png")
	} else {
		upstream.Header.Set("Accept", "application/json")
	}
	if token != "" {
		upstream.Header.Set("Authorization", "Bearer "+token)
	}
	// Only configured local credentials are forwarded. POSTs have no retry loop,
	// idempotency headers or continuation redirects.
	response, err := adapter.client.Do(upstream)
	if err != nil {
		status := 502
		if request.Context().Err() != nil {
			status = 408
		} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			status = 504
		}
		meldError(w, status, "runtime_unavailable", "Local runtime did not complete. This request was not replayed; check the runtime before explicitly resubmitting.")
		return
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		meldError(w, 502, "runtime_rejected", fmt.Sprintf("Local runtime returned HTTP %d; request was not replayed. Configure a direct local service URL, not a Modal continuation endpoint.", response.StatusCode))
		return
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, adapter.config.MaxResponseBytes+1))
	if err != nil || int64(len(result)) > adapter.config.MaxResponseBytes {
		meldError(w, 502, "invalid_runtime_response", "Local runtime response is incomplete or exceeds max_response_bytes")
		return
	}
	imageBackend, reviewBackend := "sdxl_ip_adapter", "qwen_vllm"
	if binding != nil {
		if err = validateMeldResultProof(response.Header, result, binding); err != nil {
			meldError(w, 502, "invalid_runtime_response", err.Error())
			return
		}
		imageBackend, reviewBackend = binding.manifest.Backend, binding.manifest.Backend
	}
	if request.URL.Path == "/v1/generations" {
		err = validateMeldImageBackend(response.Header, result, contract, imageBackend)
	} else {
		err = validateMeldReviewBackend(response.Header, result, contract.candidateHash, adapter.config.ReviewModel, reviewBackend)
	}
	if err != nil {
		meldError(w, 502, "invalid_runtime_response", err.Error())
		return
	}
	for _, header := range []string{MeldManifestHeader, MeldNonceHeader, MeldResultHeader, "Content-Type", "X-Request-ID", "X-Image-Preview", "X-Image-AI", "X-Image-Backend", "X-Image-Model", "X-Image-Seed", "X-Image-Provenance", "X-Reviewer-Backend", "X-Reviewer-Model", "X-Candidate-SHA256"} {
		if value := response.Header.Get(header); value != "" {
			w.Header().Set(header, value)
		}
	}
	w.WriteHeader(200)
	_, _ = w.Write(result)
}

type meldRequest struct {
	model         string
	width, height int
	candidateHash string
}

func parseMeldRequest(contentType string, body []byte, path string) (meldRequest, error) {
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "multipart/form-data" || parameters["boundary"] == "" {
		return meldRequest{}, errors.New("Meld requires multipart/form-data with a boundary")
	}
	reader := multipart.NewReader(bytes.NewReader(body), parameters["boundary"])
	fields := make(map[string]string)
	contract := meldRequest{}
	for count := 0; ; count++ {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 128 {
			return meldRequest{}, errors.New("Meld multipart is invalid or exceeds 128 parts")
		}
		switch part.FormName() {
		case "model", "width", "height":
			name := part.FormName()
			value, readErr := io.ReadAll(io.LimitReader(part, 1025))
			if _, duplicate := fields[name]; duplicate || readErr != nil || len(value) > 1024 {
				return meldRequest{}, errors.New("Meld model/dimension fields must be unique and at most 1024 bytes")
			}
			fields[name] = string(value)
		case "candidate":
			if path != "/v1/reviews" {
				break
			}
			if contract.candidateHash != "" {
				return meldRequest{}, errors.New("Meld review requires one candidate")
			}
			hash := sha256.New()
			n, err := io.Copy(hash, part)
			if err != nil || n == 0 {
				return meldRequest{}, errors.New("Meld review candidate is empty or unreadable")
			}
			contract.candidateHash = hex.EncodeToString(hash.Sum(nil))
		}
		if err := part.Close(); err != nil {
			return meldRequest{}, errors.New("Meld multipart is incomplete")
		}
	}
	if path == "/v1/reviews" {
		if contract.candidateHash == "" {
			return meldRequest{}, errors.New("Meld review requires a candidate image")
		}
		return contract, nil
	}
	contract.model = strings.TrimSpace(fields["model"])
	contract.width, _ = strconv.Atoi(fields["width"])
	contract.height, _ = strconv.Atoi(fields["height"])
	if contract.model == "" || contract.width < 1 || contract.width > 16384 || contract.height < 1 || contract.height > 16384 {
		return meldRequest{}, errors.New("Meld generation requires model, width and height (dimensions 1..16384)")
	}
	return contract, nil
}

func validateMeldImage(headers http.Header, body []byte, request meldRequest) error {
	return validateMeldImageBackend(headers, body, request, "sdxl_ip_adapter")
}
func validateMeldImageBackend(headers http.Header, body []byte, request meldRequest, backend string) error {
	contentType, _, _ := mime.ParseMediaType(headers.Get("Content-Type"))
	dimensions, format, err := image.DecodeConfig(bytes.NewReader(body))
	_, seedErr := strconv.ParseUint(strings.TrimSpace(headers.Get("X-Image-Seed")), 10, 32)
	provenance := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(headers.Get("X-Image-Provenance"))), "sha256:")
	hash, hashErr := hex.DecodeString(provenance)
	if contentType != "image/png" || err != nil || format != "png" || dimensions.Width != request.width || dimensions.Height != request.height || strings.ToLower(strings.TrimSpace(headers.Get("X-Image-Preview"))) != "false" || strings.ToLower(strings.TrimSpace(headers.Get("X-Image-AI"))) != "true" || strings.TrimSpace(headers.Get("X-Image-Backend")) != backend || strings.TrimSpace(headers.Get("X-Image-Model")) != request.model || seedErr != nil || hashErr != nil || len(hash) != 32 {
		return errors.New("Local image runtime did not return Meld's required PNG dimensions and approved backend attestation; preview or incompatible responses are rejected")
	}
	return nil
}

var meldIssueCategories = map[string]bool{
	"detached_anatomy": true, "malformed_anatomy": true, "extra_or_missing_parts": true, "multiple_people": true,
	"furniture_body_merge": true, "literal_unrequested_prop": true, "wardrobe_mismatch": true, "morphology_mismatch": true,
	"composition_mismatch": true, "embedded_text": true, "reference_leakage": true, "contact_sheet": true, "other_major_defect": true,
}

func validateMeldReview(headers http.Header, body []byte, candidateHash, expectedModel string) error {
	return validateMeldReviewBackend(headers, body, candidateHash, expectedModel, "qwen_vllm")
}
func validateMeldReviewBackend(headers http.Header, body []byte, candidateHash, expectedModel, backend string) error {
	var verdict struct {
		Accepted     *bool    `json:"accepted"`
		Issues       []string `json:"issues"`
		Summary      string   `json:"summary"`
		QualityScore *int     `json:"quality_score"`
	}
	contentType, _, _ := mime.ParseMediaType(headers.Get("Content-Type"))
	if json.Unmarshal(body, &verdict) != nil || contentType != "application/json" || verdict.Accepted == nil || verdict.Issues == nil || strings.TrimSpace(verdict.Summary) == "" || verdict.QualityScore == nil || *verdict.QualityScore < 0 || *verdict.QualityScore > 100 || (*verdict.Accepted && len(verdict.Issues) != 0) || (!*verdict.Accepted && len(verdict.Issues) == 0) || strings.TrimSpace(headers.Get("X-Reviewer-Backend")) != backend || strings.TrimSpace(headers.Get("X-Reviewer-Model")) != expectedModel || strings.TrimSpace(headers.Get("X-Candidate-SHA256")) != candidateHash {
		return errors.New("Local review runtime did not return Meld's required verdict and approved model/candidate attestation")
	}
	seen := make(map[string]bool)
	for _, issue := range verdict.Issues {
		if !meldIssueCategories[issue] || seen[issue] {
			return errors.New("Local review runtime returned unknown or duplicated Meld issue categories")
		}
		seen[issue] = true
	}
	return nil
}

func meldError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"type": "nucleus_workload_error", "code": code, "message": message}})
}

// RequestTimeout reports the validated budget for enabled bridge workloads.
// It does not indicate runtime or model readiness.
func (adapter *MeldAdapter) RequestTimeout() time.Duration {
	if adapter == nil || (adapter.config.GenerationURL == "" && adapter.config.ReviewURL == "") {
		return 0
	}
	return time.Duration(adapter.config.TimeoutSeconds) * time.Second
}
