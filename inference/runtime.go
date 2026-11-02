package inference

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/inventory"
)

// RuntimeConfig is an explicit local execution policy, never remotely supplied.
// MemoryLimitBytes is a hard Linux address-space limit, and ReserveMemoryBytes
// is RAM left available to the host before a cold load.
type RuntimeConfig struct {
	ApprovedModels        []ModelApproval  `json:"-"`
	Binary                string           `json:"binary"`
	Threads               int              `json:"threads"`
	ContextLength         int              `json:"context_length"`
	MaxTokens             int              `json:"max_tokens"`
	MemoryLimitBytes      uint64           `json:"memory_limit_bytes"`
	ReserveMemoryBytes    uint64           `json:"reserve_memory_bytes"`
	StartupTimeoutSeconds int              `json:"startup_timeout_seconds"`
	Models                []InstalledModel `json:"models"`
}

type llamaProcess struct {
	cmd      *exec.Cmd
	done     chan struct{}
	err      error
	model    string
	endpoint string
	key      string
	keyDir   string
}

type Llama struct {
	cfg     RuntimeConfig
	version string
	prlimit string
	ctx     context.Context
	cancel  context.CancelFunc
	gate    chan struct{}
	mu      sync.Mutex
	process *llamaProcess
	models  []InstalledModel
}

// NewLlama validates only explicitly provisioned files. Loading is lazy and
// happens on an authorized request, never as an automatic workstation benchmark.
func NewLlama(ctx context.Context, cfg RuntimeConfig) (Backend, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("CPU runtime requires Linux or WSL2")
	}
	if !filepath.IsAbs(cfg.Binary) {
		return nil, errors.New("llama-server binary must have an absolute local path")
	}
	info, err := os.Stat(cfg.Binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("llama-server binary must be a local executable regular file")
	}
	if cfg.Threads < 1 || cfg.Threads > runtime.NumCPU() {
		return nil, errors.New("threads must be positive and no greater than available logical CPUs")
	}
	if cfg.ContextLength < 128 || cfg.ContextLength > 131072 || cfg.MaxTokens < 1 || cfg.MaxTokens >= cfg.ContextLength {
		return nil, errors.New("invalid context length or generation token budget")
	}
	if cfg.MemoryLimitBytes < 256<<20 || cfg.MemoryLimitBytes > 1<<60 || cfg.ReserveMemoryBytes > 1<<60 {
		return nil, errors.New("invalid runtime memory limit or host reserve")
	}
	if cfg.StartupTimeoutSeconds == 0 {
		cfg.StartupTimeoutSeconds = 120
	}
	if cfg.StartupTimeoutSeconds < 1 || cfg.StartupTimeoutSeconds > 1800 {
		return nil, errors.New("startup timeout must be 1..1800 seconds")
	}
	if len(cfg.Models) < 1 || len(cfg.Models) > 32 {
		return nil, errors.New("runtime requires 1..32 explicitly installed models")
	}
	cfg.ApprovedModels = cloneApprovals(cfg.ApprovedModels)
	models := make([]InstalledModel, 0, len(cfg.Models))
	seen := map[string]bool{}
	for _, m := range cfg.Models {
		m.Model = cloneModel(m.Model)
		checked, e := validateApprovedInstalled(m, cfg.ContextLength, cfg.ApprovedModels)
		if e != nil {
			return nil, fmt.Errorf("model %q: %w", m.ID, e)
		}
		if seen[m.ID] {
			return nil, errors.New("duplicate model identifier")
		}
		seen[m.ID] = true
		if checked.RequiredMemoryBytes > cfg.MemoryLimitBytes {
			return nil, fmt.Errorf("model %q exceeds runtime memory limit", m.ID)
		}
		models = append(models, checked)
	}
	prlimit, err := exec.LookPath("prlimit")
	if err != nil {
		return nil, errors.New("util-linux prlimit is required for a hard subprocess memory limit")
	}
	versionCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	command := exec.CommandContext(versionCtx, cfg.Binary, "--version")
	command.Env = runtimeEnvironment()
	var output boundedOutput
	command.Stdout = &output
	command.Stderr = &output
	if err = command.Run(); err != nil {
		return nil, fmt.Errorf("llama-server version probe failed: %w", err)
	}
	version := strings.TrimSpace(output.String())
	if version == "" {
		return nil, errors.New("llama-server did not report a version")
	}
	life, cancel := context.WithCancel(ctx)
	r := &Llama{cfg: cfg, version: version, prlimit: prlimit, ctx: life, cancel: cancel, gate: make(chan struct{}, 1), models: models}
	r.gate <- struct{}{}
	return r, nil
}

func NewRuntime(ctx context.Context, cfg RuntimeConfig) (Backend, error) { return NewLlama(ctx, cfg) }
func (r *Llama) Models() []Model {
	result := make([]Model, 0, len(r.models))
	for _, m := range r.models {
		copy := cloneModel(m.Model)
		result = append(result, copy)
	}
	return result
}
func (r *Llama) Close() error {
	r.cancel()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	return nil
}
func (r *Llama) stopLocked() {
	p := r.process
	r.process = nil
	if p == nil {
		return
	}
	_ = p.cmd.Process.Kill()
	<-p.done
	_ = os.RemoveAll(p.keyDir)
}

// Run serializes access to one resident model. Cancellation terminates the
// subprocess so a cancelled slot cannot continue consuming CPU invisibly.
func (r *Llama) Run(ctx context.Context, request Request, emit func(Event) error) (runErr error) {
	if emit == nil {
		return errors.New("event consumer is required")
	}
	if request.MaxTokens == 0 {
		request.MaxTokens = r.cfg.MaxTokens
	}
	if err := validateRuntimeRequest(request, r.cfg.MaxTokens); err != nil {
		return err
	}
	if _, err := approveBackendModel(r, request.Model, r.cfg.ApprovedModels); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.ctx.Done():
		return errors.New("runtime is closed")
	case <-r.gate:
	}
	defer func() { r.gate <- struct{}{} }()
	runCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.ctx, cancel)
	defer stop()
	defer cancel()
	started := time.Now()
	p, cold, err := r.ensure(runCtx, request.Model)
	if err != nil {
		return err
	}
	metrics := Metrics{ColdStartMS: float64(cold) / float64(time.Millisecond), RuntimeVersion: r.version, Threads: r.cfg.Threads, ContextLength: r.cfg.ContextLength, MaxTokens: request.MaxTokens}
	defer func() {
		if runErr != nil {
			r.mu.Lock()
			if r.process == p {
				r.stopLocked()
			}
			r.mu.Unlock()
		}
	}()
	sampleCtx, sampleCancel := context.WithCancel(runCtx)
	defer sampleCancel()
	var peak uint64
	var sampleMu sync.Mutex
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			rss := processRSS(p.cmd.Process.Pid)
			sampleMu.Lock()
			if rss > peak {
				peak = rss
			}
			sampleMu.Unlock()
			if rss > r.cfg.MemoryLimitBytes {
				cancel()
				return
			}
			select {
			case <-sampleCtx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	payload := map[string]any{"model": request.Model, "messages": request.Messages, "stream": request.Stream, "max_tokens": request.MaxTokens, "cache_prompt": false}
	if request.Temperature != nil {
		payload["temperature"] = *request.Temperature
	}
	if len(request.ResponseFormat) > 0 {
		var format any
		if err = json.Unmarshal(request.ResponseFormat, &format); err != nil {
			return err
		}
		payload["response_format"] = format
	}
	if request.Stream {
		payload["stream_options"] = map[string]bool{"include_usage": true}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(runCtx, http.MethodPost, p.endpoint+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Content-Type", "application/json")
	client := localHTTPClient()
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("CPU inference request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("llama.cpp rejected inference (%d): %s", response.StatusCode, strings.TrimSpace(string(data)))
	}
	consume := func(data []byte) error {
		if !json.Valid(data) {
			return errors.New("llama.cpp returned invalid JSON")
		}
		var failure struct {
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(data, &failure) != nil {
			return errors.New("runtime response is not a JSON object")
		}
		if len(failure.Error) > 0 && string(failure.Error) != "null" {
			return errors.New("llama.cpp reported an inference error")
		}
		captureMetrics(data, &metrics)
		return emit(Event{Data: append(json.RawMessage(nil), data...)})
	}
	if request.Stream {
		if !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
			return errors.New("llama.cpp did not return SSE")
		}
		if err = readSSE(response.Body, consume); err != nil {
			return err
		}
	} else {
		data, e := io.ReadAll(io.LimitReader(response.Body, 8<<20+1))
		if e != nil {
			return e
		}
		if len(data) > 8<<20 {
			return errors.New("llama.cpp response exceeds 8 MiB")
		}
		if err = consume(data); err != nil {
			return err
		}
	}
	sampleCancel()
	<-sampled
	sampleMu.Lock()
	metrics.PeakRSSBytes = peak
	sampleMu.Unlock()
	metrics.ElapsedMS = float64(time.Since(started)) / float64(time.Millisecond)
	return emit(Event{Done: true, Metrics: &metrics})
}

func validateRuntimeRequest(r Request, maxTokens int) error {
	if r.Model == "" || len(r.Messages) < 1 || len(r.Messages) > 256 {
		return errors.New("model and 1..256 text messages are required")
	}
	total := 0
	for _, m := range r.Messages {
		if m.Role != "system" && m.Role != "user" && m.Role != "assistant" && m.Role != "developer" {
			return errors.New("unsupported message role")
		}
		total += len(m.Content)
	}
	if total > 1<<20 {
		return errors.New("prompt exceeds 1 MiB")
	}
	if r.MaxTokens < 1 || r.MaxTokens > maxTokens {
		return fmt.Errorf("max_tokens must be 1..%d", maxTokens)
	}
	if r.Temperature != nil && (math.IsNaN(*r.Temperature) || math.IsInf(*r.Temperature, 0) || *r.Temperature < 0 || *r.Temperature > 2) {
		return errors.New("temperature must be finite and in 0..2")
	}
	if len(r.ResponseFormat) > 64<<10 || len(r.ResponseFormat) > 0 && !json.Valid(r.ResponseFormat) {
		return errors.New("invalid or oversized response_format")
	}
	return nil
}

func (r *Llama) ensure(ctx context.Context, id string) (*llamaProcess, time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	if err := r.ctx.Err(); err != nil {
		return nil, 0, errors.New("runtime is closed")
	}
	if r.process != nil && r.process.model == id {
		select {
		case <-r.process.done:
			r.stopLocked()
		default:
			return r.process, 0, nil
		}
	}
	var model *InstalledModel
	for i := range r.models {
		if r.models[i].ID == id {
			model = &r.models[i]
			break
		}
	}
	if model == nil {
		return nil, 0, errors.New("model is not installed on this worker; provision explicitly")
	}
	began := time.Now()
	r.stopLocked()
	if _, err := validateApprovedInstalled(*model, r.cfg.ContextLength, r.cfg.ApprovedModels); err != nil {
		return nil, 0, fmt.Errorf("revalidate model before loading: %w", err)
	}
	snapshot, err := new(inventory.Monitor).Snapshot()
	if err != nil {
		return nil, 0, err
	}
	if snapshot.CPU.EffectiveCores > 0 && float64(r.cfg.Threads) > math.Ceil(snapshot.CPU.EffectiveCores) {
		return nil, 0, errors.New("configured threads exceed effective cgroup CPU capacity")
	}
	available := snapshot.Memory.AvailableBytes
	if snapshot.Memory.EffectiveTotalBytes > 0 {
		available = snapshot.Memory.EffectiveAvailableBytes
	}
	if model.RequiredMemoryBytes > available || r.cfg.ReserveMemoryBytes > available-model.RequiredMemoryBytes {
		return nil, 0, errors.New("insufficient available RAM after the configured host reserve")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return nil, 0, err
	}
	key := hex.EncodeToString(random)
	directory, err := os.MkdirTemp("", "nucleus-llama-")
	if err != nil {
		return nil, 0, err
	}
	keyFile := filepath.Join(directory, "api-key")
	if err = os.WriteFile(keyFile, []byte(key+"\n"), 0600); err != nil {
		_ = os.RemoveAll(directory)
		return nil, 0, err
	}
	args := []string{"--as=" + strconv.FormatUint(r.cfg.MemoryLimitBytes, 10), "--", r.cfg.Binary, "--model", model.Path, "--alias", model.ID, "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--api-key-file", keyFile, "--threads", strconv.Itoa(r.cfg.Threads), "--threads-batch", strconv.Itoa(r.cfg.Threads), "--threads-http", "2", "--ctx-size", strconv.Itoa(r.cfg.ContextLength), "--n-predict", strconv.Itoa(r.cfg.MaxTokens), "--parallel", "1", "--n-gpu-layers", "0", "--device", "none", "--no-op-offload", "--no-kv-offload", "--cache-ram", "0", "--ctx-checkpoints", "0", "--no-context-shift", "--no-warmup", "--no-webui", "--no-slots", "--log-disable", "--perf", "--prio", "-1"}
	command := exec.CommandContext(r.ctx, r.prlimit, args...)
	command.Env = runtimeEnvironment()
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err = command.Start(); err != nil {
		_ = os.RemoveAll(directory)
		return nil, 0, err
	}
	p := &llamaProcess{cmd: command, done: make(chan struct{}), model: id, endpoint: fmt.Sprintf("http://127.0.0.1:%d", port), key: key, keyDir: directory}
	go func() { p.err = command.Wait(); close(p.done) }()
	r.process = p
	readyCtx, cancel := context.WithTimeout(ctx, time.Duration(r.cfg.StartupTimeoutSeconds)*time.Second)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	client := localHTTPClient()
	defer client.CloseIdleConnections()
	for {
		select {
		case <-p.done:
			r.stopLocked()
			return nil, 0, fmt.Errorf("llama-server exited during load (%v); check CPU instruction compatibility, model support and address-space budget", p.err)
		case <-readyCtx.Done():
			r.stopLocked()
			return nil, 0, fmt.Errorf("llama-server initialization: %w", readyCtx.Err())
		case <-ticker.C:
			probeCtx, stop := context.WithTimeout(readyCtx, time.Second)
			request, _ := http.NewRequestWithContext(probeCtx, http.MethodGet, p.endpoint+"/v1/models", nil)
			request.Header.Set("Authorization", "Bearer "+key)
			response, e := client.Do(request)
			if e == nil {
				data, _ := io.ReadAll(io.LimitReader(response.Body, 64<<10))
				response.Body.Close()
				if response.StatusCode == http.StatusOK {
					var list struct {
						Data []struct {
							ID string `json:"id"`
						} `json:"data"`
					}
					if json.Unmarshal(data, &list) == nil {
						for _, m := range list.Data {
							if m.ID == id {
								stop()
								return p, time.Since(began), nil
							}
						}
					}
				}
			}
			stop()
		}
	}
}

func localHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("local runtime redirects are disabled") }}
}

func runtimeEnvironment() []string {
	result := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(key)
		if strings.HasPrefix(upper, "LLAMA_") || strings.HasPrefix(upper, "HF_") || strings.Contains(upper, "PROXY") {
			continue
		}
		result = append(result, entry)
	}
	return append(result, "HF_HUB_OFFLINE=1")
}

type boundedOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if len(b.data) < 4096 {
		take := 4096 - len(b.data)
		if take > n {
			take = n
		}
		b.data = append(b.data, p[:take]...)
	}
	return n, nil
}
func (b *boundedOutput) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

// readSSE accepts full SSE framing and refuses success on a truncated stream.
func readSSE(reader io.Reader, consume func([]byte) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	var data []byte
	flush := func() (bool, error) {
		if len(data) == 0 {
			return false, nil
		}
		value := bytes.TrimSuffix(data, []byte("\n"))
		data = nil
		if bytes.Equal(value, []byte("[DONE]")) {
			return true, nil
		}
		return false, consume(value)
	}
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			done, err := flush()
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			value := strings.TrimPrefix(line, "data:")
			value = strings.TrimPrefix(value, " ")
			if len(data)+len(value) > 2<<20 {
				return errors.New("runtime SSE event exceeds 2 MiB")
			}
			data = append(data, value...)
			data = append(data, '\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	done, err := flush()
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	return errors.New("llama.cpp stream disconnected before [DONE]")
}

func captureMetrics(data []byte, m *Metrics) {
	var body struct {
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
		} `json:"usage"`
		Timings struct {
			PromptN     int     `json:"prompt_n"`
			PredictedN  int     `json:"predicted_n"`
			PromptMS    float64 `json:"prompt_ms"`
			PredictedMS float64 `json:"predicted_ms"`
		} `json:"timings"`
	}
	if json.Unmarshal(data, &body) != nil {
		return
	}
	if body.Usage.Prompt > 0 {
		m.PromptTokens = body.Usage.Prompt
	}
	if body.Usage.Completion > 0 {
		m.GenerationTokens = body.Usage.Completion
	}
	if body.Timings.PromptN >= 0 && body.Timings.PromptMS > 0 && !math.IsInf(body.Timings.PromptMS, 0) {
		m.PromptMS = body.Timings.PromptMS
		m.PromptTokensPerSecond = 1000 * float64(body.Timings.PromptN) / body.Timings.PromptMS
		if m.PromptTokens == 0 {
			m.PromptTokens = body.Timings.PromptN
		}
	}
	if body.Timings.PredictedN >= 0 && body.Timings.PredictedMS > 0 && !math.IsInf(body.Timings.PredictedMS, 0) {
		m.GenerationMS = body.Timings.PredictedMS
		m.GenerationTokensPerSecond = 1000 * float64(body.Timings.PredictedN) / body.Timings.PredictedMS
		if m.GenerationTokens == 0 {
			m.GenerationTokens = body.Timings.PredictedN
		}
	}
}
func processRSS(pid int) uint64 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	var current, peak uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			n, _ := strconv.ParseUint(fields[1], 10, 64)
			if n > math.MaxUint64/1024 {
				continue
			}
			switch fields[0] {
			case "VmRSS:":
				current = n * 1024
			case "VmHWM:":
				peak = n * 1024
			}
		}
	}
	if peak > current {
		return peak
	}
	return current
}
func (r *Llama) RuntimeVersion() string { return r.version }
