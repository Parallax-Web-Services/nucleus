package inference

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This executable substitutes a protocol fixture for llama-server. Its timings
// are fixture data only and must never be published as real model benchmarks.
func TestMain(m *testing.M) {
	if os.Getenv("NUCLEUS_TEST_LLAMA") == "1" {
		fakeLlama()
		return
	}
	os.Exit(m.Run())
}
func fakeLlama() {
	for _, arg := range os.Args[1:] {
		if arg == "--version" {
			fmt.Println("llama.cpp fixture version - NOT A BENCHMARK")
			return
		}
	}
	values := map[string]string{}
	for i := 1; i+1 < len(os.Args); i++ {
		if strings.HasPrefix(os.Args[i], "--") {
			values[os.Args[i]] = os.Args[i+1]
		}
	}
	// Validate arguments in the spawned process, including budgets not exercised
	// by this HTTP fixture's tensor-free implementation.
	for flag, expected := range map[string]string{
		"--host": "127.0.0.1", "--parallel": "1", "--threads": "1",
		"--threads-batch": "1", "--threads-http": "2", "--ctx-size": "128",
		"--n-predict": "16", "--n-gpu-layers": "0", "--device": "none",
		"--cache-ram": "0", "--ctx-checkpoints": "0", "--prio": "-1",
	} {
		if values[flag] != expected {
			os.Exit(21)
		}
	}
	for _, flag := range []string{"--no-op-offload", "--no-kv-offload", "--no-context-shift", "--no-warmup", "--no-webui", "--no-slots", "--log-disable", "--perf"} {
		found := false
		for _, arg := range os.Args[1:] {
			if arg == flag {
				found = true
				break
			}
		}
		if !found {
			os.Exit(22)
		}
	}
	// Assert the real Linux subprocess inherited the hard address-space limit.
	limits, err := os.ReadFile("/proc/self/limits")
	if err != nil {
		os.Exit(23)
	}
	limited := false
	for _, line := range strings.Split(string(limits), "\n") {
		if strings.HasPrefix(line, "Max address space") {
			fields := strings.Fields(line)
			limited = len(fields) >= 6 && fields[3] != "unlimited" && fields[3] == fields[4]
		}
	}
	if !limited {
		os.Exit(24)
	}
	key, _ := os.ReadFile(values["--api-key-file"])
	secret := strings.TrimSpace(string(key))
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/models", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]string{{"id": values["--alias"]}}})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			w.WriteHeader(401)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, _ := json.Marshal(body["messages"])
		if bytes.Contains(raw, []byte("wait")) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
		timings := map[string]any{"prompt_n": 4, "prompt_ms": 20, "predicted_n": 2, "predicted_ms": 100}
		usage := map[string]int{"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}
		if body["stream"] == true {
			w.Header().Set("Content-Type", "text/event-stream")
			chunk, _ := json.Marshal(map[string]any{"id": "fixture", "model": values["--alias"], "choices": []map[string]any{{"index": 0, "delta": map[string]string{"content": "hello"}}}, "timings": timings, "usage": usage})
			fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", chunk)
		} else {
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "fixture", "model": values["--alias"], "choices": []map[string]any{{"index": 0, "message": map[string]string{"role": "assistant", "content": "hello"}, "finish_reason": "stop"}}, "timings": timings, "usage": usage})
		}
	})
	listener, err := net.Listen("tcp", net.JoinHostPort(values["--host"], values["--port"]))
	if err != nil {
		os.Exit(3)
	}
	_ = http.Serve(listener, mux)
}

func fixtureModel(t *testing.T) InstalledModel {
	t.Helper()
	var data bytes.Buffer
	data.WriteString("GGUF")
	_ = binary.Write(&data, binary.LittleEndian, uint32(3))
	_ = binary.Write(&data, binary.LittleEndian, uint64(1))
	_ = binary.Write(&data, binary.LittleEndian, uint64(7))
	putString := func(s string) { _ = binary.Write(&data, binary.LittleEndian, uint64(len(s))); data.WriteString(s) }
	putString("general.architecture")
	_ = binary.Write(&data, binary.LittleEndian, uint32(8))
	putString("llama")
	for _, entry := range []struct {
		k string
		n uint32
	}{{"general.file_type", 2}, {"llama.block_count", 2}, {"llama.embedding_length", 32}, {"llama.attention.head_count", 4}, {"llama.attention.head_count_kv", 1}, {"llama.context_length", 4096}} {
		putString(entry.k)
		_ = binary.Write(&data, binary.LittleEndian, uint32(4))
		_ = binary.Write(&data, binary.LittleEndian, entry.n)
	}
	path := filepath.Join(t.TempDir(), "fixture.gguf")
	if err := os.WriteFile(path, data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data.Bytes())
	return InstalledModel{Model: Model{Provenance: testModelProvenance(), ID: "fixture", Revision: "fixture-revision", Source: "test-fixture", License: "fixture only", Architecture: "llama", Format: "GGUF", Quantization: "Q4_0", SHA256: hex.EncodeToString(sum[:]), SizeBytes: uint64(data.Len()), RequiredMemoryBytes: 300 << 20, Workloads: []string{"text-generation"}, Runtime: "llama.cpp"}, Path: path}
}
func fixtureConfig(t *testing.T) RuntimeConfig {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := fixtureModel(t)
	return RuntimeConfig{ApprovedModels: testModelApprovals(m.Model), Binary: binary, Threads: 1, ContextLength: 128, MaxTokens: 16, MemoryLimitBytes: 1 << 50, StartupTimeoutSeconds: 3, Models: []InstalledModel{m}}
}
func TestGGUFIntegrityAndMemory(t *testing.T) {
	m := fixtureModel(t)
	info, err := InspectGGUF(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Architecture != "llama" || info.Version != 3 || info.Layers != 2 || info.KVHeads != 1 {
		t.Fatalf("wrong GGUF metadata: %#v", info)
	}
	if _, err = validateInstalled(m, 128); err != nil {
		t.Fatal(err)
	}
	broken := m
	broken.SHA256 = strings.Repeat("0", 64)
	if _, err = validateInstalled(broken, 128); err == nil {
		t.Fatal("wrong integrity hash accepted")
	}
	broken = m
	broken.RequiredMemoryBytes = m.SizeBytes
	if _, err = validateInstalled(broken, 128); err == nil {
		t.Fatal("model with insufficient KV/runtime memory accepted")
	}
	if _, err = validateInstalled(m, 8192); err == nil {
		t.Fatal("context exceeds training context")
	}
	if err = os.WriteFile(m.Path, []byte("not a GGUF"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectGGUF(m.Path); err == nil {
		t.Fatal("invalid GGUF accepted")
	}
}
func TestRuntimeSubprocessResourcePolicyStreamingReuseAndMetrics(t *testing.T) {
	t.Setenv("NUCLEUS_TEST_LLAMA", "1")
	backend, err := NewLlama(context.Background(), fixtureConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	r := backend.(*Llama)
	request := Request{Model: "fixture", Messages: []Message{{Role: "user", Content: "hello"}}, Stream: true, MaxTokens: 4}
	var first, second Metrics
	count := 0
	for attempt := 0; attempt < 2; attempt++ {
		err = backend.Run(context.Background(), request, func(e Event) error {
			if len(e.Data) > 0 {
				count++
				if !json.Valid(e.Data) {
					t.Fatal("invalid event JSON")
				}
			}
			if e.Done {
				if e.Metrics == nil {
					t.Fatal("missing metrics")
				}
				if attempt == 0 {
					first = *e.Metrics
				} else {
					second = *e.Metrics
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if count != 2 || first.ColdStartMS <= 0 || second.ColdStartMS != 0 || first.PromptTokensPerSecond != 200 || first.GenerationTokensPerSecond != 20 || first.PeakRSSBytes == 0 {
		t.Fatalf("unexpected fixture metrics (not benchmark): first=%+v second=%+v", first, second)
	}
	if r.process == nil {
		t.Fatal("model not retained")
	}
	if err = backend.Run(context.Background(), Request{Model: "fixture", Messages: request.Messages, MaxTokens: 999}, func(Event) error { return nil }); err == nil {
		t.Fatal("token budget not enforced")
	}
	if err = backend.Run(context.Background(), Request{Model: "unknown", Messages: request.Messages, MaxTokens: 4}, func(Event) error { return nil }); err == nil {
		t.Fatal("uninstalled model accepted")
	}
}
func TestRuntimeCancellationStopsProcess(t *testing.T) {
	t.Setenv("NUCLEUS_TEST_LLAMA", "1")
	backend, err := NewLlama(context.Background(), fixtureConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	// Complete one request so timeout measures an active request, not startup.
	request := Request{Model: "fixture", Messages: []Message{{Role: "user", Content: "hello"}}, MaxTokens: 4}
	if err = backend.Run(context.Background(), request, func(Event) error { return nil }); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request.Messages[0].Content = "wait"
	if err = backend.Run(ctx, request, func(Event) error { return nil }); err == nil {
		t.Fatal("cancelled request succeeded")
	}
	if backend.(*Llama).process != nil {
		t.Fatal("cancelled generation process retained")
	}
}
func TestRuntimePolicyAndSSE(t *testing.T) {
	cfg := fixtureConfig(t)
	cfg.Threads = 0
	if _, err := NewLlama(context.Background(), cfg); err == nil {
		t.Fatal("zero thread budget accepted")
	}
	cfg = fixtureConfig(t)
	cfg.MemoryLimitBytes = 256 << 20
	if _, err := NewLlama(context.Background(), cfg); err == nil {
		t.Fatal("model beyond memory limit accepted")
	}
	for _, wire := range []string{"data: {}\n\n", "data: invalid\n\ndata: [DONE]\n\n"} {
		err := readSSE(strings.NewReader(wire), func(v []byte) error {
			if !json.Valid(v) {
				return fmt.Errorf("invalid JSON")
			}
			return nil
		})
		if err == nil {
			t.Fatal("broken stream accepted")
		}
	}
	if err := readSSE(strings.NewReader(": ping\r\ndata: {\"ok\":true}\r\n\r\ndata: [DONE]\r\n\r\n"), func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	m := Metrics{}
	captureMetrics([]byte(`{"usage":{"prompt_tokens":100,"completion_tokens":10}}`), &m)
	if m.PromptTokensPerSecond != 0 || m.GenerationTokensPerSecond != 0 {
		t.Fatal("invented measured throughput without phase timings")
	}

}
