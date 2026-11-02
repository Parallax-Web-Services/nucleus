package inference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/inventory"
)

// RunWorker executes one leased text request at a time. Heartbeats continue
// independently during cold starts. Losing control contact cancels execution.
func RunWorker(ctx context.Context, backend Backend, control WorkerControl, cfg RuntimeConfig, benchmarks []Benchmark, onError func(error)) error {
	if backend == nil || control == nil {
		return errors.New("backend and worker control required")
	}
	for _, m := range backend.Models() {
		if err := ApproveModel(m, cfg.ApprovedModels); err != nil {
			return err
		}
	}
	version := ""
	if v, ok := backend.(interface{ RuntimeVersion() string }); ok {
		version = v.RuntimeVersion()
	}
	filtered := []Benchmark{}
	for _, b := range benchmarks {
		for _, m := range backend.Models() {
			if b.ModelID == m.ID && b.SHA256 == m.SHA256 && b.Revision == m.Revision && b.Quantization == m.Quantization && b.Metrics.Threads == cfg.Threads && b.Metrics.ContextLength == cfg.ContextLength && b.Metrics.RuntimeVersion == version {
				filtered = append(filtered, b)
			}
		}
	}
	benchmarks = filtered
	monitor := new(inventory.Monitor)
	var mu sync.Mutex
	warm := ""
	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}
	advertise := func() error {
		for _, m := range backend.Models() {
			if err := ApproveModel(m, cfg.ApprovedModels); err != nil {
				return err
			}
		}
		sample, err := monitor.Snapshot()
		if err != nil {
			return err
		}
		available := sample.Memory.AvailableBytes
		if sample.Memory.EffectiveTotalBytes > 0 {
			available = sample.Memory.EffectiveAvailableBytes
		}
		if available > cfg.ReserveMemoryBytes {
			available -= cfg.ReserveMemoryBytes
		} else {
			available = 0
		}
		cpu := 0.0
		if sample.CPU.UsagePercent != nil {
			cpu = *sample.CPU.UsagePercent
		}
		a := Advertisement{Threads: cfg.Threads, RuntimeVersion: version, Models: backend.Models(), AvailableMemoryBytes: available, MemoryLimitBytes: cfg.MemoryLimitBytes, CPUPercent: cpu, MaxConcurrent: 1, ContextLength: cfg.ContextLength, MaxTokens: cfg.MaxTokens, Benchmarks: benchmarks}
		mu.Lock()
		if warm != "" {
			a.WarmModels = []string{warm}
		}
		mu.Unlock()
		return control.Register(ctx, a)
	}
	// Owner startup and member disconnection share the same bounded retry path.
	report(advertise())
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				report(advertise())
			}
		}
	}()
	defer func() { <-heartbeatDone }()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			lease, err := control.Acquire(ctx)
			if err != nil {
				report(err)
				continue
			}
			if lease == nil {
				continue
			}
			if _, err := approveBackendModel(backend, lease.Request.Model, cfg.ApprovedModels); err != nil {
				_ = control.Push(ctx, lease.ID, Event{Done: true, Error: err.Error()})
				report(err)
				continue
			}
			mu.Lock()
			warm = ""
			mu.Unlock()
			jobCtx, cancel := context.WithDeadline(ctx, lease.Deadline)
			done := make(chan error, 1)
			go func() {
				done <- backend.Run(jobCtx, lease.Request, func(e Event) error { return control.Push(jobCtx, lease.ID, e) })
			}()
			check := time.NewTicker(300 * time.Millisecond)
			finished := false
			for !finished {
				select {
				case <-ctx.Done():
					cancel()
					<-done
					finished = true
				case err = <-done:
					if err != nil {
						report(err)
						pushCtx, stop := context.WithTimeout(ctx, 3*time.Second)
						_ = control.Push(pushCtx, lease.ID, Event{Done: true, Error: err.Error()})
						stop()
					} else {
						mu.Lock()
						warm = lease.Request.Model
						mu.Unlock()
					}
					finished = true
				case <-check.C:
					j, checkErr := control.Job(jobCtx, lease.ID)
					if checkErr != nil || j.Status != "running" {
						cancel()
					}
				}
			}
			check.Stop()
			cancel()
		}
	}
}

// BenchmarkBackend is invoked only by the explicit benchmark CLI. Model/runtime
// association is retained; missing phase timing is an error, never an estimate.
func BenchmarkBackend(ctx context.Context, backend Backend, model, prompt string, maxTokens int, approvals []ModelApproval) (Benchmark, error) {
	var selected *Model
	for _, m := range backend.Models() {
		if m.ID == model {
			copy := m
			selected = &copy
			break
		}
	}
	if selected == nil {
		return Benchmark{}, errors.New("benchmark model is not explicitly provisioned")
	}
	if err := ApproveModel(*selected, approvals); err != nil {
		return Benchmark{}, err
	}
	var measured *Metrics
	req := Request{Model: model, Messages: []Message{{Role: "user", Content: prompt}}, Stream: true, MaxTokens: maxTokens}
	err := backend.Run(ctx, req, func(e Event) error {
		if e.Error != "" {
			return errors.New(e.Error)
		}
		if e.Metrics != nil {
			copy := *e.Metrics
			measured = &copy
		}
		return nil
	})
	if err != nil {
		return Benchmark{}, err
	}
	if measured == nil || measured.PromptTokens < 1 || measured.GenerationTokens < 1 || measured.PromptMS <= 0 || measured.GenerationMS <= 0 {
		return Benchmark{}, errors.New("runtime did not provide actual prompt/generation phase timings; benchmark not recorded")
	}
	return Benchmark{ModelID: model, Revision: selected.Revision, SHA256: selected.SHA256, Quantization: selected.Quantization, MeasuredAt: time.Now().UTC(), Metrics: *measured}, nil
}
func ReadBenchmarks(home string) []Benchmark {
	path := filepath.Join(home, "inference-benchmarks.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var results []Benchmark
	if err = decodeStrict(io.LimitReader(f, 256<<10), &results); err != nil || len(results) > 64 {
		return nil
	}
	return results
}
func SaveBenchmark(home string, b Benchmark) error {
	results := ReadBenchmarks(home)
	filtered := []Benchmark{}
	for _, v := range results {
		if v.ModelID != b.ModelID || v.SHA256 != b.SHA256 || v.Metrics.Threads != b.Metrics.Threads || v.Metrics.ContextLength != b.Metrics.ContextLength {
			filtered = append(filtered, v)
		}
	}
	filtered = append(filtered, b)
	if len(filtered) > 64 {
		filtered = filtered[len(filtered)-64:]
	}
	data, err := json.MarshalIndent(filtered, "", "  ")
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(home, ".inference-benchmarks-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(home, "inference-benchmarks.json")); err != nil {
		return fmt.Errorf("save measured benchmark: %w", err)
	}
	return nil
}

func approveBackendModel(backend Backend, id string, approvals []ModelApproval) (Model, error) {
	for _, m := range backend.Models() {
		if m.ID == id {
			return m, ApproveModel(m, approvals)
		}
	}
	return Model{}, errors.New("requested model is not installed in this backend")
}
