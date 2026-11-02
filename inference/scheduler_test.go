package inference

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func schedulerModel() Model {
	return Model{Provenance: testModelProvenance(), ID: "text-model", Revision: "revision-1", Source: "explicit-local-file", License: "test-fixture-only", Architecture: "llama", Format: "GGUF", Quantization: "Q4_K_M", SHA256: strings.Repeat("a", 64), SizeBytes: 512, RequiredMemoryBytes: 1024, Workloads: []string{"text-generation"}, Runtime: "llama.cpp"}
}
func schedulerAdvertisement() Advertisement {
	return Advertisement{Models: []Model{schedulerModel()}, AvailableMemoryBytes: 2048, MemoryLimitBytes: 4096, CPUPercent: 10, MaxConcurrent: 1, ContextLength: 512, MaxTokens: 128, Threads: 2, RuntimeVersion: "build-1"}
}
func schedulerRequest() Request {
	return Request{Model: "text-model", Messages: []Message{{Role: "user", Content: "protocol test"}}, Stream: true, MaxTokens: 32}
}
func newSchedulerFixture(t *testing.T, cfg FleetConfig) (*Scheduler, *time.Time, map[string]bool) {
	t.Helper()
	cfg.AllowedWorkers = []string{"a", "b"}
	if cfg.ApprovedModels == nil {
		m := schedulerModel()
		cfg.ApprovedModels = testModelApprovals(m)
		m.SHA256 = strings.Repeat("b", 64)
		cfg.ApprovedModels = append(cfg.ApprovedModels, testModelApprovals(m)...)
	}
	allowed := map[string]bool{"owner": true, "a": true, "b": true, "not-authorized-for-work": true}
	s, err := NewScheduler("owner", cfg, func(id string) bool { return allowed[id] })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	return s, &now, allowed
}
func schedulerRegister(t *testing.T, s *Scheduler, id string, a Advertisement) {
	t.Helper()
	if err := s.Register(id, a); err != nil {
		t.Fatal(err)
	}
}
func schedulerSubmit(t *testing.T, s *Scheduler) (JobView, <-chan Event) {
	t.Helper()
	j, e, err := s.Submit(context.Background(), schedulerRequest())
	if err != nil {
		t.Fatal(err)
	}
	return j, e
}

func TestSchedulerPlacementEligibility(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*Advertisement, *Request)
		advance time.Duration
		reason  string
	}{
		{name: "insufficient memory", change: func(a *Advertisement, r *Request) { a.AvailableMemoryBytes = 512 }, reason: "insufficient available memory"},
		{name: "overloaded", change: func(a *Advertisement, r *Request) { a.CPUPercent = 90 }, reason: "CPU load"},
		{name: "disconnected", advance: 4 * time.Second, reason: "heartbeat expired"},
		{name: "placement restriction", change: func(a *Advertisement, r *Request) { r.AllowedNodes = []string{"b"} }, reason: "placement restriction"},
		{name: "unprovisioned", change: func(a *Advertisement, r *Request) { r.Model = "missing" }, reason: "not provisioned"},
		{name: "token policy", change: func(a *Advertisement, r *Request) { r.MaxTokens = 129 }, reason: "max_tokens"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, now, _ := newSchedulerFixture(t, FleetConfig{WorkerTTLSeconds: 3})
			a, r := schedulerAdvertisement(), schedulerRequest()
			if test.change != nil {
				test.change(&a, &r)
			}
			schedulerRegister(t, s, "a", a)
			*now = now.Add(test.advance)
			if _, _, err := s.Submit(context.Background(), r); err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("expected %s: %v", test.reason, err)
			}
		})
	}
}

func TestSchedulerAuthorizationAndBackendExtensibility(t *testing.T) {
	s, _, members := newSchedulerFixture(t, FleetConfig{})
	a := schedulerAdvertisement()
	if s.Register("unknown", a) == nil || s.Register("not-authorized-for-work", a) == nil {
		t.Fatal("unauthorized worker registered")
	}
	a.Models[0].Runtime = "openvino"
	a.Models[0].Format = "ONNX"
	schedulerRegister(t, s, "a", a)
	j, _ := schedulerSubmit(t, s)
	if j.NodeID != "a" {
		t.Fatal("generic backend not eligible")
	}
	members["a"] = false
	if lease, err := s.Acquire("a"); err == nil || lease != nil {
		t.Fatal("revoked worker acquired request")
	}
	if _, _, err := s.Submit(context.Background(), schedulerRequest()); err == nil {
		t.Fatal("revoked worker remained eligible")
	}
}

func TestSchedulerRejectsInvalidWorkerLimits(t *testing.T) {
	for _, change := range []func(*Advertisement){
		func(a *Advertisement) { a.MaxConcurrent = 2 }, func(a *Advertisement) { a.Threads = 0 }, func(a *Advertisement) { a.MemoryLimitBytes = 512 },
		func(a *Advertisement) { a.CPUPercent = math.NaN() }, func(a *Advertisement) { a.Models[0].Workloads = []string{"embeddings"} },
	} {
		s, _, _ := newSchedulerFixture(t, FleetConfig{})
		a := schedulerAdvertisement()
		change(&a)
		if s.Register("a", a) == nil {
			t.Fatal("invalid resource or workload policy accepted")
		}
	}
}

func TestSchedulerDistributesRequestsAndBoundsQueue(t *testing.T) {
	s, _, _ := newSchedulerFixture(t, FleetConfig{QueueLimit: 2})
	schedulerRegister(t, s, "a", schedulerAdvertisement())
	schedulerRegister(t, s, "b", schedulerAdvertisement())
	first, _ := schedulerSubmit(t, s)
	lease, err := s.Acquire(first.NodeID)
	if err != nil || lease == nil || lease.ID != first.ID {
		t.Fatal("first request not leased")
	}
	second, _ := schedulerSubmit(t, s)
	if first.NodeID == second.NodeID {
		t.Fatal("independent requests not distributed")
	}
	if lease, err = s.Acquire(second.NodeID); err != nil || lease == nil || lease.ID != second.ID {
		t.Fatal("second request not leased")
	}
	if lease, err = s.Acquire(first.NodeID); err != nil || lease != nil {
		t.Fatal("busy worker exceeded concurrency budget")
	}
	queued, _ := schedulerSubmit(t, s)
	schedulerSubmit(t, s)
	if _, _, err = s.Submit(context.Background(), schedulerRequest()); err == nil || !strings.Contains(err.Error(), "queue full") {
		t.Fatal("queue limit not enforced")
	}
	if !s.Cancel(queued.ID) || !s.Cancel(first.ID) {
		t.Fatal("cancellation failed")
	}
	j, _ := s.Job(first.ID)
	if j.Status != "cancelled" {
		t.Fatal("running request not cancelled")
	}
	nodes, _ := s.Status()
	for _, node := range nodes {
		if node.NodeID == first.NodeID && node.Active != 0 {
			t.Fatal("reservation not released")
		}
	}
}

func TestSchedulerOnlyUnleasedRequestsMayFailOver(t *testing.T) {
	for _, running := range []bool{false, true} {
		name := "queued"
		if running {
			name = "running"
		}
		t.Run(name, func(t *testing.T) {
			s, now, _ := newSchedulerFixture(t, FleetConfig{WorkerTTLSeconds: 3})
			schedulerRegister(t, s, "a", schedulerAdvertisement())
			schedulerRegister(t, s, "b", schedulerAdvertisement())
			j, events := schedulerSubmit(t, s)
			if running {
				if lease, err := s.Acquire("a"); err != nil || lease == nil {
					t.Fatal("initial lease failed")
				}
			}
			*now = now.Add(4 * time.Second)
			schedulerRegister(t, s, "b", schedulerAdvertisement())
			lease, err := s.Acquire("b")
			if err != nil {
				t.Fatal(err)
			}
			if running {
				if lease != nil {
					t.Fatal("running request transparently replayed")
				}
				view, _ := s.Job(j.ID)
				if view.Status != "failed" || !strings.Contains(view.Error, "not replayed") {
					t.Fatalf("disconnect state: %#v", view)
				}
				if event := <-events; event.Error == "" {
					t.Fatal("disconnect error not delivered")
				}
			} else if lease == nil || lease.ID != j.ID {
				t.Fatal("unleased request did not fail over")
			}
		})
	}
}

func TestSchedulerContextCancellationAndTimeout(t *testing.T) {
	s, now, _ := newSchedulerFixture(t, FleetConfig{RequestTimeoutSeconds: 1})
	schedulerRegister(t, s, "a", schedulerAdvertisement())
	ctx, cancel := context.WithCancel(context.Background())
	j, events, err := s.Submit(ctx, schedulerRequest())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Acquire("a"); err != nil {
		t.Fatal(err)
	}
	cancel()
	view, _ := s.Job(j.ID)
	if view.Status != "cancelled" {
		t.Fatalf("cancel state %s", view.Status)
	}
	if event := <-events; event.Error == "" {
		t.Fatal("cancel error absent")
	}
	if s.Push("a", j.ID, Event{Data: json.RawMessage(`{}`)}) == nil {
		t.Fatal("cancelled request accepted output")
	}
	later, _ := schedulerSubmit(t, s)
	*now = now.Add(2 * time.Second)
	view, _ = s.Job(later.ID)
	if view.Status != "timed_out" {
		t.Fatalf("timeout state %s", view.Status)
	}
}

func TestSchedulerBackpressureAlwaysDeliversTerminalError(t *testing.T) {
	s, _, _ := newSchedulerFixture(t, FleetConfig{})
	schedulerRegister(t, s, "a", schedulerAdvertisement())
	j, events := schedulerSubmit(t, s)
	if _, err := s.Acquire("a"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 127; i++ {
		if err := s.Push("a", j.ID, Event{Data: json.RawMessage(`{"choices":[]}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if s.Push("a", j.ID, Event{Data: json.RawMessage(`{"choices":[]}`)}) == nil {
		t.Fatal("backpressure not enforced")
	}
	var last Event
	count := 0
	for event := range events {
		last = event
		count++
	}
	if count != 128 || !last.Done || !strings.Contains(last.Error, "consume stream") {
		t.Fatalf("terminal error lost after %d events: %#v", count, last)
	}
}

func TestSchedulerBoundsTotalOutputAndPreservesFinalData(t *testing.T) {
	s, _, _ := newSchedulerFixture(t, FleetConfig{})
	schedulerRegister(t, s, "a", schedulerAdvertisement())
	j, events := schedulerSubmit(t, s)
	_, _ = s.Acquire("a")
	payload := json.RawMessage(`"` + strings.Repeat("x", (1<<20)-2) + `"`)
	for i := 0; i < 8; i++ {
		if err := s.Push("a", j.ID, Event{Data: payload}); err != nil {
			t.Fatal(err)
		}
		<-events
	}
	if s.Push("a", j.ID, Event{Data: json.RawMessage(`"x"`)}) == nil {
		t.Fatal("8MiB output budget exceeded")
	}
	if event := <-events; !strings.Contains(event.Error, "8 MiB") {
		t.Fatalf("output error absent: %#v", event)
	}
	next, nextEvents := schedulerSubmit(t, s)
	_, _ = s.Acquire("a")
	if err := s.Push("a", next.ID, Event{Data: json.RawMessage(`{"choices":[]}`), Done: true}); err != nil {
		t.Fatal(err)
	}
	if data := <-nextEvents; len(data.Data) == 0 || data.Done {
		t.Fatal("final data lost")
	}
	if done := <-nextEvents; !done.Done || done.Error != "" {
		t.Fatal("completion lost")
	}
}

func schedulerBenchmark(now time.Time) Benchmark {
	m := schedulerModel()
	return Benchmark{ModelID: m.ID, Revision: m.Revision, SHA256: m.SHA256, Quantization: m.Quantization, MeasuredAt: now,
		Metrics: Metrics{PromptTokens: 10, GenerationTokens: 10, PromptMS: 100, GenerationMS: 100, PromptTokensPerSecond: 100, GenerationTokensPerSecond: 100, RuntimeVersion: "build-1", Threads: 2, ContextLength: 512, MaxTokens: 32}}
}

func TestSchedulerBenchmarkRankingRequiresIdentityAndSettings(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Benchmark)
		want   string
	}{
		{name: "matching", want: "b"},
		{name: "stale threads", change: func(b *Benchmark) { b.Metrics.Threads = 1 }, want: "a"},
		{name: "stale context", change: func(b *Benchmark) { b.Metrics.ContextLength = 256 }, want: "a"},
		{name: "stale runtime", change: func(b *Benchmark) { b.Metrics.RuntimeVersion = "old-build" }, want: "a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, now, _ := newSchedulerFixture(t, FleetConfig{})
			schedulerRegister(t, s, "a", schedulerAdvertisement())
			a := schedulerAdvertisement()
			b := schedulerBenchmark(*now)
			if test.change != nil {
				test.change(&b)
			}
			a.Benchmarks = []Benchmark{b}
			schedulerRegister(t, s, "b", a)
			j, _ := schedulerSubmit(t, s)
			if j.NodeID != test.want {
				t.Fatalf("benchmark chose %s, expected %s", j.NodeID, test.want)
			}
		})
	}
}

func TestSchedulerRejectsInvalidBenchmarksAndModelConflicts(t *testing.T) {
	for _, change := range []func(*Benchmark){
		func(b *Benchmark) { b.SHA256 = strings.Repeat("b", 64) }, func(b *Benchmark) { b.Revision = "other" },
		func(b *Benchmark) { b.Metrics.GenerationTokensPerSecond = math.Inf(1) }, func(b *Benchmark) { b.Metrics.PromptMS = math.NaN() },
		func(b *Benchmark) { b.Metrics.ColdStartMS = -1 }, func(b *Benchmark) { b.Metrics.PromptTokens = 0 },
		func(b *Benchmark) { b.MeasuredAt = b.MeasuredAt.Add(time.Hour) },
	} {
		s, now, _ := newSchedulerFixture(t, FleetConfig{})
		a := schedulerAdvertisement()
		b := schedulerBenchmark(*now)
		change(&b)
		a.Benchmarks = []Benchmark{b}
		if s.Register("a", a) == nil {
			t.Fatal("invalid benchmark accepted")
		}
	}
	s, _, _ := newSchedulerFixture(t, FleetConfig{})
	schedulerRegister(t, s, "a", schedulerAdvertisement())
	for _, id := range []string{"a", "b"} {
		a := schedulerAdvertisement()
		a.Models[0].SHA256 = strings.Repeat("b", 64)
		if s.Register(id, a) == nil {
			t.Fatal("conflicting model content accepted")
		}
		a = schedulerAdvertisement()
		a.Models[0].Revision = "other"
		if s.Register(id, a) == nil {
			t.Fatal("conflicting model revision accepted")
		}
	}
	a := schedulerAdvertisement()
	a.Models[0].ID = "text-model-v2"
	a.Models[0].SHA256 = strings.Repeat("b", 64)
	schedulerRegister(t, s, "b", a)
}
