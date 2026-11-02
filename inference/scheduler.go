package inference

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// Advertisement is authenticated by the fabric transport. It describes a
// provisioned runtime, never an invitation to download or provision a model.
const maxJobOutputBytes = 8 << 20

type Advertisement struct {
	Threads              int         `json:"threads"`
	RuntimeVersion       string      `json:"runtime_version,omitempty"`
	Models               []Model     `json:"models"`
	AvailableMemoryBytes uint64      `json:"available_memory_bytes"`
	MemoryLimitBytes     uint64      `json:"memory_limit_bytes"`
	CPUPercent           float64     `json:"cpu_percent"`
	MaxConcurrent        int         `json:"max_concurrent"`
	ContextLength        int         `json:"context_length"`
	MaxTokens            int         `json:"max_tokens"`
	WarmModels           []string    `json:"warm_models,omitempty"`
	Benchmarks           []Benchmark `json:"benchmarks,omitempty"`
}
type Benchmark struct {
	ModelID      string    `json:"model_id"`
	Revision     string    `json:"revision"`
	SHA256       string    `json:"sha256"`
	Quantization string    `json:"quantization"`
	MeasuredAt   time.Time `json:"measured_at"`
	Metrics      Metrics   `json:"metrics"`
}
type WorkerView struct {
	NodeID string `json:"node_id"`
	Advertisement
	LastSeen        time.Time `json:"last_seen"`
	Active          int       `json:"active"`
	Online          bool      `json:"online"`
	LastRoundTripMS float64   `json:"last_round_trip_ms"`
}
type JobView struct {
	ID         string     `json:"id"`
	Model      string     `json:"model"`
	NodeID     string     `json:"node_id,omitempty"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	Deadline   time.Time  `json:"deadline"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Error      string     `json:"error,omitempty"`
	Metrics    *Metrics   `json:"metrics,omitempty"`
}
type Lease struct {
	ID       string    `json:"id"`
	Request  Request   `json:"request"`
	Deadline time.Time `json:"deadline"`
}
type job struct {
	view        JobView
	request     Request
	events      chan Event
	ctx         context.Context
	cancel      context.CancelFunc
	terminal    bool
	outputBytes int
}
type worker struct{ view WorkerView }
type Scheduler struct {
	mu         sync.Mutex
	cfg        FleetConfig
	owner      string
	authorized func(string) bool
	nodes      map[string]*worker
	jobs       map[string]*job
	order      []string
	history    []string
	now        func() time.Time
}

func NewScheduler(owner string, cfg FleetConfig, authorized func(string) bool) (*Scheduler, error) {
	if err := cfg.defaults(); err != nil {
		return nil, err
	}
	if owner == "" || authorized == nil {
		return nil, errors.New("owner and membership checker required")
	}
	return &Scheduler{cfg: cfg, owner: owner, authorized: authorized, nodes: map[string]*worker{}, jobs: map[string]*job{}, now: time.Now}, nil
}
func (s *Scheduler) allowed(id string) bool {
	if !s.authorized(id) {
		return false
	}
	if id == s.owner {
		return true
	}
	for _, v := range s.cfg.AllowedWorkers {
		if v == id {
			return true
		}
	}
	return false
}
func (s *Scheduler) Register(id string, a Advertisement) error {
	if !s.allowed(id) {
		return errors.New("node is not authorized for inference; owner must explicitly add allowed_workers")
	}
	if a.Threads < 1 || a.Threads > 1_048_576 || len(a.RuntimeVersion) > 8192 || a.MaxConcurrent != 1 || len(a.Models) > 64 || len(a.WarmModels) > 64 || len(a.Benchmarks) > 64 || a.MemoryLimitBytes == 0 || a.ContextLength < 1 || a.ContextLength > 1<<20 || a.MaxTokens < 1 || a.MaxTokens > a.ContextLength || math.IsNaN(a.CPUPercent) || math.IsInf(a.CPUPercent, 0) || a.CPUPercent < 0 || a.CPUPercent > 100 {
		return errors.New("invalid worker resource policy")
	}
	seen := map[string]bool{}
	models := map[string]Model{}
	for _, m := range a.Models {
		if err := ApproveModel(m, s.cfg.ApprovedModels); err != nil {
			return fmt.Errorf("model provenance policy rejected worker capability: %w", err)
		}
		if m.ID == "" || len(m.ID) > 256 || m.Runtime == "" || len(m.Runtime) > 128 || m.Format == "" || len(m.Format) > 64 || !contains(m.Workloads, "text-generation") || m.Revision == "" || len(m.Revision) > 2048 || m.RequiredMemoryBytes == 0 || m.RequiredMemoryBytes > a.MemoryLimitBytes || len(m.SHA256) != 64 {
			return errors.New("invalid model capability or memory budget")
		}
		if _, err := hex.DecodeString(m.SHA256); err != nil {
			return errors.New("invalid model integrity hash")
		}
		if seen[m.ID] {
			return errors.New("duplicate model ID")
		}
		seen[m.ID] = true
		models[m.ID] = m
	}
	for _, b := range a.Benchmarks {
		m, exists := models[b.ModelID]
		if !exists || b.MeasuredAt.IsZero() || b.MeasuredAt.After(s.now().Add(5*time.Minute)) || b.SHA256 != m.SHA256 || b.Revision != m.Revision || b.Quantization != m.Quantization || !validMetrics(b.Metrics) || b.Metrics.PromptTokens < 1 || b.Metrics.GenerationTokens < 1 || b.Metrics.PromptMS <= 0 || b.Metrics.GenerationMS <= 0 || b.Metrics.RuntimeVersion == "" || b.Metrics.Threads < 1 || b.Metrics.ContextLength < 1 || b.Metrics.MaxTokens < 1 {
			return errors.New("invalid measured benchmark identity, timings or execution settings")
		}
	}
	// Deep-copy caller-owned collections before retaining them.
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	if len(data) > 256<<10 {
		return errors.New("worker capability exceeds limit")
	}
	if err = json.Unmarshal(data, &a); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// A public model ID denotes one immutable revision and content digest across
	// the fleet, including temporarily offline workers. New content needs a new ID.
	for otherID, existing := range s.nodes {
		if otherID == id {
			continue
		}
		for _, previous := range existing.view.Models {
			if current, exists := models[previous.ID]; exists && (current.SHA256 != previous.SHA256 || current.Revision != previous.Revision) {
				return fmt.Errorf("model %q conflicts with the hash/revision already advertised by worker %s; use a distinct model ID", previous.ID, otherID)
			}
		}
	}
	// A worker cannot silently change an existing ID's meaning either.
	if existing := s.nodes[id]; existing != nil {
		for _, previous := range existing.view.Models {
			if current, exists := models[previous.ID]; exists && (current.SHA256 != previous.SHA256 || current.Revision != previous.Revision) {
				return fmt.Errorf("model %q identity changed; use a distinct model ID", previous.ID)
			}
		}
	}
	n := s.nodes[id]
	if n == nil {
		n = &worker{}
		s.nodes[id] = n
	}
	n.view.NodeID = id
	n.view.Advertisement = a
	n.view.LastSeen = s.now()
	return nil
}
func validateRequest(r Request) error {
	if r.Model == "" || len(r.Model) > 256 || len(r.Messages) < 1 || len(r.Messages) > 256 || r.MaxTokens < 0 || r.MaxTokens > 1<<20 || len(r.AllowedNodes) > 128 {
		return errors.New("model, messages, max_tokens or node restriction is invalid")
	}
	total := 0
	for _, m := range r.Messages {
		if m.Role != "system" && m.Role != "user" && m.Role != "assistant" {
			return errors.New("only system, user and assistant text messages are supported")
		}
		total += len(m.Content)
	}
	if total > 512<<10 {
		return errors.New("prompt exceeds 512 KiB")
	}
	if r.Temperature != nil && (math.IsNaN(*r.Temperature) || math.IsInf(*r.Temperature, 0) || *r.Temperature < 0 || *r.Temperature > 2) {
		return errors.New("temperature must be between 0 and 2")
	}
	return nil
}
func contains(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func (s *Scheduler) eligible(n *worker, r Request) (Model, string) {
	id := n.view.NodeID
	if !s.allowed(id) {
		return Model{}, "worker permission revoked"
	}
	if s.now().Sub(n.view.LastSeen) >= time.Duration(s.cfg.WorkerTTLSeconds)*time.Second {
		return Model{}, "worker disconnected or heartbeat expired"
	}
	if len(r.AllowedNodes) > 0 && !contains(r.AllowedNodes, id) {
		return Model{}, "excluded by request placement restriction"
	}
	if n.view.CPUPercent >= s.cfg.MaxCPUPercent {
		return Model{}, "CPU load exceeds resource policy"
	}
	for _, m := range n.view.Models {
		if m.ID != r.Model {
			continue
		}
		if err := ApproveModel(m, s.cfg.ApprovedModels); err != nil {
			return Model{}, err.Error()
		}
		if r.MaxTokens > n.view.MaxTokens {
			return Model{}, "max_tokens exceeds worker policy"
		}
		available := n.view.AvailableMemoryBytes
		if contains(n.view.WarmModels, m.ID) && available <= math.MaxUint64-m.RequiredMemoryBytes {
			available += m.RequiredMemoryBytes
		}
		if m.RequiredMemoryBytes > available || m.RequiredMemoryBytes > n.view.MemoryLimitBytes {
			return Model{}, "insufficient available memory or RAM budget"
		}
		return m, ""
	}
	return Model{}, "model not provisioned on worker"
}
func (s *Scheduler) Submit(ctx context.Context, r Request) (JobView, <-chan Event, error) {
	if err := validateRequest(r); err != nil {
		return JobView{}, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	queued := 0
	for _, j := range s.jobs {
		if !j.terminal && j.view.Status == "queued" {
			queued++
		}
	}
	if queued >= s.cfg.QueueLimit {
		return JobView{}, nil, errors.New("inference queue full; retry after active requests finish")
	}
	type candidate struct {
		id    string
		score float64
	}
	var candidates []candidate
	reasons := map[string]string{}
	for id, n := range s.nodes {
		m, reason := s.eligible(n, r)
		if reason != "" {
			reasons[id] = reason
			continue
		}
		score := float64(n.view.Active)*10000 + n.view.CPUPercent
		if contains(n.view.WarmModels, r.Model) {
			score -= 100
		}
		for _, b := range n.view.Benchmarks {
			if b.ModelID == r.Model && b.SHA256 == m.SHA256 && b.Revision == m.Revision && b.Quantization == m.Quantization && b.Metrics.Threads == n.view.Threads && b.Metrics.ContextLength == n.view.ContextLength && b.Metrics.RuntimeVersion == n.view.RuntimeVersion && n.view.RuntimeVersion != "" {
				score -= math.Min(100, b.Metrics.GenerationTokensPerSecond)
			}
		}
		for _, j := range s.jobs {
			if !j.terminal && j.view.Status == "queued" && j.view.NodeID == id {
				score += 10000
			}
		}
		candidates = append(candidates, candidate{id, score})
	}
	if len(candidates) == 0 {
		data, _ := json.Marshal(reasons)
		return JobView{}, nil, fmt.Errorf("no eligible node for model %q: %s; explicitly provision the model, authorize a worker and check memory/load/health", r.Model, data)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score == candidates[j].score {
			return candidates[i].id < candidates[j].id
		}
		return candidates[i].score < candidates[j].score
	})
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return JobView{}, nil, err
	}
	id := hex.EncodeToString(nonce[:])
	deadline := s.now().Add(time.Duration(s.cfg.RequestTimeoutSeconds) * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	jobCtx, cancel := context.WithDeadline(ctx, deadline)
	j := &job{view: JobView{ID: id, Model: r.Model, NodeID: candidates[0].id, Status: "queued", CreatedAt: s.now(), Deadline: deadline}, request: r, events: make(chan Event, 128), ctx: jobCtx, cancel: cancel}
	s.jobs[id] = j
	s.order = append(s.order, id)
	return j.view, j.events, nil
}
func (s *Scheduler) Acquire(id string) (*Lease, error) {
	if !s.allowed(id) {
		return nil, errors.New("worker permission revoked")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	n := s.nodes[id]
	if n == nil {
		return nil, errors.New("worker must register capabilities before polling")
	}
	if n.view.Active >= n.view.MaxConcurrent {
		return nil, nil
	}
	for _, jobID := range s.order {
		j := s.jobs[jobID]
		if j == nil || j.terminal || j.view.Status != "queued" {
			continue
		}
		// A queued, never-leased request may safely move if its original worker fails.
		if j.view.NodeID != id {
			old := s.nodes[j.view.NodeID]
			if old != nil {
				if _, why := s.eligible(old, j.request); why == "" {
					continue
				}
			}
		}
		if _, why := s.eligible(n, j.request); why != "" {
			continue
		}
		j.view.NodeID = id
		j.view.Status = "running"
		now := s.now()
		j.view.StartedAt = &now
		n.view.Active++
		r := j.request
		r.AllowedNodes = nil
		return &Lease{ID: jobID, Request: r, Deadline: j.view.Deadline}, nil
	}
	return nil, nil
}
func (s *Scheduler) Push(id, jobID string, e Event) error {
	if !s.allowed(id) {
		return errors.New("worker permission revoked")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[jobID]
	if j == nil || j.terminal || j.view.NodeID != id || j.view.Status != "running" {
		return errors.New("job no longer executable by this worker")
	}
	if j.ctx.Err() != nil {
		s.finishLocked(j, "cancelled", j.ctx.Err().Error(), nil)
		return j.ctx.Err()
	}
	if len(e.Data) > 2<<20 || len(e.Error) > 4096 || (e.Metrics != nil && !validMetrics(*e.Metrics)) {
		s.finishLocked(j, "failed", "worker event exceeds resource or numeric limits", nil)
		return errors.New("worker event exceeds resource or numeric limits")
	}
	if len(e.Data) > 0 && !json.Valid(e.Data) {
		s.finishLocked(j, "failed", "worker emitted invalid JSON", nil)
		return errors.New("worker emitted invalid JSON")
	}
	if len(e.Data) > maxJobOutputBytes-j.outputBytes {
		s.finishLocked(j, "failed", "job output exceeds 8 MiB limit", nil)
		return errors.New("job output exceeds 8 MiB limit")
	}
	j.outputBytes += len(e.Data)
	if e.Error != "" {
		s.finishLocked(j, "failed", e.Error, e.Metrics)
		return nil
	}
	// Reserve the last slot for a terminal event, including when backpressure
	// causes failure. Clients must never see a partial stream close as success.
	if len(e.Data) > 0 || !e.Done {
		if len(j.events) >= cap(j.events)-1 {
			s.finishLocked(j, "failed", "client cannot consume stream within bounded buffer", nil)
			return errors.New("stream backpressure limit exceeded")
		}
		dataEvent := e
		dataEvent.Done = false
		dataEvent.Metrics = nil
		j.events <- dataEvent
	}
	if e.Done {
		s.finishLocked(j, "completed", "", e.Metrics)
	}
	return nil
}

func validMetrics(m Metrics) bool {
	if m.PromptTokens < 0 || m.GenerationTokens < 0 || m.Threads < 0 || m.Threads > 1_048_576 || m.ContextLength < 0 || m.ContextLength > 1<<20 || m.MaxTokens < 0 || m.MaxTokens > 1<<20 || len(m.RuntimeVersion) > 8192 {
		return false
	}
	for _, v := range []float64{m.PromptMS, m.GenerationMS, m.PromptTokensPerSecond, m.GenerationTokensPerSecond, m.ColdStartMS, m.ElapsedMS} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
			return false
		}
	}
	return true
}

func (s *Scheduler) finishLocked(j *job, status, message string, metrics *Metrics) {
	if j.terminal {
		return
	}
	if j.view.Status == "running" {
		if n := s.nodes[j.view.NodeID]; n != nil && n.view.Active > 0 {
			n.view.Active--
		}
	}
	j.terminal = true
	j.view.Status = status
	j.view.Error = message
	j.view.Metrics = metrics
	now := s.now()
	j.view.FinishedAt = &now
	j.cancel()
	select {
	case j.events <- Event{Done: true, Error: message, Metrics: metrics}:
	default:
	}
	close(j.events)
	// Prompts and results live only until terminal state; bounded operational history
	// retains placements and metrics, never prompt or generated content.
	j.request = Request{}
	s.history = append(s.history, j.view.ID)
	if len(s.history) > 256 {
		delete(s.jobs, s.history[0])
		s.history = s.history[1:]
	}
	if len(s.order) > s.cfg.QueueLimit+512 {
		order := s.order[:0]
		for _, id := range s.order {
			if x := s.jobs[id]; x != nil && !x.terminal {
				order = append(order, id)
			}
		}
		s.order = order
	}
}
func (s *Scheduler) Cancel(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	j := s.jobs[id]
	if j == nil {
		return false
	}
	s.finishLocked(j, "cancelled", "request cancelled", nil)
	return true
}
func (s *Scheduler) Job(id string) (JobView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	j := s.jobs[id]
	if j == nil {
		return JobView{}, false
	}
	return j.view, true
}
func (s *Scheduler) WorkerJob(node, id string) (JobView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	j := s.jobs[id]
	if j == nil || j.view.NodeID != node || !s.allowed(node) {
		return JobView{}, false
	}
	return j.view, true
}
func (s *Scheduler) sweepLocked() {
	now := s.now()
	for _, j := range s.jobs {
		if j.terminal {
			continue
		}
		if err := j.ctx.Err(); err != nil {
			status := "cancelled"
			if errors.Is(err, context.DeadlineExceeded) {
				status = "timed_out"
			}
			s.finishLocked(j, status, err.Error(), nil)
			continue
		}
		if !now.Before(j.view.Deadline) {
			s.finishLocked(j, "timed_out", "request deadline exceeded", nil)
			continue
		}
		if j.view.Status == "running" {
			n := s.nodes[j.view.NodeID]
			if n == nil || !s.allowed(j.view.NodeID) || now.Sub(n.view.LastSeen) >= time.Duration(s.cfg.WorkerTTLSeconds)*time.Second {
				s.finishLocked(j, "failed", "worker disconnected or authorization revoked; execution is not replayed", nil)
			}
		}
	}
}
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			for _, j := range s.jobs {
				s.finishLocked(j, "cancelled", "coordinator shutting down", nil)
			}
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.mu.Lock()
			s.sweepLocked()
			s.mu.Unlock()
		}
	}
}
func (s *Scheduler) Status() ([]WorkerView, []JobView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
	nodes := []WorkerView{}
	jobs := []JobView{}
	for _, n := range s.nodes {
		v := n.view
		v.Online = s.allowed(v.NodeID) && s.now().Sub(v.LastSeen) < time.Duration(s.cfg.WorkerTTLSeconds)*time.Second
		nodes = append(nodes, v)
	}
	for _, j := range s.jobs {
		jobs = append(jobs, j.view)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.Before(jobs[j].CreatedAt) })
	return nodes, jobs
}
