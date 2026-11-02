package hostedworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/inference"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

var artifactHash = regexp.MustCompile("^[0-9a-f]{64}$")

type Manager struct {
	mu             sync.Mutex
	life           context.Context
	configPath     string
	expectedConfig string
	cfg            inference.FleetConfig
	modelRoot      string
	allowInstall   bool
	backend        inference.Backend
	factory        func(context.Context, inference.RuntimeConfig) (inference.Backend, error)
	downloader     *downloader
	overlayLock    *os.File
	operatorModels map[string]bool
}

func NewManager(ctx context.Context, configPath, modelRoot string, allowInstall bool) (*Manager, error) {
	raw, err := readPrivate(configPath, 1<<20)
	if err != nil {
		return nil, err
	}
	cfg, err := inference.LoadFleetConfig(configPath)
	if err != nil {
		return nil, err
	}
	// LoadFleetConfig permits an API-key environment override; never persist it.
	var original inference.FleetConfig
	if decode(raw, &original) != nil {
		return nil, errors.New("invalid local inference configuration")
	}
	cfg.APIKey = original.APIKey
	if cfg.Runtime == nil {
		return nil, errors.New("hosted work requires an explicit local runtime configuration")
	}
	if !filepath.IsAbs(cfg.Runtime.Binary) || cfg.Runtime.Threads < 1 || cfg.Runtime.ContextLength < 128 || cfg.Runtime.MaxTokens < 1 || cfg.Runtime.MaxTokens >= cfg.Runtime.ContextLength || cfg.Runtime.MemoryLimitBytes < 256<<20 || cfg.Runtime.MemoryLimitBytes > 1<<60 {
		return nil, errors.New("invalid locally configured runtime limits")
	}
	if allowInstall && modelRoot == "" {
		return nil, errors.New("model installation requires an explicit private model root")
	}
	if modelRoot != "" {
		if err = ensureModelRoot(modelRoot); err != nil {
			return nil, err
		}
	}
	m := &Manager{life: ctx, configPath: configPath, expectedConfig: sum(raw), cfg: cfg, modelRoot: modelRoot, allowInstall: allowInstall, factory: inference.NewRuntime, downloader: newDownloader(), operatorModels: map[string]bool{}}
	for _, model := range cfg.Runtime.Models {
		m.operatorModels[model.ID] = true
	}
	if modelRoot != "" {
		models, lock, e := loadManagedModels(modelRoot)
		if e != nil {
			return nil, e
		}
		m.overlayLock = lock
		for _, model := range models {
			if m.operatorModels[model.ID] || model.Path != filepath.Join(modelRoot, model.SHA256+".gguf") {
				m.Close()
				return nil, errors.New("managed overlay conflicts with operator models")
			}
			cfg.Runtime.Models = append(cfg.Runtime.Models, model)
		}
		m.cfg = cfg
	}
	if len(cfg.Runtime.Models) > 0 {
		m.backend, err = m.factory(ctx, *cfg.Runtime)
		if err != nil {
			m.Close()
			return nil, err
		}
	}
	if m.backend == nil && !allowInstall {
		m.Close()
		return nil, errors.New("no installed models and model installation was not opted in")
	}
	return m, nil
}
func decode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}
func sum(raw []byte) string { hash := sha256.Sum256(raw); return hex.EncodeToString(hash[:]) }
func readPrivate(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("private configuration requires an absolute clean path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("private configuration must not traverse symlinks")
	}
	file, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("configuration must be a private regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, errors.New("private configuration is oversized or unreadable")
	}
	return raw, nil
}
func (m *Manager) Capabilities() cloud.WorkCapabilities {
	m.mu.Lock()
	defer m.mu.Unlock()
	caps := cloud.WorkCapabilities{JobTypes: []string{}, Models: []cloud.WorkModel{}, MaxConcurrentJobs: 1, ApprovedModelSHA256s: []string{}, RuntimeLimits: &cloud.RuntimeLimits{MemoryLimitBytes: m.cfg.Runtime.MemoryLimitBytes, ContextLength: m.cfg.Runtime.ContextLength, MaxTokens: m.cfg.Runtime.MaxTokens}}
	if caps.RuntimeLimits.MaxTokens > 8192 {
		caps.RuntimeLimits.MaxTokens = 8192
	}
	if m.backend != nil {
		caps.JobTypes = append(caps.JobTypes, "infer")
		for _, model := range m.backend.Models() {
			caps.Models = append(caps.Models, cloud.WorkModel{ID: model.ID, SHA256: model.SHA256, Revision: model.Revision})
		}
	}
	if m.allowInstall {
		caps.JobTypes = append(caps.JobTypes, "install", "remove")
	}
	for _, approval := range m.cfg.ApprovedModels {
		caps.ApprovedModelSHA256s = append(caps.ApprovedModelSHA256s, approval.SHA256)
	}
	return caps
}
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var err error
	if m.backend != nil {
		err = m.backend.Close()
		m.backend = nil
	}
	if m.overlayLock != nil {
		syscall.Flock(int(m.overlayLock.Fd()), syscall.LOCK_UN)
		m.overlayLock.Close()
		m.overlayLock = nil
	}
	return err
}

func (m *Manager) Execute(ctx context.Context, job cloud.WorkLease, emit func(json.RawMessage) error) (json.RawMessage, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err := m.checkOperatorConfig(); err != nil {
		return nil, err
	}
	switch job.Type {
	case "infer":
		return m.infer(ctx, job.Payload, emit)
	case "install":
		return m.install(ctx, job.Payload)
	case "remove":
		return m.remove(ctx, job.Payload)
	default:
		return nil, errors.New("unsupported hosted work type")
	}
}
func (m *Manager) infer(ctx context.Context, raw json.RawMessage, emit func(json.RawMessage) error) (json.RawMessage, error) {
	var payload struct {
		Request inference.Request `json:"request"`
	}
	if decode(raw, &payload) != nil || m.backend == nil {
		return nil, errors.New("invalid inference job or no installed runtime")
	}
	request := payload.Request
	if request.MaxTokens < 1 || request.MaxTokens > m.cfg.Runtime.MaxTokens || len(request.Messages) < 1 || len(request.Messages) > 256 || len(request.AllowedNodes) > 0 {
		return nil, errors.New("request exceeds local generation limits")
	}
	known := false
	for _, model := range m.backend.Models() {
		if model.ID == request.Model {
			known = true
		}
	}
	if !known {
		return nil, errors.New("requested model is not installed")
	}
	prompt := 0
	for _, message := range request.Messages {
		prompt += len(message.Content)
	}
	if prompt > 32<<10 {
		return nil, errors.New("hosted prompt exceeds32KiB")
	}
	var metrics *inference.Metrics
	done := false
	err := m.backend.Run(ctx, request, func(event inference.Event) error {
		if event.Error != "" {
			return errors.New("runtime generation failed")
		}
		if event.Metrics != nil {
			metrics = event.Metrics
		}
		if len(event.Data) > 0 {
			raw, e := json.Marshal(event)
			if e != nil {
				return e
			}
			if e = emit(raw); e != nil {
				return e
			}
		}
		if event.Done {
			done = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("runtime ended without a completion marker")
	}
	return json.Marshal(struct {
		Metrics *inference.Metrics `json:"metrics,omitempty"`
	}{metrics})
}
func (m *Manager) install(ctx context.Context, raw json.RawMessage) (result json.RawMessage, runErr error) {
	if !m.allowInstall || m.modelRoot == "" {
		return nil, errors.New("model installation was not opted in")
	}
	var payload struct {
		Model       inference.Model `json:"model"`
		DownloadURL string          `json:"download_url"`
	}
	if decode(raw, &payload) != nil {
		return nil, errors.New("invalid install payload")
	}
	model := payload.Model
	// Owner approval is checked before URL processing, allocation, or networking.
	if err := inference.ApproveModel(model, m.cfg.ApprovedModels); err != nil {
		return nil, err
	}
	if model.ID == "" || len(model.ID) > 128 || strings.ContainsAny(model.ID, "\x00\r\n") || model.Format != "GGUF" || model.Runtime != "llama.cpp" || len(model.Workloads) != 1 || model.Workloads[0] != "text-generation" || model.SizeBytes < 24 || model.SizeBytes > 64<<30 || model.RequiredMemoryBytes < model.SizeBytes || model.RequiredMemoryBytes > m.cfg.Runtime.MemoryLimitBytes {
		return nil, errors.New("model exceeds the local runtime policy")
	}
	for _, installed := range m.cfg.Runtime.Models {
		if installed.ID == model.ID {
			if installed.SHA256 != model.SHA256 || installed.Revision != model.Revision {
				return nil, errors.New("remove the old immutable model before replacing its identifier")
			}
			if err := hashModel(ctx, installed.Path, model.SizeBytes, model.SHA256); err != nil {
				return nil, err
			}
			return modelResult(model)
		}
	}
	if len(m.cfg.Runtime.Models) >= 32 {
		return nil, errors.New("local model count limit reached")
	}
	snapshot, err := new(inventory.Monitor).Snapshot()
	if err != nil {
		return nil, errors.New("cannot inspect local model capacity")
	}
	available := snapshot.Memory.AvailableBytes
	if snapshot.Memory.EffectiveTotalBytes > 0 {
		available = snapshot.Memory.EffectiveAvailableBytes
	}
	if model.RequiredMemoryBytes > available || m.cfg.Runtime.ReserveMemoryBytes > available-model.RequiredMemoryBytes {
		return nil, errors.New("insufficient available memory after host reserve")
	}
	limit := m.cfg.Runtime.MemoryLimitBytes
	if limit > 64<<30 {
		limit = 64 << 30
	}
	target, created, err := m.downloader.fetch(ctx, m.modelRoot, model, payload.DownloadURL, limit)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if created && !committed {
			removeExactModel(target, model.SHA256)
		}
	}()
	candidate := copyFleet(m.cfg)
	candidate.Runtime.Models = append(candidate.Runtime.Models, inference.InstalledModel{Model: model, Path: target})
	candidate.Runtime.ApprovedModels = candidate.ApprovedModels
	backend, err := m.factory(m.life, *candidate.Runtime)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		backend.Close()
		return nil, ctx.Err()
	}
	if err = m.persist(candidate); err != nil {
		backend.Close()
		return nil, err
	}
	old := m.backend
	m.backend = backend
	m.cfg = candidate
	committed = true
	if old != nil {
		old.Close()
	}
	return modelResult(model)
}
func (m *Manager) remove(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	if !m.allowInstall || m.modelRoot == "" {
		return nil, errors.New("model management was not opted in")
	}
	var payload struct {
		ModelID string `json:"model_id"`
		SHA256  string `json:"sha256"`
	}
	if decode(raw, &payload) != nil || payload.ModelID == "" || !artifactHash.MatchString(payload.SHA256) {
		return nil, errors.New("invalid remove payload")
	}
	candidate := copyFleet(m.cfg)
	candidate.Runtime.Models = nil
	var removed *inference.InstalledModel
	for _, model := range m.cfg.Runtime.Models {
		if model.ID == payload.ModelID {
			if m.operatorModels[model.ID] {
				return nil, errors.New("operator-pinned models cannot be removed by hosted jobs")
			}
			if model.SHA256 != payload.SHA256 || model.Path != filepath.Join(m.modelRoot, model.SHA256+".gguf") {
				return nil, errors.New("only a registered model inside the opted-in model root can be removed")
			}
			clone := model
			removed = &clone
		} else {
			candidate.Runtime.Models = append(candidate.Runtime.Models, model)
		}
	}
	if removed == nil {
		return nil, errors.New("model is not installed")
	}
	if err := hashModel(ctx, removed.Path, removed.SizeBytes, removed.SHA256); err != nil {
		return nil, err
	}
	var backend inference.Backend
	var err error
	if len(candidate.Runtime.Models) > 0 {
		candidate.Runtime.ApprovedModels = candidate.ApprovedModels
		backend, err = m.factory(m.life, *candidate.Runtime)
		if err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil {
		if backend != nil {
			backend.Close()
		}
		return nil, ctx.Err()
	}
	if err = m.persist(candidate); err != nil {
		if backend != nil {
			backend.Close()
		}
		return nil, err
	}
	old := m.backend
	m.backend = backend
	m.cfg = candidate
	if old != nil {
		old.Close()
	}
	if ctx.Err() == nil {
		shared := false
		for _, model := range candidate.Runtime.Models {
			if model.Path == removed.Path {
				shared = true
			}
		}
		if !shared {
			if err = removeExactModel(removed.Path, removed.SHA256); err != nil {
				return nil, err
			}
		}
	}
	return modelResult(removed.Model)
}
func modelResult(model inference.Model) (json.RawMessage, error) {
	return json.Marshal(struct {
		Model cloud.WorkModel `json:"model"`
	}{cloud.WorkModel{ID: model.ID, SHA256: model.SHA256, Revision: model.Revision}})
}
func copyFleet(cfg inference.FleetConfig) inference.FleetConfig {
	raw, _ := json.Marshal(cfg)
	var result inference.FleetConfig
	_ = json.Unmarshal(raw, &result)
	if result.Runtime != nil {
		result.Runtime.ApprovedModels = result.ApprovedModels
	}
	return result
}

type managedModels struct {
	SchemaVersion int                        `json:"schema_version"`
	Models        []inference.InstalledModel `json:"models"`
}

func loadManagedModels(root string) ([]inference.InstalledModel, *os.File, error) {
	descriptor, err := syscall.Open(filepath.Join(root, "hosted-models.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, nil, errors.New("cannot lock managed model overlay")
	}
	lock := os.NewFile(uintptr(descriptor), "hosted-models.lock")
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, nil, errors.New("managed model lock must be private and regular")
	}
	if syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, nil, errors.New("another worker owns this managed model directory")
	}
	path := filepath.Join(root, "hosted-models.json")
	if _, err = os.Lstat(path); os.IsNotExist(err) {
		return nil, lock, nil
	}
	raw, err := readPrivate(path, 4<<20)
	if err != nil {
		lock.Close()
		return nil, nil, err
	}
	var overlay managedModels
	if decode(raw, &overlay) != nil || overlay.SchemaVersion != 1 || len(overlay.Models) > 32 {
		lock.Close()
		return nil, nil, errors.New("invalid private managed model overlay")
	}
	return overlay.Models, lock, nil
}
func (m *Manager) checkOperatorConfig() error {
	raw, err := readPrivate(m.configPath, 1<<20)
	if err != nil || sum(raw) != m.expectedConfig {
		return errors.New("operator changed inference configuration; restart worker to apply it")
	}
	return nil
}
func (m *Manager) persist(cfg inference.FleetConfig) error {
	// The operator's FleetConfig is read-only. Worker-owned installed state lives
	// in its own overlay, so an uncooperative editor can never be overwritten.
	if err := m.checkOperatorConfig(); err != nil {
		return err
	}
	overlay := managedModels{SchemaVersion: 1, Models: []inference.InstalledModel{}}
	for _, model := range cfg.Runtime.Models {
		if !m.operatorModels[model.ID] {
			overlay.Models = append(overlay.Models, model)
		}
	}
	raw, err := json.MarshalIndent(overlay, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	file, err := os.CreateTemp(m.modelRoot, ".hosted-model-registry-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = m.checkOperatorConfig(); err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(m.modelRoot, "hosted-models.json")); err != nil {
		return err
	}
	directory, err := os.Open(m.modelRoot)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
