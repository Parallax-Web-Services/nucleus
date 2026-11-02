package inference

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// FleetConfig enables work only by explicit operator configuration. Remote
// membership alone does not grant inference placement permission.
type FleetConfig struct {
	Runtime               *RuntimeConfig  `json:"runtime,omitempty"`
	ApprovedModels        []ModelApproval `json:"approved_models,omitempty"`
	Meld                  *MeldConfig     `json:"meld,omitempty"`
	APIKey                string          `json:"api_key,omitempty"`
	AllowedWorkers        []string        `json:"allowed_workers,omitempty"`
	QueueLimit            int             `json:"queue_limit,omitempty"`
	RequestTimeoutSeconds int             `json:"request_timeout_seconds,omitempty"`
	WorkerTTLSeconds      int             `json:"worker_ttl_seconds,omitempty"`
	MaxCPUPercent         float64         `json:"max_cpu_percent,omitempty"`
}

func LoadFleetConfig(path string) (FleetConfig, error) {
	var cfg FleetConfig
	f, err := os.Open(path)
	if err != nil {
		return cfg, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return cfg, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return cfg, errors.New("inference config must be a private regular file (0600)")
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return cfg, err
	}
	if len(data) > 1<<20 {
		return cfg, errors.New("inference config exceeds 1 MiB")
	}
	if err = decodeStrict(bytes.NewReader(data), &cfg); err != nil {
		return cfg, err
	}
	if key := os.Getenv("NUCLEUS_INFERENCE_API_KEY"); key != "" {
		cfg.APIKey = key
	}
	return cfg, cfg.defaults()
}
func (cfg *FleetConfig) defaults() error {
	seen := map[string]bool{}
	for _, a := range cfg.ApprovedModels {
		if err := ValidateModelApproval(a); err != nil {
			return err
		}
		if seen[a.SHA256] {
			return errors.New("duplicate model hash approval")
		}
		seen[a.SHA256] = true
	}
	cfg.ApprovedModels = cloneApprovals(cfg.ApprovedModels)
	if cfg.Meld != nil {
		cfg.Meld.ApprovedModels = cloneApprovals(cfg.ApprovedModels)
	}
	if cfg.Runtime != nil {
		cfg.Runtime.ApprovedModels = cloneApprovals(cfg.ApprovedModels)
	}
	if cfg.QueueLimit == 0 {
		cfg.QueueLimit = 64
	}
	if cfg.RequestTimeoutSeconds == 0 {
		cfg.RequestTimeoutSeconds = 300
	}
	if cfg.WorkerTTLSeconds == 0 {
		cfg.WorkerTTLSeconds = 10
	}
	if cfg.MaxCPUPercent == 0 {
		cfg.MaxCPUPercent = 90
	}
	if cfg.QueueLimit < 1 || cfg.QueueLimit > 1024 || cfg.RequestTimeoutSeconds < 1 || cfg.RequestTimeoutSeconds > 1800 || cfg.WorkerTTLSeconds < 3 || cfg.WorkerTTLSeconds > 120 || cfg.MaxCPUPercent < 1 || cfg.MaxCPUPercent > 100 {
		return errors.New("invalid inference queue, timeout, heartbeat or CPU policy")
	}
	return nil
}
func decodeStrict(r io.Reader, v any) error {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

// ValidateConfiguredModels is an offline preflight: provenance admission comes
// before file hashing, provisioning, subprocess startup or benchmark execution.
func ValidateConfiguredModels(cfg FleetConfig) error {
	if err := cfg.defaults(); err != nil {
		return err
	}
	if cfg.Runtime == nil || len(cfg.Runtime.Models) == 0 {
		return errors.New("model validation requires explicitly configured local models")
	}
	for _, m := range cfg.Runtime.Models {
		if _, err := validateApprovedInstalled(m, cfg.Runtime.ContextLength, cfg.ApprovedModels); err != nil {
			return err
		}
		if m.RequiredMemoryBytes > cfg.Runtime.MemoryLimitBytes {
			return errors.New("model exceeds configured runtime memory limit")
		}
	}
	return nil
}
