// Package inference supplies the typed, bounded text-generation execution path.
package inference

import (
	"context"
	"encoding/json"
)

type Model struct {
	ID                  string           `json:"id"`
	Revision            string           `json:"revision"`
	Source              string           `json:"source"`
	License             string           `json:"license"`
	Architecture        string           `json:"architecture"`
	Format              string           `json:"format"`
	Quantization        string           `json:"quantization"`
	SHA256              string           `json:"sha256"`
	SizeBytes           uint64           `json:"size_bytes"`
	RequiredMemoryBytes uint64           `json:"required_memory_bytes"`
	Workloads           []string         `json:"workloads"`
	Runtime             string           `json:"runtime"`
	Provenance          *ModelProvenance `json:"provenance,omitempty"`
}

func cloneModel(m Model) Model {
	data, _ := json.Marshal(m)
	var copy Model
	_ = json.Unmarshal(data, &copy)
	return copy
}
func cloneApprovals(a []ModelApproval) []ModelApproval {
	data, _ := json.Marshal(a)
	var copy []ModelApproval
	_ = json.Unmarshal(data, &copy)
	return copy
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request excludes remote commands, tools, URLs, and model paths.
type Request struct {
	Model          string          `json:"model"`
	Messages       []Message       `json:"messages"`
	Stream         bool            `json:"stream"`
	MaxTokens      int             `json:"max_tokens,omitempty"`
	Temperature    *float64        `json:"temperature,omitempty"`
	ResponseFormat json.RawMessage `json:"response_format,omitempty"`
	AllowedNodes   []string        `json:"nucleus_allowed_nodes,omitempty"`
}

// Throughput is present only when llama.cpp supplies measured phase timings.
// SSE chunks are not counted as tokens.
type Metrics struct {
	PromptTokens              int     `json:"prompt_tokens"`
	GenerationTokens          int     `json:"generation_tokens"`
	PromptMS                  float64 `json:"prompt_ms"`
	GenerationMS              float64 `json:"generation_ms"`
	PromptTokensPerSecond     float64 `json:"prompt_tokens_per_second"`
	GenerationTokensPerSecond float64 `json:"generation_tokens_per_second"`
	ColdStartMS               float64 `json:"cold_start_ms"`
	ElapsedMS                 float64 `json:"elapsed_ms"`
	PeakRSSBytes              uint64  `json:"peak_rss_bytes"`
	RuntimeVersion            string  `json:"runtime_version"`
	Threads                   int     `json:"threads"`
	ContextLength             int     `json:"context_length"`
	MaxTokens                 int     `json:"max_tokens"`
}

type Event struct {
	Data    json.RawMessage `json:"data,omitempty"`
	Done    bool            `json:"done,omitempty"`
	Error   string          `json:"error,omitempty"`
	Metrics *Metrics        `json:"metrics,omitempty"`
}

type Backend interface {
	Models() []Model
	Run(context.Context, Request, func(Event) error) error
	Close() error
}
