package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Work v1 reuses the origin-bound Ed25519 signature. Tokens stay private.
type WorkModel struct {
	ID       string `json:"id"`
	SHA256   string `json:"sha256"`
	Revision string `json:"revision"`
}
type RuntimeLimits struct {
	MemoryLimitBytes uint64 `json:"memory_limit_bytes"`
	ContextLength    int    `json:"context_length"`
	MaxTokens        int    `json:"max_tokens"`
}
type WorkCapabilities struct {
	JobTypes             []string       `json:"job_types"`
	Models               []WorkModel    `json:"models"`
	MaxConcurrentJobs    int            `json:"max_concurrent_jobs"`
	ApprovedModelSHA256s []string       `json:"approved_model_sha256s,omitempty"`
	RuntimeLimits        *RuntimeLimits `json:"runtime_limits,omitempty"`
}
type WorkLease struct {
	ID               string          `json:"id"`
	Type             string          `json:"type"`
	LeaseID          string          `json:"lease_id"`
	LeaseToken       string          `json:"lease_token"`
	LeaseExpiresAtMS int64           `json:"lease_expires_at_ms"`
	DeadlineAtMS     int64           `json:"deadline_at_ms"`
	Payload          json.RawMessage `json:"payload"`
}
type WorkPoll struct {
	Work              *WorkLease `json:"work"`
	RetryAfterSeconds int        `json:"retry_after_seconds"`
}
type WorkRenewal struct {
	State            string `json:"state"`
	LeaseExpiresAtMS int64  `json:"lease_expires_at_ms"`
}
type WorkEvent struct {
	Sequence int64           `json:"sequence"`
	Type     string          `json:"type"`
	Data     json.RawMessage `json:"data,omitempty"`
}
type WorkAcknowledgment struct {
	AcceptedSequence int64  `json:"accepted_sequence"`
	State            string `json:"state"`
}

func strictWorkJSON(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("hosted service returned invalid work JSON")
	}
	return nil
}
func (c *Client) workBinding() (*Binding, error) {
	b, err := LoadBinding(c.home)
	if err != nil {
		return nil, err
	}
	if b.Origin != c.base.origin || b.BasePath != c.base.path {
		return nil, errors.New("work client does not match saved cloud registration")
	}
	if b.Revoked {
		return nil, &APIError{Status: http.StatusForbidden, Code: "node_revoked"}
	}
	return b, nil
}
func (c *Client) LeaseWork(ctx context.Context, caps WorkCapabilities) (WorkPoll, error) {
	var out WorkPoll
	if caps.MaxConcurrentJobs != 1 || len(caps.JobTypes) < 1 || len(caps.JobTypes) > 3 || len(caps.Models) > 32 || len(caps.ApprovedModelSHA256s) > 256 {
		return out, errors.New("invalid local work capabilities")
	}
	seen := map[string]bool{}
	for _, kind := range caps.JobTypes {
		if (kind != "infer" && kind != "install" && kind != "remove") || seen[kind] {
			return out, errors.New("unsupported local work capability")
		}
		seen[kind] = true
	}
	for _, m := range caps.Models {
		if m.ID == "" || len(m.ID) > 128 || !hex64.MatchString(m.SHA256) || len(m.Revision) > 256 {
			return out, errors.New("invalid local model capability")
		}
	}
	for _, hash := range caps.ApprovedModelSHA256s {
		if !hex64.MatchString(hash) {
			return out, errors.New("invalid local approved model hash")
		}
	}
	b, err := c.workBinding()
	if err != nil {
		return out, err
	}
	body, err := json.Marshal(struct {
		SchemaVersion int              `json:"schema_version"`
		Capabilities  WorkCapabilities `json:"capabilities"`
	}{1, caps})
	if err != nil {
		return out, err
	}
	raw, err := c.requestBounded(ctx, http.MethodPost, c.nodePath(b.NodeID)+"/work/lease", body, true, 65536)
	if err != nil {
		return out, err
	}
	if strictWorkJSON(raw, &out) != nil || out.RetryAfterSeconds < 1 || out.RetryAfterSeconds > 60 {
		return WorkPoll{}, errors.New("invalid hosted work response")
	}
	if out.Work != nil {
		if err = ValidateWorkLease(*out.Work, c.now()); err != nil {
			return WorkPoll{}, err
		}
		if !seen[out.Work.Type] {
			return WorkPoll{}, errors.New("hosted service offered work that was not opted in")
		}
	}
	return out, nil
}
func ValidateWorkLease(w WorkLease, now time.Time) error {
	if !enrollmentID.MatchString(w.ID) || !enrollmentID.MatchString(w.LeaseID) || !hex64.MatchString(w.LeaseToken) || len(w.Payload) > 48<<10 || !json.Valid(w.Payload) {
		return errors.New("invalid hosted work lease")
	}
	limit := 20 * time.Minute
	if w.Type == "infer" {
		limit = 600 * time.Second
	} else if w.Type != "install" && w.Type != "remove" {
		return errors.New("unsupported hosted job type")
	}
	expires := time.UnixMilli(w.LeaseExpiresAtMS)
	deadline := time.UnixMilli(w.DeadlineAtMS)
	if !expires.After(now) || expires.After(now.Add(65*time.Second)) || !deadline.After(now) || deadline.After(now.Add(limit+5*time.Second)) || expires.After(deadline) {
		return errors.New("invalid hosted work lease deadline")
	}
	return nil
}
func (c *Client) RenewWork(ctx context.Context, w WorkLease, lastSequence int64) (WorkRenewal, error) {
	var out WorkRenewal
	b, err := c.workBinding()
	if err != nil {
		return out, err
	}
	if !enrollmentID.MatchString(w.ID) || !enrollmentID.MatchString(w.LeaseID) || !hex64.MatchString(w.LeaseToken) || lastSequence < 0 {
		return out, errors.New("invalid work renewal")
	}
	body, _ := json.Marshal(struct {
		LeaseID      string `json:"lease_id"`
		LeaseToken   string `json:"lease_token"`
		LastSequence int64  `json:"last_sequence"`
	}{w.LeaseID, w.LeaseToken, lastSequence})
	raw, err := c.requestBounded(ctx, http.MethodPost, c.nodePath(b.NodeID)+"/work/"+w.ID+"/renew", body, true, 16384)
	if err != nil {
		return out, err
	}
	if strictWorkJSON(raw, &out) != nil || (out.State != "leased" && out.State != "cancelled") {
		return WorkRenewal{}, errors.New("invalid hosted lease renewal")
	}
	if out.State == "leased" {
		expires := time.UnixMilli(out.LeaseExpiresAtMS)
		if !expires.After(c.now()) || expires.After(c.now().Add(65*time.Second)) || expires.After(time.UnixMilli(w.DeadlineAtMS)) {
			return WorkRenewal{}, errors.New("invalid renewed lease deadline")
		}
	}
	return out, nil
}
func (c *Client) SendWorkEvents(ctx context.Context, w WorkLease, events []WorkEvent) (WorkAcknowledgment, error) {
	var out WorkAcknowledgment
	b, err := c.workBinding()
	if err != nil {
		return out, err
	}
	if !enrollmentID.MatchString(w.ID) || !enrollmentID.MatchString(w.LeaseID) || !hex64.MatchString(w.LeaseToken) || len(events) < 1 || len(events) > 32 {
		return out, errors.New("invalid work event batch")
	}
	var previous int64
	for _, event := range events {
		if event.Sequence < 1 || (previous > 0 && event.Sequence != previous+1) || len(event.Data) > 32<<10 || (len(event.Data) > 0 && !json.Valid(event.Data)) {
			return out, errors.New("invalid work event sequence or size")
		}
		switch event.Type {
		case "started", "chunk", "completed", "failed", "cancelled":
		default:
			return out, errors.New("unsupported work event type")
		}
		previous = event.Sequence
	}
	body, err := json.Marshal(struct {
		LeaseID    string      `json:"lease_id"`
		LeaseToken string      `json:"lease_token"`
		Events     []WorkEvent `json:"events"`
	}{w.LeaseID, w.LeaseToken, events})
	if err != nil {
		return out, err
	}
	raw, err := c.requestBounded(ctx, http.MethodPost, c.nodePath(b.NodeID)+"/work/"+w.ID+"/events", body, true, 16384)
	if err != nil {
		return out, err
	}
	if strictWorkJSON(raw, &out) != nil || out.AcceptedSequence != events[len(events)-1].Sequence {
		return WorkAcknowledgment{}, errors.New("invalid work event acknowledgment")
	}
	switch out.State {
	case "leased", "completed", "failed", "cancelled":
	default:
		return WorkAcknowledgment{}, errors.New("invalid work event state")
	}
	return out, nil
}
func (c *Client) validSignedPath(nodeID, path string) bool {
	base := c.nodePath(nodeID)
	if path == base || path == base+"/heartbeat" || path == base+"/work/lease" {
		return true
	}
	suffix := strings.TrimPrefix(path, base+"/work/")
	if suffix == path {
		return false
	}
	pieces := strings.Split(suffix, "/")
	return len(pieces) == 2 && enrollmentID.MatchString(pieces[0]) && (pieces[1] == "renew" || pieces[1] == "events")
}
