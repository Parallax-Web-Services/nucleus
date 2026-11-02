package inference

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

const workerPrefix = "/v1/inference/worker/"

type Service struct {
	Scheduler *Scheduler
	APIKey    string
	Meld      http.Handler
}

func (s *Service) WorkerHandler(w http.ResponseWriter, r *http.Request, node string) {
	w.Header().Set("Cache-Control", "no-store")
	// The caller MUST be the Positronic membership-authenticated dispatch hook.
	switch {
	case r.URL.Path == workerPrefix+"register" && r.Method == http.MethodPost:
		var a Advertisement
		if !readJSON(w, r, &a, 256<<10) {
			return
		}
		if err := s.Scheduler.Register(node, a); err != nil {
			apiError(w, 403, err.Error())
			return
		}
		w.WriteHeader(204)
	case r.URL.Path == workerPrefix+"acquire" && r.Method == http.MethodPost:
		lease, err := s.Scheduler.Acquire(node)
		if err != nil {
			apiError(w, 403, err.Error())
			return
		}
		if lease == nil {
			w.WriteHeader(204)
			return
		}
		writeJSON(w, 200, lease)
	case strings.HasPrefix(r.URL.Path, workerPrefix+"jobs/"):
		tail := strings.TrimPrefix(r.URL.Path, workerPrefix+"jobs/")
		parts := strings.Split(tail, "/")
		if len(parts) > 2 || len(parts[0]) != 32 {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		if len(parts) == 1 && r.Method == http.MethodGet {
			j, ok := s.Scheduler.WorkerJob(node, id)
			if !ok {
				apiError(w, 404, "job not assigned to this worker")
				return
			}
			writeJSON(w, 200, j)
			return
		}
		if len(parts) == 2 && parts[1] == "events" && r.Method == http.MethodPost {
			var e Event
			if !readJSON(w, r, &e, (2<<20)+8192) {
				return
			}
			if err := s.Scheduler.Push(node, id, e); err != nil {
				apiError(w, 409, err.Error())
				return
			}
			w.WriteHeader(204)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}
func readJSON(w http.ResponseWriter, r *http.Request, target any, limit int64) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		apiError(w, 415, "application/json required")
		return false
	}
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	if err = decodeStrict(r.Body, target); err != nil {
		apiError(w, 400, "invalid, unsupported or oversized JSON: "+err.Error())
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": message, "type": "nucleus_inference_error", "code": status}})
}
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if len(s.APIKey) < 32 || subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.APIKey)) != 1 {
			apiError(w, 401, "inference bearer token required")
			return
		}
		if r.URL.Path == "/v1/generations" || r.URL.Path == "/v1/reviews" {
			if s.Meld == nil {
				apiError(w, 503, "Meld runtime is not configured; GGUF text generation cannot execute image generation or visual quality review")
				return
			}
			s.Meld.ServeHTTP(w, r)
			return
		}
		switch {
		case r.URL.Path == "/v1/inference/policy" && r.Method == http.MethodGet:
			hashes := []string{}
			for _, a := range s.Scheduler.cfg.ApprovedModels {
				hashes = append(hashes, a.SHA256)
			}
			writeJSON(w, 200, map[string]any{"scope": "models_and_model_derivatives", "denied_publisher_jurisdictions": []string{"CN", "HK", "MO"}, "unknown_provenance": "deny", "approved_sha256": hashes, "approval_basis": "operator-reviewed evidence with complete declared model lineage, or an explicit exact-SHA256 publisher-disclosed-lineage exception pinned to identical provenance and a review note"})
		case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
			writeJSON(w, 200, map[string]any{"service": "nucleus-inference", "state": "gateway_online", "note": "does not attest image, review or model readiness"})
		case r.URL.Path == "/v1/models" && r.Method == http.MethodGet:
			nodes, _ := s.Scheduler.Status()
			models := map[string]Model{}
			for _, n := range nodes {
				if !n.Online {
					continue
				}
				for _, m := range n.Models {
					if ApproveModel(m, s.Scheduler.cfg.ApprovedModels) != nil {
						continue
					}
					models[m.ID] = m
				}
			}
			data := []any{}
			ids := make([]string, 0, len(models))
			for id := range models {
				ids = append(ids, id)
			}
			sortStrings(ids)
			for _, id := range ids {
				m := models[id]
				data = append(data, map[string]any{"id": m.ID, "object": "model", "created": 0, "owned_by": "nucleus", "nucleus": m})
			}
			writeJSON(w, 200, map[string]any{"object": "list", "data": data})
		case r.URL.Path == "/v1/chat/completions" && r.Method == http.MethodPost:
			var req Request
			if !readJSON(w, r, &req, 1<<20) {
				return
			}
			if err := validateRequest(req); err != nil {
				apiError(w, 400, err.Error())
				return
			}
			j, events, err := s.Scheduler.Submit(r.Context(), req)
			if err != nil {
				apiError(w, 503, err.Error())
				return
			}
			defer s.Scheduler.Cancel(j.ID)
			w.Header().Set("X-Nucleus-Job-ID", j.ID)
			if req.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("X-Accel-Buffering", "no")
				w.WriteHeader(200)
				flusher, ok := w.(http.Flusher)
				if !ok {
					return
				}
				flusher.Flush()
				ticker := time.NewTicker(5 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-r.Context().Done():
						return
					case <-ticker.C:
						if _, err = io.WriteString(w, ": keepalive\n\n"); err != nil {
							return
						}
						flusher.Flush()
					case e, ok := <-events:
						if !ok {
							_, _ = io.WriteString(w, "data: [DONE]\n\n")
							flusher.Flush()
							return
						}
						if e.Error != "" {
							b, _ := json.Marshal(map[string]any{"error": map[string]string{"message": e.Error, "type": "nucleus_inference_error"}})
							if _, err = fmt.Fprintf(w, "data: %s\n\n", b); err != nil {
								return
							}
						}
						if len(e.Data) > 0 {
							if _, err = fmt.Fprintf(w, "data: %s\n\n", e.Data); err != nil {
								return
							}
						}
						flusher.Flush()
					}
				}
			}
			var result json.RawMessage
			for {
				select {
				case <-r.Context().Done():
					return
				case e, ok := <-events:
					if !ok {
						if len(result) == 0 {
							apiError(w, 502, "worker ended without a completion")
							return
						}
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write(result)
						return
					}
					if e.Error != "" {
						apiError(w, 502, e.Error)
						return
					}
					if len(e.Data) > 0 {
						result = append(result[:0], e.Data...)
					}
				}
			}
		case r.URL.Path == "/v1/inference/status" && r.Method == http.MethodGet:
			nodes, jobs := s.Scheduler.Status()
			writeJSON(w, 200, map[string]any{"nodes": nodes, "jobs": jobs, "queue_limit": s.Scheduler.cfg.QueueLimit, "limitations": []string{"one active request per worker", "running requests are never replayed", "image/review bridge executes on coordinator only"}})
		case strings.HasPrefix(r.URL.Path, "/v1/inference/jobs/"):
			id := strings.TrimPrefix(r.URL.Path, "/v1/inference/jobs/")
			if r.Method == http.MethodDelete {
				if !s.Scheduler.Cancel(id) {
					apiError(w, 404, "unknown job")
					return
				}
				w.WriteHeader(204)
				return
			}
			if r.Method == http.MethodGet {
				j, ok := s.Scheduler.Job(id)
				if !ok {
					apiError(w, 404, "unknown job")
					return
				}
				writeJSON(w, 200, j)
				return
			}
			apiError(w, 405, "method not allowed")
		default:
			http.NotFound(w, r)
		}
	})
}
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// StartAPI exposes application clients only on loopback. Fabric workers continue
// using the existing owner mTLS listener and never see this bearer credential.
func StartAPI(ctx context.Context, address string, service *Service) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errors.New("inference client API must bind a literal loopback address")
	}
	if len(service.APIKey) < 32 {
		return "", errors.New("NUCLEUS_INFERENCE_API_KEY (or config api_key) must contain at least 32 bytes")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return "", err
	}
	server := &http.Server{Handler: service.Handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: apiWriteTimeout(service), IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	go func() { _ = server.Serve(listener) }()
	go func() { <-ctx.Done(); _ = server.Close() }()
	return "http://" + listener.Addr().String(), nil
}

// apiWriteTimeout permits each enabled workload's configured execution budget
// while keeping a finite deadline for clients that stop consuming a response.
func apiWriteTimeout(service *Service) time.Duration {
	budget := time.Duration(service.Scheduler.cfg.RequestTimeoutSeconds) * time.Second
	if workload, ok := service.Meld.(interface{ RequestTimeout() time.Duration }); ok {
		if configured := workload.RequestTimeout(); configured > budget {
			budget = configured
		}
	}
	return budget + 30*time.Second
}
