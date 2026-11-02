package hostedworker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inference"
)

// Opt in with NUCLEUS_PHP_APP=/path/to/Marketing/apps/nucleus-dashboard.
// Every PHP process gets an explicit synthetic environment and exclusive SQLite.
func TestPHPHostedWorkProtocol(t *testing.T) {
	appPath := os.Getenv("NUCLEUS_PHP_APP")
	if appPath == "" {
		t.Skip("set NUCLEUS_PHP_APP for isolated cross-language integration")
	}
	appPath, err := filepath.Abs(appPath)
	if err != nil {
		t.Fatal(err)
	}
	php := os.Getenv("NUCLEUS_PHP_BIN")
	if php == "" {
		php, err = exec.LookPath("php8.5")
		if err != nil {
			t.Skip("PHP8.5 is required for the opt-in integration")
		}
	}
	if _, err = os.Stat(filepath.Join(appPath, "vendor/autoload.php")); err != nil {
		t.Fatal("local PHP dependencies are required")
	}
	fixture, err := os.MkdirTemp("/tmp", "nucleus-work-integration-")
	if err != nil {
		t.Fatal(err)
	}
	var finalMetadata func() map[string]any
	defer func() {
		defer os.RemoveAll(fixture)
		if finalMetadata != nil {
			snapshot := finalMetadata()
			if directory := os.Getenv("NUCLEUS_PHP_RECEIPT_DIR"); directory != "" {
				_ = os.MkdirAll(directory, 0700)
				data, _ := json.MarshalIndent(snapshot, "", "  ")
				_ = os.WriteFile(filepath.Join(directory, "php-work-safe-final-meta.json"), data, 0600)
			}
		}
	}()
	for _, dir := range []string{"storage/framework/cache/data", "storage/framework/views", "storage/framework/sessions", "storage/logs", "bootstrap/cache", "node"} {
		if err = os.MkdirAll(filepath.Join(fixture, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	database := filepath.Join(fixture, "fixture.sqlite")
	if err = os.WriteFile(database, nil, 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "http://" + address
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 8)
	_, _ = rand.Read(prefix)
	env := []string{
		"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + fixture, "LANG=C.UTF-8",
		"APP_ENV=testing", "APP_DEBUG=false", "APP_NAME=Nucleus isolated work fixture",
		"APP_KEY=base64:" + base64.StdEncoding.EncodeToString(key), "APP_URL=" + origin, "ASSET_URL=" + origin + "/dashboard",
		"APP_CONFIG_CACHE=" + filepath.Join(fixture, "bootstrap/cache/config.php"),
		"APP_ROUTES_CACHE=" + filepath.Join(fixture, "bootstrap/cache/routes.php"),
		"APP_SERVICES_CACHE=" + filepath.Join(fixture, "bootstrap/cache/services.php"),
		"APP_PACKAGES_CACHE=" + filepath.Join(fixture, "bootstrap/cache/packages.php"),
		"LARAVEL_STORAGE_PATH=" + filepath.Join(fixture, "storage"),
		"VIEW_COMPILED_PATH=" + filepath.Join(fixture, "storage/framework/views"),
		"DB_CONNECTION=sqlite", "DB_DATABASE=" + database, "DB_FOREIGN_KEYS=true", "DB_BUSY_TIMEOUT=5000",
		"CACHE_STORE=file", "CACHE_PREFIX=isolated-work-" + hex.EncodeToString(prefix),
		"SESSION_DRIVER=array", "SESSION_SECURE_COOKIE=false", "QUEUE_CONNECTION=sync", "LOG_CHANNEL=single",
		"NEXUS_URL=http://127.0.0.1:1", "OAUTH_BASEURL=http://127.0.0.1:1",
		"OAUTH_CLIENT_ID=synthetic-only", "OAUTH_CLIENT_SECRET=synthetic-only",
		"STRIPE_SECRET=", "STRIPE_ACCOUNT_ID=", "NUCLEUS_CHECKOUT_ENABLED=false",
		"PHP_CLI_SERVER_WORKERS=4", "NUCLEUS_PHP_APP=" + appPath,
	}
	run := func(args ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, php, args...)
		command.Dir = appPath
		command.Env = env
		output, e := command.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated PHP fixture failed (%v): %s", e, output)
		}
		return output
	}
	run("-r", phpIsolationGuard, appPath, database, origin)
	run("artisan", "migrate", "--force", "--no-interaction")
	home := filepath.Join(fixture, "node")
	if _, err = fabric.Init(home, "synthetic-hosted-worker"); err != nil {
		t.Fatal(err)
	}
	state, public, err := fabric.CloudIdentity(home)
	if err != nil {
		t.Fatal(err)
	}
	modelID := "synthetic-protocol-model"
	modelSHA := strings.Repeat("b", 64)
	revision := strings.Repeat("a", 40)
	modelSize := uint64(64)
	realPath := os.Getenv("NUCLEUS_REAL_FLEET_CONFIG")
	fakeDelay := 0
	if raw := os.Getenv("NUCLEUS_FAKE_RAG_DELAY_SECONDS"); raw != "" {
		value, e := strconv.Atoi(raw)
		if e != nil || value < 1 || value > 100 {
			t.Fatal("fake RAG delay must be1..100seconds")
		}
		fakeDelay = value
	}
	var approved inference.FleetConfig
	if realPath != "" {
		if os.Getenv("NUCLEUS_ALLOW_REAL_INFERENCE") != "1" {
			t.Fatal("real inference needs the separate explicit opt-in")
		}
		file, e := openRegular(realPath)
		if e != nil {
			t.Fatal("approved runtime profile unavailable")
		}
		var selected struct {
			Runtime        *inference.RuntimeConfig  `json:"runtime"`
			ApprovedModels []inference.ModelApproval `json:"approved_models"`
		}
		e = json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&selected)
		file.Close()
		if e != nil || selected.Runtime == nil || len(selected.Runtime.Models) != 1 {
			t.Fatal("approved runtime metadata invalid")
		}
		rt := selected.Runtime
		if rt.Threads != 2 || rt.ContextLength != 1024 || rt.MaxTokens != 64 || rt.MemoryLimitBytes != 8<<30 || rt.ReserveMemoryBytes != 1<<30 {
			t.Fatal("approved CPU budget differs")
		}
		if os.Getenv("NUCLEUS_SHIPPING_PROFILE") == "1" {
			rt.ContextLength = 8192
			rt.MaxTokens = 256
		}
		rt.ApprovedModels = selected.ApprovedModels
		approved = inference.FleetConfig{Runtime: rt, ApprovedModels: selected.ApprovedModels}
		model := rt.Models[0]
		if e = inference.ApproveModel(model.Model, selected.ApprovedModels); e != nil {
			t.Fatal("approved model admission rejected")
		}
		modelID = model.ID
		modelSHA = model.SHA256
		revision = model.Revision
		modelSize = model.SizeBytes
	}

	input := map[string]string{"database": database, "origin": origin, "node_id": state.NodeID, "public_key": base64.StdEncoding.EncodeToString(public), "model_id": modelID, "sha256": modelSHA, "revision": revision, "model_size": fmt.Sprint(modelSize)}
	inputPath := filepath.Join(fixture, "fixture-input.json")
	raw, _ := json.Marshal(input)
	_ = os.WriteFile(inputPath, raw, 0600)
	helper := filepath.Join(fixture, "fixture.php")
	if err = os.WriteFile(helper, []byte(phpWorkFixture), 0600); err != nil {
		t.Fatal(err)
	}
	action := func(name string, arguments ...string) map[string]any {
		t.Helper()
		args := []string{helper, appPath, name, inputPath}
		args = append(args, arguments...)
		output := run(args...)
		var result map[string]any
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("invalid isolated fixture result: %s", output)
		}
		return result
	}
	action("seed")
	finalMetadata = func() map[string]any { return action("diagnostic") }
	binding := cloud.Binding{SchemaVersion: 1, Origin: origin, BasePath: "/dashboard", NodeID: state.NodeID, OrganizationID: "201", HeartbeatIntervalSeconds: 60, RegisteredAt: time.Now()}
	raw, _ = json.Marshal(binding)
	_ = os.WriteFile(filepath.Join(home, "cloud.json"), raw, 0600)
	router := filepath.Join(fixture, "router.php")
	_ = os.WriteFile(router, []byte("<?php require getenv('NUCLEUS_PHP_APP').'/public/index.php';"), 0600)
	log, err := os.OpenFile(filepath.Join(fixture, "php.log"), os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	server := exec.Command(php, "-S", address, router)
	server.Dir = appPath
	server.Env = env
	server.Stdout = log
	server.Stderr = log
	server.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err = server.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- server.Wait() }()
	defer func() {
		_ = syscall.Kill(-server.Process.Pid, syscall.SIGTERM)
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			_ = syscall.Kill(-server.Process.Pid, syscall.SIGKILL)
			<-stopped
		}
		log.Close()
	}()
	client, err := cloud.New(home, origin+"/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	ready := false
	httpClient := &http.Client{Timeout: time.Second}
	for i := 0; i < 60; i++ {
		response, e := httpClient.Get(origin + "/dashboard/up")
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated PHP server did not become ready")
	}
	t.Log("isolated four-worker PHP server:", origin, "(no external auth/Stripe/weights)")
	if err = client.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	caps := cloud.WorkCapabilities{JobTypes: []string{"infer"}, Models: []cloud.WorkModel{{ID: modelID, SHA256: modelSHA, Revision: revision}}, MaxConcurrentJobs: 1, ApprovedModelSHA256s: []string{modelSHA}, RuntimeLimits: &cloud.RuntimeLimits{MemoryLimitBytes: 256 << 20, ContextLength: 128, MaxTokens: 8}}
	if realPath != "" || fakeDelay > 0 {
		var backend inference.Backend
		var e error
		if realPath != "" {
			backend, e = inference.NewRuntime(context.Background(), *approved.Runtime)
			if e != nil {
				t.Fatal("approved runtime initialization failed")
			}
		} else {
			approved.Runtime = &inference.RuntimeConfig{Threads: 2, ContextLength: 1024, MaxTokens: 64, MemoryLimitBytes: 8 << 30, ReserveMemoryBytes: 1 << 30}
			backend = &delayedRAGBackend{delay: time.Duration(fakeDelay) * time.Second, model: inference.Model{ID: modelID}}
		}
		defer backend.Close()
		caps.Models = []cloud.WorkModel{{ID: modelID, SHA256: modelSHA, Revision: revision}}
		caps.RuntimeLimits = &cloud.RuntimeLimits{MemoryLimitBytes: approved.Runtime.MemoryLimitBytes, ContextLength: approved.Runtime.ContextLength, MaxTokens: approved.Runtime.MaxTokens}
		realExecutor := &phpRealExecutor{caps: caps, manager: &Manager{cfg: approved, backend: backend}}
		observation := &observedControl{client: client}
		if _, e = client.LeaseWork(context.Background(), caps); e != nil {
			t.Fatal("real node capability registration failed")
		}
		token := action("issue-key")["secret"].(string)
		requestJSON := func(path string, payload any) map[string]any {
			t.Helper()
			data, _ := json.Marshal(payload)
			request, _ := http.NewRequest("POST", origin+path, strings.NewReader(string(data)))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Accept", "application/json")
			request.Header.Set("Authorization", "Bearer "+token)
			response, e := (&http.Client{Timeout: 125 * time.Second}).Do(request)
			if e != nil {
				t.Fatal("isolated real acceptance request failed")
			}
			defer response.Body.Close()
			var value map[string]any
			if response.StatusCode != 200 && response.StatusCode != 201 {
				var rejected map[string]any
				_ = json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&rejected)
				code := "unclassified"
				if value, ok := rejected["error"].(string); ok && len(value) < 100 && !strings.ContainsAny(value, " /\\\n\r\t") {
					code = value
				}
				diagnostic := action("diagnostic")
				failure := map[string]any{"http_status": response.StatusCode, "safe_code": code, "jobs": diagnostic, "runtime_category": realExecutor.lastError.Load(), "renewals": observation.renewals.Load(), "renew_errors": observation.renewErrors.Load()}
				if directory := os.Getenv("NUCLEUS_PHP_RECEIPT_DIR"); directory != "" {
					_ = os.MkdirAll(directory, 0700)
					data, _ := json.MarshalIndent(failure, "", "  ")
					_ = os.WriteFile(filepath.Join(directory, "failed-real-context.json"), data, 0600)
				}
				data, _ := json.Marshal(failure)
				t.Log(string(data))
				t.Fatalf("isolated real acceptance HTTP%d", response.StatusCode)
			}
			if json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&value) != nil {
				t.Fatal("invalid real acceptance response")
			}
			return value
		}
		document := requestJSON("/dashboard/api/context/documents", map[string]any{"title": "Launch note", "body": "The organization launch codename is ORBIT-73.", "tags": []string{"launch"}})
		documentID, _ := document["id"].(string)
		if nested, ok := document["document"].(map[string]any); ok {
			documentID, _ = nested["id"].(string)
		}
		if documentID == "" {
			t.Fatal("context document response has no ID")
		}
		worker, e := New(home, observation, realExecutor, nil)
		if e != nil {
			t.Fatal(e)
		}
		runCtx, cancelWorker := context.WithCancel(context.Background())
		defer cancelWorker()
		finalMetadata = func() map[string]any {
			return map[string]any{"jobs": action("diagnostic"), "renewals": observation.renewals.Load(), "renew_errors": observation.renewErrors.Load(), "runtime_category": realExecutor.lastError.Load()}
		}
		workerDone := make(chan error, 1)
		go func() { workerDone <- worker.Run(runCtx, false) }()
		began := time.Now()
		schemaOnly := os.Getenv("NUCLEUS_SCHEMA_ONLY") == "1"
		maxTokens := 16
		if schemaOnly {
			maxTokens = 32
		}
		format := map[string]any{"type": "json_schema", "json_schema": map[string]any{"name": "codename_answer", "strict": true, "schema": map[string]any{"type": "object", "properties": map[string]any{"codename": map[string]any{"type": "string"}}, "required": []string{"codename"}, "additionalProperties": false}}}
		writeEvidence := func(name string, value any) {
			if directory := os.Getenv("NUCLEUS_PHP_RECEIPT_DIR"); directory != "" {
				_ = os.MkdirAll(directory, 0700)
				data, _ := json.MarshalIndent(value, "", "  ")
				_ = os.WriteFile(filepath.Join(directory, name), data, 0600)
			}
		}
		boundedOutput := func(text string) string {
			if len(text) > 2048 {
				return text[:2048]
			}
			return text
		}
		input := map[string]any{"model": modelID, "messages": []map[string]string{{"role": "user", "content": "What is our launch codename? Answer only the codename."}}, "context_query": "launch codename", "max_tokens": maxTokens, "temperature": 0, "stream": false}
		if schemaOnly {
			input["response_format"] = format
		}
		completion := requestJSON("/dashboard/api/v1/chat/completions", input)
		choices, ok := completion["choices"].([]any)
		if !ok || len(choices) == 0 {
			t.Fatal("real completion missing choices")
		}
		choice, _ := choices[0].(map[string]any)
		message, _ := choice["message"].(map[string]any)
		text, _ := message["content"].(string)
		if schemaOnly {
			writeEvidence("php-schema-only-output.json", map[string]any{"real_gemma": realPath != "", "output": boundedOutput(text), "output_truncated": len(text) > 2048, "finish_reason": choice["finish_reason"], "usage": completion["usage"], "response_format_type": "json_schema", "max_tokens": 32, "no_weight_download_or_copy": true})
		}
		sources, ok := completion["sources"].([]any)
		if !ok || len(sources) == 0 {
			t.Fatal("real completion missing context citation")
		}
		citation, _ := sources[0].(map[string]any)
		if !strings.Contains(text, "ORBIT-73") || citation["document_id"] != documentID {
			t.Fatal("real context answer or document citation mismatch")
		}
		var structured map[string]any
		if schemaOnly {
			var value map[string]any
			if json.Unmarshal([]byte(text), &value) != nil || value["codename"] != "ORBIT-73" {
				t.Fatal("schema-only codename object mismatch; bounded output retained")
			}
			structured = map[string]any{"json_schema": true, "codename": value["codename"], "same_document_citation": true}
		} else {
			writeEvidence("php-real-or-fake-plain-context.json", map[string]any{"real_gemma": realPath != "", "output": boundedOutput(text), "document_id": documentID, "citation": citation["citation"], "same_document_citation": true, "finish_reason": choice["finish_reason"], "model_id": modelID, "model_sha256": modelSHA, "max_tokens": 16, "no_weight_download_or_copy": true})
		}
		if !schemaOnly && os.Getenv("NUCLEUS_STRUCTURED_OUTPUT_TEST") == "1" {
			answer := requestJSON("/dashboard/api/v1/chat/completions", map[string]any{"model": modelID, "messages": []map[string]string{{"role": "user", "content": "What is our launch codename? Answer only the codename."}}, "context_query": "launch codename", "max_tokens": 16, "temperature": 0, "stream": false, "response_format": format})
			entries, ok := answer["choices"].([]any)
			if !ok || len(entries) == 0 {
				t.Fatal("structured completion missing choices")
			}
			entry, _ := entries[0].(map[string]any)
			msg, _ := entry["message"].(map[string]any)
			content, _ := msg["content"].(string)
			writeEvidence("php-structured-context-output.json", map[string]any{"real_gemma": realPath != "", "output": boundedOutput(content), "output_truncated": len(content) > 2048, "finish_reason": entry["finish_reason"], "model_id": modelID, "max_tokens": 16, "response_format_type": "json_schema", "usage": answer["usage"], "no_weight_download_or_copy": true})
			var value map[string]any
			if json.Unmarshal([]byte(content), &value) != nil || value["codename"] != "ORBIT-73" {
				t.Fatal("structured codename schema did not produce the expected object")
			}
			answerSources, ok := answer["sources"].([]any)
			if !ok || len(answerSources) == 0 {
				t.Fatal("structured answer missing context citation")
			}
			source, _ := answerSources[0].(map[string]any)
			if source["document_id"] != documentID {
				t.Fatal("structured answer cited wrong document")
			}
			structured = map[string]any{"json_schema": true, "codename": value["codename"], "same_document_citation": true}
		}
		cancelWorker()
		if e = <-workerDone; e != nil {
			t.Fatal("real worker did not finish cleanly")
		}
		receipt := map[string]any{"scope": "isolated_local_php_go_runtime", "real_gemma": realPath != "", "schema_only": schemaOnly, "structured_output": structured, "fake_delay_seconds": fakeDelay, "signed_php_go_php": true, "output": boundedOutput(text), "finish_reason": choice["finish_reason"], "usage": completion["usage"], "model_id": modelID, "model_sha256": modelSHA, "document_id": documentID, "citation": citation["citation"], "same_document_citation": true, "renewals": observation.renewals.Load(), "renew_errors": observation.renewErrors.Load(), "elapsed_ms": time.Since(began).Milliseconds(), "cpu_threads": 2, "context_length": approved.Runtime.ContextLength, "configured_max_tokens": approved.Runtime.MaxTokens, "runtime_metrics": realExecutor.lastMetrics.Load(), "max_tokens": maxTokens, "process_budget_bytes": 8 << 30, "host_reserve_bytes": 1 << 30, "no_weight_download_or_copy": true, "isolated_database": true}
		if directory := os.Getenv("NUCLEUS_PHP_RECEIPT_DIR"); directory != "" {
			if !filepath.IsAbs(directory) {
				t.Fatal("receipt directory must be absolute")
			}
			name := fmt.Sprintf("php-delayed-fake-context-%ds.json", fakeDelay)
			if realPath != "" {
				name = "php-real-gemma-context.json"
				if schemaOnly {
					name = "php-real-gemma-schema32.json"
					if os.Getenv("NUCLEUS_SHIPPING_PROFILE") == "1" {
						name = "php-real-gemma-shipping8192-schema32.json"
					}
				}
			}
			writeEvidence(name, receipt)
		}

		data, _ := json.Marshal(receipt)
		t.Log(string(data))
		return
	}
	queued := action("enqueue")
	jobID := queued["id"].(string)
	executor := &phpFakeExecutor{caps: caps, run: func(ctx context.Context, emit func(json.RawMessage) error) (json.RawMessage, error) {
		if !pause(ctx, 150*time.Millisecond) {
			return nil, ctx.Err()
		}
		for _, frame := range []json.RawMessage{
			json.RawMessage(`{"data":{"choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}}`),
			json.RawMessage(`{"data":{"choices":[{"index":0,"delta":{"content":"hello"},"finish_reason":null}]}}`),
			json.RawMessage(`{"data":{"choices":[{"index":0,"delta":{"content":null},"finish_reason":"stop"}]}}`),
		} {
			if err := emit(frame); err != nil {
				return nil, err
			}
		}
		return json.RawMessage(`{"metrics":{"prompt_tokens":2,"generation_tokens":1}}`), nil
	}}
	control := &lostAckControl{client: client}
	worker, err := New(home, control, executor, nil)
	if err != nil {
		t.Fatal(err)
	}
	worker.renewEvery = 20 * time.Millisecond
	worker.retryEvery = time.Millisecond
	worker.flushEvery = 5 * time.Millisecond
	if err = worker.Run(context.Background(), true); err != nil {
		t.Fatal("signed worker round trip:", err)
	}
	snapshot := action("snapshot", jobID)
	if snapshot["state"] != "completed" || snapshot["text"] != "hello" || snapshot["last_sequence"] != float64(5) || snapshot["result_encrypted"] != true {
		t.Fatalf("completion mismatch: %#v", snapshot)
	}
	if snapshot["finish_reason"] != "stop" {
		t.Fatal("finish frame reason was not preserved")
	}
	if control.renewals.Load() < 1 || !control.lost.Load() {
		t.Fatal("renewal or lost-ack retry was not exercised")
	}
	// Actual PHP nonce replay protection on the work endpoint.
	body, _ := json.Marshal(map[string]any{"schema_version": 1, "capabilities": caps})
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := fmt.Sprint(time.Now().Unix())
	path := "/dashboard/api/nodes/" + state.NodeID + "/work/lease"
	signature, err := fabric.SignCloud(home, []byte(cloud.RequestMessage("POST", origin, path, timestamp, nonce, body)))
	if err != nil {
		t.Fatal(err)
	}
	replayStatuses := []int{}
	for i := 0; i < 2; i++ {
		request, _ := http.NewRequest("POST", origin+path, strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-Nucleus-Timestamp", timestamp)
		request.Header.Set("X-Nucleus-Nonce", nonce)
		request.Header.Set("X-Nucleus-Signature", base64.StdEncoding.EncodeToString(signature))
		response, e := httpClient.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		replayStatuses = append(replayStatuses, response.StatusCode)
	}
	if replayStatuses[0] != 200 || replayStatuses[1] != 409 {
		t.Fatalf("work nonce replay statuses:%v", replayStatuses)
	}
	cancelJob := action("enqueue")["id"].(string)
	started := make(chan struct{})
	backendStopped := make(chan struct{})
	executor.run = func(ctx context.Context, _ func(json.RawMessage) error) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		close(backendStopped)
		return nil, ctx.Err()
	}
	jobDone := make(chan error, 1)
	go func() { jobDone <- worker.Run(context.Background(), true) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("cancel fixture job not started")
	}
	action("cancel", cancelJob)
	select {
	case e := <-jobDone:
		if !errors.Is(e, ErrCancelled) {
			t.Fatalf("cancel did not reach Go backend: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not stop worker")
	}
	select {
	case <-backendStopped:
	default:
		t.Fatal("backend cancellation not awaited")
	}
	cancelled := action("snapshot", cancelJob)
	if cancelled["state"] != "cancelled" {
		t.Fatal(cancelled)
	}
	receipt := map[string]any{"signed_lease": true, "renewals": control.renewals.Load(), "lost_completion_ack_retried_idempotently": true, "completed": snapshot, "cancelled": cancelled, "nonce_replay_statuses": replayStatuses, "no_real_model_or_download": true, "isolated_database": true, "server_origin": origin}
	if directory := os.Getenv("NUCLEUS_PHP_RECEIPT_DIR"); directory != "" {
		if !filepath.IsAbs(directory) {
			t.Fatal("receipt directory must be absolute")
		}
		if err = os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(receipt, "", "  ")
		if err = os.WriteFile(filepath.Join(directory, "php-work-protocol.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, _ := json.Marshal(receipt)
	t.Log(string(data))
}

type phpFakeExecutor struct {
	caps cloud.WorkCapabilities
	run  func(context.Context, func(json.RawMessage) error) (json.RawMessage, error)
}

func (e *phpFakeExecutor) Capabilities() cloud.WorkCapabilities { return e.caps }
func (e *phpFakeExecutor) Execute(ctx context.Context, _ cloud.WorkLease, emit func(json.RawMessage) error) (json.RawMessage, error) {
	return e.run(ctx, emit)
}
func (e *phpFakeExecutor) Close() error { return nil }

type lostAckControl struct {
	client   *cloud.Client
	lost     atomic.Bool
	renewals atomic.Int32
	mu       sync.Mutex
}

func (c *lostAckControl) LeaseWork(ctx context.Context, caps cloud.WorkCapabilities) (cloud.WorkPoll, error) {
	return c.client.LeaseWork(ctx, caps)
}
func (c *lostAckControl) RenewWork(ctx context.Context, job cloud.WorkLease, seq int64) (cloud.WorkRenewal, error) {
	c.renewals.Add(1)
	return c.client.RenewWork(ctx, job, seq)
}
func (c *lostAckControl) SendWorkEvents(ctx context.Context, job cloud.WorkLease, events []cloud.WorkEvent) (cloud.WorkAcknowledgment, error) {
	ack, err := c.client.SendWorkEvents(ctx, job, events)
	if err == nil && events[len(events)-1].Type == "completed" && c.lost.CompareAndSwap(false, true) {
		return cloud.WorkAcknowledgment{}, errors.New("synthetic response loss after actual PHP acceptance")
	}
	return ack, err
}

type observedControl struct {
	client      *cloud.Client
	renewals    atomic.Int32
	renewErrors atomic.Int32
}

func (c *observedControl) LeaseWork(ctx context.Context, caps cloud.WorkCapabilities) (cloud.WorkPoll, error) {
	return c.client.LeaseWork(ctx, caps)
}
func (c *observedControl) RenewWork(ctx context.Context, job cloud.WorkLease, seq int64) (cloud.WorkRenewal, error) {
	c.renewals.Add(1)
	result, err := c.client.RenewWork(ctx, job, seq)
	if err != nil {
		c.renewErrors.Add(1)
	}
	return result, err
}
func (c *observedControl) SendWorkEvents(ctx context.Context, job cloud.WorkLease, events []cloud.WorkEvent) (cloud.WorkAcknowledgment, error) {
	return c.client.SendWorkEvents(ctx, job, events)
}

type delayedRAGBackend struct {
	delay time.Duration
	model inference.Model
}

func (b *delayedRAGBackend) Models() []inference.Model { return []inference.Model{b.model} }
func (b *delayedRAGBackend) Close() error              { return nil }
func (b *delayedRAGBackend) Run(ctx context.Context, request inference.Request, emit func(inference.Event) error) error {
	if !pause(ctx, b.delay) {
		return ctx.Err()
	}
	text := "ORBIT-73"
	if len(request.ResponseFormat) > 0 {
		var format map[string]any
		if json.Unmarshal(request.ResponseFormat, &format) != nil || format["type"] != "json_schema" {
			return errors.New("schema was not forwarded")
		}
		text = `{"codename":"ORBIT-73"}`
	}
	data, _ := json.Marshal(map[string]any{"choices": []map[string]any{{"delta": map[string]string{"content": text}}}})
	if err := emit(inference.Event{Data: json.RawMessage(`{"choices":[{"index":0,"delta":{"role":"assistant","content":null},"finish_reason":null}]}`)}); err != nil {
		return err
	}
	if err := emit(inference.Event{Data: data}); err != nil {
		return err
	}
	if err := emit(inference.Event{Data: json.RawMessage(`{"choices":[{"index":0,"delta":{"content":null},"finish_reason":"stop"}]}`)}); err != nil {
		return err
	}
	return emit(inference.Event{Done: true, Metrics: &inference.Metrics{PromptTokens: 2, GenerationTokens: 4}})
}

type phpRealExecutor struct {
	caps        cloud.WorkCapabilities
	manager     *Manager
	lastError   atomic.Value
	lastMetrics atomic.Value
}

func (e *phpRealExecutor) Capabilities() cloud.WorkCapabilities { return e.caps }
func (e *phpRealExecutor) Execute(ctx context.Context, job cloud.WorkLease, emit func(json.RawMessage) error) (json.RawMessage, error) {
	result, err := e.manager.infer(ctx, job.Payload, emit)
	if err != nil {
		e.lastError.Store(runtimeFailureCategory(err))
	} else {
		var value struct {
			Metrics *inference.Metrics `json:"metrics"`
		}
		if json.Unmarshal(result, &value) == nil && value.Metrics != nil {
			e.lastMetrics.Store(*value.Metrics)
		}
	}
	return result, err
}
func runtimeFailureCategory(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "context_deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "context_cancelled"
	}
	text := err.Error()
	for code := 400; code <= 599; code++ {
		if strings.Contains(text, fmt.Sprintf("llama.cpp rejected inference (%d)", code)) {
			return fmt.Sprintf("runtime_rejected_http_%d", code)
		}
	}
	for _, entry := range []struct{ match, category string }{
		{"insufficient available RAM", "insufficient_ram"}, {"llama-server initialization", "startup_timeout"}, {"exited during load", "process_exit_during_load"},
		{"address-space", "address_space_budget"}, {"stream disconnected", "truncated_stream"}, {"did not return SSE", "not_sse"},
		{"CPU inference request", "runtime_transport"}, {"status", "runtime_http_status"}, {"invalid", "invalid_runtime_response"}, {"without a completion", "missing_completion_marker"},
	} {
		if strings.Contains(text, entry.match) {
			return entry.category
		}
	}
	return "runtime_failed_unspecified"
}
func (e *phpRealExecutor) Close() error { return nil }

const phpWorkFixture = `<?php
try{
 $base=$argv[1];$action=$argv[2];$input=json_decode(file_get_contents($argv[3]),true,512,JSON_THROW_ON_ERROR);
 require $base.'/vendor/autoload.php';$app=require $base.'/bootstrap/app.php';$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
 if(config('database.default')!=='sqlite'||config('database.connections.sqlite.database')!==$input['database']||config('app.url')!==$input['origin']||config('nucleus.cloud.origin')!==$input['origin']||config('nexus.url')!=='http://127.0.0.1:1'){throw new RuntimeException('Fixture isolation guard failed');}
 if($action==='seed'){
  (require dirname(base_path(),2).'/database/migrations/2026_11_01_000000_create_nucleus_billing_tables.php')->up();
  App\Models\User::create(['id'=>101,'name'=>'Synthetic isolated owner','email'=>'owner@fixture.example.test','email_verified_at'=>now(),'current_team_id'=>201,'nexus_synced_at'=>now()]);
  $team=App\Models\Team::create(['id'=>201,'user_id'=>101,'name'=>'Synthetic isolated team','personal_team'=>false,'nexus_synced_at'=>now()]);
  $account=App\Models\NucleusBillingAccount::create(['plan'=>'managed','machines'=>5,'status'=>'active','entitlement_status'=>'active','stripe_customer_id'=>'cus_SYNTHETIC_ONLY','stripe_subscription_id'=>'sub_SYNTHETIC_ONLY','paid_through'=>now()->addDay()]);
  App\Models\HostedSubscription::create(['team_id'=>201,'billing_account_id'=>$account->id]);
  $node=App\Models\HostedNode::create(['team_id'=>201,'node_id'=>$input['node_id'],'public_key'=>$input['public_key'],'hostname'=>'synthetic-worker','platform'=>'linux','arch'=>'amd64','version'=>'0.3.0-alpha','approved_by'=>101,'last_seen_at'=>now()]);
  App\Models\HostedModelDeployment::create(['team_id'=>201,'node_id'=>$node->id,'catalog_id'=>'synthetic-fixture','model_id'=>$input['model_id'],'sha256'=>$input['sha256'],'status'=>'ready','size_bytes'=>(int)$input['model_size'],'progress_bytes'=>(int)$input['model_size']]);
  echo json_encode(['seeded'=>true]);exit;
 }
 $node=App\Models\HostedNode::where('node_id',$input['node_id'])->firstOrFail();$team=App\Models\Team::findOrFail(201);$work=app(App\Services\NucleusWorkService::class);
 if($action==='issue-key'){$issued=app(App\Services\NucleusApiKeys::class)->issue($team,['name'=>'isolated-real-test','scopes'=>['context:read','context:write','inference:run']],101);echo json_encode(['secret'=>$issued['secret']]);exit;}
 if($action==='enqueue'){
  $deployment=App\Models\HostedModelDeployment::where('node_id',$node->id)->firstOrFail();
  $job=$work->enqueue($team,$node,'infer',['request'=>['model'=>$input['model_id'],'messages'=>[['role'=>'user','content'=>'synthetic prompt']],'max_tokens'=>8]],$deployment,101);
  echo json_encode(['id'=>$job->id]);exit;
 }
 if($action==='diagnostic'){echo json_encode(['jobs'=>App\Models\HostedWork::get()->map(fn($j)=>['state'=>$j->state,'error'=>$j->error,'last_sequence'=>$j->last_sequence,'finish_reason'=>data_get($j->result,'completion.choices.0.finish_reason'),'usage'=>data_get($j->result,'completion.usage'),'lease_seconds_remaining'=>$j->lease_expires_at?->timestamp-time(),'deadline_seconds_remaining'=>$j->deadline_at->timestamp-time(),'event_types'=>App\Models\HostedWorkEvent::where('work_id',$j->id)->orderBy('sequence')->pluck('type')])]);exit;}
 $job=App\Models\HostedWork::findOrFail($argv[4]);
 if($action==='cancel'){$work->cancel($job);echo json_encode(['cancelled'=>true]);exit;}
 if($action==='snapshot'){
  $job=$job->fresh();$raw=Illuminate\Support\Facades\DB::table('nucleus_dashboard_work')->where('id',$job->id)->value('result');
  $events=App\Models\HostedWorkEvent::where('work_id',$job->id)->orderBy('sequence')->get(['sequence','type']);
  echo json_encode(['state'=>$job->state,'text'=>$job->result['text']??'','finish_reason'=>data_get($job->result,'completion.choices.0.finish_reason'),'last_sequence'=>$job->last_sequence,'events'=>$events,'result_encrypted'=>$raw!==null&&!str_contains($raw,'hello')]);exit;
 }
 throw new RuntimeException('Unknown fixture action');
}catch(Throwable $e){fwrite(STDERR,json_encode(['fixture_failed'=>true,'type'=>get_class($e),'code'=>$e->getCode()]).PHP_EOL);exit(1);}
`

const phpIsolationGuard = `require $argv[1].'/vendor/autoload.php';$app=require $argv[1].'/bootstrap/app.php';$app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();if(!$app->environment('testing')||config('database.default')!=='sqlite'||config('database.connections.sqlite.database')!==$argv[2]||config('app.url')!==$argv[3]||config('nexus.url')!=='http://127.0.0.1:1'||config('services.stripe.secret')!==''){fwrite(STDERR,"Fixture isolation rejected\n");exit(1);}echo "Fixture isolation checked\n";`
