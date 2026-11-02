package hostedworker

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
)

type fakeControl struct {
	mu               sync.Mutex
	job              cloud.WorkLease
	records          map[int64]string
	calls            [][]cloud.WorkEvent
	renewState       string
	failAcceptedType string
	failed           bool
	terminalAccepted bool
}

func (f *fakeControl) LeaseWork(context.Context, cloud.WorkCapabilities) (cloud.WorkPoll, error) {
	return cloud.WorkPoll{Work: &f.job, RetryAfterSeconds: 1}, nil
}
func (f *fakeControl) RenewWork(context.Context, cloud.WorkLease, int64) (cloud.WorkRenewal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.terminalAccepted {
		return cloud.WorkRenewal{}, &cloud.APIError{Status: 409, Code: "lease_lost"}
	}
	if f.renewState == "lost" {
		return cloud.WorkRenewal{}, &cloud.APIError{Status: 409, Code: "lease_lost"}
	}
	if f.renewState == "cancelled" {
		return cloud.WorkRenewal{State: "cancelled"}, nil
	}
	expires := time.Now().Add(60 * time.Second).UnixMilli()
	if expires > f.job.DeadlineAtMS {
		expires = f.job.DeadlineAtMS
	}
	return cloud.WorkRenewal{State: "leased", LeaseExpiresAtMS: expires}, nil
}
func (f *fakeControl) SendWorkEvents(_ context.Context, _ cloud.WorkLease, events []cloud.WorkEvent) (cloud.WorkAcknowledgment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[int64]string{}
	}
	f.calls = append(f.calls, append([]cloud.WorkEvent(nil), events...))
	state := "leased"
	for _, event := range events {
		raw, _ := json.Marshal(event)
		if previous, exists := f.records[event.Sequence]; exists && previous != string(raw) {
			return cloud.WorkAcknowledgment{}, &cloud.APIError{Status: 409, Code: "event_conflict"}
		}
		f.records[event.Sequence] = string(raw)
		if event.Type == "completed" || event.Type == "failed" || event.Type == "cancelled" {
			state = event.Type
			f.terminalAccepted = true
		}
	}
	if !f.failed && events[len(events)-1].Type == f.failAcceptedType {
		f.failed = true
		return cloud.WorkAcknowledgment{}, errors.New("response lost after durable acceptance")
	}
	return cloud.WorkAcknowledgment{AcceptedSequence: events[len(events)-1].Sequence, State: state}, nil
}

type fakeExecutor struct {
	mu      sync.Mutex
	calls   int
	execute func(context.Context, func(json.RawMessage) error) (json.RawMessage, error)
}

func (f *fakeExecutor) Capabilities() cloud.WorkCapabilities {
	return cloud.WorkCapabilities{JobTypes: []string{"infer"}, Models: []cloud.WorkModel{}, MaxConcurrentJobs: 1}
}
func (f *fakeExecutor) Execute(ctx context.Context, _ cloud.WorkLease, emit func(json.RawMessage) error) (json.RawMessage, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return f.execute(ctx, emit)
}
func (f *fakeExecutor) Close() error { return nil }
func testJob() cloud.WorkLease {
	now := time.Now()
	return cloud.WorkLease{ID: "a1234567-1234-4567-8123-123456789abc", Type: "infer", LeaseID: "b1234567-1234-4567-8123-123456789abc", LeaseToken: strings.Repeat("a", 64), LeaseExpiresAtMS: now.Add(60 * time.Second).UnixMilli(), DeadlineAtMS: now.Add(120 * time.Second).UnixMilli(), Payload: json.RawMessage(`{"request":{}}`)}
}
func testWorker(t *testing.T, control *fakeControl, executor *fakeExecutor) *Worker {
	t.Helper()
	home := t.TempDir()
	_ = os.Chmod(home, 0700)
	return &Worker{home: home, namespace: "test-bound-org", control: control, executor: executor, renewEvery: 20 * time.Millisecond, retryEvery: time.Millisecond, flushEvery: time.Millisecond, requestTimeout: time.Second}
}
func TestAcceptedEventRetryDoesNotRepeatGenerationAndJournalRejectsReplay(t *testing.T) {
	control := &fakeControl{job: testJob(), failAcceptedType: "completed"}
	executor := &fakeExecutor{execute: func(ctx context.Context, emit func(json.RawMessage) error) (json.RawMessage, error) {
		if err := emit(json.RawMessage(`{"data":{"choices":[{"delta":{"content":"hello"}}]}}`)); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"metrics":{"generation_tokens":1}}`), nil
	}}
	worker := testWorker(t, control, executor)
	worker.renewEvery = time.Millisecond
	worker.retryEvery = 20 * time.Millisecond
	if err := worker.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if executor.calls != 1 || len(control.records) != 3 {
		t.Fatalf("generation=%d events=%d", executor.calls, len(control.records))
	}
	last := control.calls[len(control.calls)-1]
	previous := control.calls[len(control.calls)-2]
	a, _ := json.Marshal(last)
	b, _ := json.Marshal(previous)
	if string(a) != string(b) || last[0].Type != "completed" {
		t.Fatal("lost acknowledgment was not retried identically")
	}
	if err := worker.Run(context.Background(), true); !errors.Is(err, ErrJobReplay) {
		t.Fatalf("replayed job: %v", err)
	}
	if executor.calls != 1 {
		t.Fatal("persisted job executed twice")
	}
}
func TestCancelAndLostLeaseStopBackendAndNeverReplay(t *testing.T) {
	for _, mode := range []string{"cancelled", "lost", "expired"} {
		t.Run(mode, func(t *testing.T) {
			control := &fakeControl{job: testJob(), renewState: mode}
			stopped := make(chan struct{})
			executor := &fakeExecutor{execute: func(ctx context.Context, _ func(json.RawMessage) error) (json.RawMessage, error) {
				<-ctx.Done()
				close(stopped)
				return nil, ctx.Err()
			}}
			worker := testWorker(t, control, executor)
			if mode == "expired" {
				control.job.LeaseExpiresAtMS = time.Now().Add(40 * time.Millisecond).UnixMilli()
				worker.renewEvery = time.Second
			}
			began := time.Now()
			err := worker.Run(context.Background(), true)
			if err == nil || time.Since(began) > time.Second {
				t.Fatalf("lease did not stop backend: %v", err)
			}
			select {
			case <-stopped:
			default:
				t.Fatal("backend cancellation was not awaited")
			}
			if err = worker.Run(context.Background(), true); !errors.Is(err, ErrJobReplay) && mode != "expired" {
				t.Fatalf("lost job replay: %v", err)
			}
			if executor.calls != 1 {
				t.Fatal("cancelled backend executed again")
			}
		})
	}
}
func TestJournalHasExclusiveProcessLockAndPrivateNoSymlinkState(t *testing.T) {
	home := t.TempDir()
	journal, err := openJournal(home, "org")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = openJournal(home, "other-org"); err == nil {
		t.Fatal("second process acquired worker lock")
	}
	if err = journal.begin("once-only"); err != nil {
		t.Fatal(err)
	}
	journal.Close()
	again, err := openJournal(home, "org")
	if err != nil {
		t.Fatal(err)
	}
	if err = again.begin("once-only"); !errors.Is(err, ErrJobReplay) {
		t.Fatal("lost durable replay guard")
	}
	again.Close()
	entries, _ := os.ReadDir(home)
	for _, entry := range entries {
		info, _ := entry.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate worker state")
		}
	}
	other := t.TempDir()
	target := filepath.Join(other, "foreign")
	_ = os.WriteFile(target, []byte("foreign"), 0600)
	_ = os.Symlink(target, filepath.Join(other, "hosted-worker.lock"))
	if _, err = openJournal(other, "org"); err == nil {
		t.Fatal("worker followed symlink lock")
	}
}
