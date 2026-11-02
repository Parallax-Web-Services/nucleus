package hostedworker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
)

var ErrJobReplay = errors.New("previously observed work will not be executed again")
var ErrLeaseLost = errors.New("hosted work lease was lost")
var ErrCancelled = errors.New("hosted work was cancelled")
var ErrLeaseExpired = errors.New("hosted work lease expired")

type Control interface {
	LeaseWork(context.Context, cloud.WorkCapabilities) (cloud.WorkPoll, error)
	RenewWork(context.Context, cloud.WorkLease, int64) (cloud.WorkRenewal, error)
	SendWorkEvents(context.Context, cloud.WorkLease, []cloud.WorkEvent) (cloud.WorkAcknowledgment, error)
}
type Executor interface {
	Capabilities() cloud.WorkCapabilities
	Execute(context.Context, cloud.WorkLease, func(json.RawMessage) error) (json.RawMessage, error)
	Close() error
}
type Worker struct {
	home           string
	namespace      string
	control        Control
	executor       Executor
	renewEvery     time.Duration
	retryEvery     time.Duration
	flushEvery     time.Duration
	requestTimeout time.Duration
	notify         func(string)
}

func New(home string, control Control, executor Executor, notify func(string)) (*Worker, error) {
	binding, err := cloud.LoadBinding(home)
	if err != nil {
		return nil, err
	}
	if binding.Revoked {
		return nil, errors.New("hosted registration is revoked")
	}
	return &Worker{home: home, namespace: binding.Origin + "\n" + binding.OrganizationID + "\n" + binding.NodeID, control: control, executor: executor, renewEvery: 10 * time.Second, retryEvery: time.Second, flushEvery: 100 * time.Millisecond, requestTimeout: 10 * time.Second, notify: notify}, nil
}
func (w *Worker) Run(ctx context.Context, once bool) error {
	j, err := openJournal(w.home, w.namespace)
	if err != nil {
		return err
	}
	defer j.Close()
	for {
		if ctx.Err() != nil {
			return nil
		}
		call, stop := context.WithTimeout(ctx, w.requestTimeout)
		poll, err := w.control.LeaseWork(call, w.executor.Capabilities())
		stop()
		if err != nil {
			if fatalAPI(err) {
				return err
			}
			if once {
				return err
			}
			if !pause(ctx, w.retryEvery) {
				return nil
			}
			continue
		}
		if poll.Work != nil {
			if err = cloud.ValidateWorkLease(*poll.Work, time.Now()); err != nil {
				return err
			}
			if err = w.runJob(ctx, j, *poll.Work); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if fatalAPI(err) {
					return err
				}
				if w.notify != nil {
					w.notify("Hosted work stopped; no execution will be replayed.")
				}
			}
			if once {
				return err
			}
		} else if once {
			return nil
		}
		delay := time.Duration(poll.RetryAfterSeconds) * time.Second
		if delay < time.Second || delay > time.Minute {
			return errors.New("invalid worker poll interval")
		}
		if !pause(ctx, delay) {
			return nil
		}
	}
}
func fatalAPI(err error) bool {
	var api *cloud.APIError
	return errors.As(err, &api) && (api.Status == http.StatusUnauthorized || api.Status == http.StatusPaymentRequired || api.Status == http.StatusForbidden)
}
func transient(err error) bool {
	var api *cloud.APIError
	if errors.As(err, &api) {
		return api.Status == 429 || api.Status >= 500
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded)
}
func pause(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

type leaseState struct {
	mu        sync.Mutex
	expires   time.Time
	ack       int64
	reason    error
	finishing bool
}

func (s *leaseState) deadline() time.Time { s.mu.Lock(); defer s.mu.Unlock(); return s.expires }
func (s *leaseState) acknowledge(n int64) { s.mu.Lock(); s.ack = n; s.mu.Unlock() }
func (s *leaseState) setReason(err error) { s.mu.Lock(); s.reason = err; s.mu.Unlock() }
func (s *leaseState) failure() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason != nil {
		return s.reason
	}
	return ErrLeaseExpired
}
func (w *Worker) supervise(ctx context.Context, cancel context.CancelFunc, job cloud.WorkLease, state *leaseState, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(w.renewEvery)
	defer ticker.Stop()
	for {
		remaining := time.Until(state.deadline())
		if remaining <= 0 {
			state.setReason(ErrLeaseExpired)
			cancel()
			return
		}
		expiry := time.NewTimer(remaining)
		select {
		case <-ctx.Done():
			expiry.Stop()
			return
		case <-expiry.C:
			state.setReason(ErrLeaseExpired)
			cancel()
			return
		case <-ticker.C:
			expiry.Stop()
			state.mu.Lock()
			sequence := state.ack
			finishing := state.finishing
			state.mu.Unlock()
			if finishing {
				continue
			}
			call, stop := context.WithDeadline(ctx, state.deadline())
			call, timeout := context.WithTimeout(call, w.requestTimeout)
			renewal, err := w.control.RenewWork(call, job, sequence)
			timeout()
			stop()
			if err != nil {
				state.mu.Lock()
				finishingNow := state.finishing
				state.mu.Unlock()
				var api *cloud.APIError
				if finishingNow && errors.As(err, &api) && api.Status == 409 {
					continue
				}
				if fatalAPI(err) || !transient(err) {
					state.setReason(err)
					cancel()
					return
				}
				continue
			}
			if renewal.State == "cancelled" {
				state.setReason(ErrCancelled)
				cancel()
				return
			}
			next := time.UnixMilli(renewal.LeaseExpiresAtMS)
			if renewal.State != "leased" || !next.After(time.Now()) || next.After(time.UnixMilli(job.DeadlineAtMS)) || next.After(time.Now().Add(65*time.Second)) {
				state.setReason(ErrLeaseLost)
				cancel()
				return
			}
			state.mu.Lock()
			state.expires = next
			state.mu.Unlock()
		}
	}
}
func (w *Worker) send(ctx context.Context, job cloud.WorkLease, state *leaseState, events []cloud.WorkEvent) error {
	for {
		if ctx.Err() != nil {
			return state.failure()
		}
		call, stop := context.WithDeadline(ctx, state.deadline())
		call, timeout := context.WithTimeout(call, w.requestTimeout)
		ack, err := w.control.SendWorkEvents(call, job, events)
		timeout()
		stop()
		if err == nil {
			if ack.AcceptedSequence != events[len(events)-1].Sequence {
				return errors.New("work event acknowledgment did not match")
			}
			if ack.State == "cancelled" {
				return ErrCancelled
			}
			expected := "leased"
			switch events[len(events)-1].Type {
			case "completed", "failed", "cancelled":
				expected = events[len(events)-1].Type
			}
			if ack.State != expected {
				return ErrLeaseLost
			}
			state.acknowledge(ack.AcceptedSequence)
			return nil
		}
		if !transient(err) {
			return err
		}
		if !pause(ctx, w.retryEvery) {
			return state.failure()
		}
	}
}
func (w *Worker) runJob(parent context.Context, j *journal, job cloud.WorkLease) error {
	if err := j.begin(job.ID); err != nil {
		return err
	}
	ctx, stop := context.WithDeadline(parent, time.UnixMilli(job.DeadlineAtMS))
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	state := &leaseState{expires: time.UnixMilli(job.LeaseExpiresAtMS)}
	supervised := make(chan struct{})
	go w.supervise(ctx, cancel, job, state, supervised)
	defer func() { cancel(); <-supervised }()
	sequence := int64(1)
	if err := w.send(ctx, job, state, []cloud.WorkEvent{{Sequence: sequence, Type: "started"}}); err != nil {
		_ = j.record(job.ID, "abandoned")
		return err
	}
	type execution struct {
		result json.RawMessage
		err    error
	}
	chunks := make(chan json.RawMessage, 8)
	result := make(chan execution, 1)
	go func() {
		value, err := w.executor.Execute(ctx, job, func(data json.RawMessage) error {
			if len(data) > 32<<10 || !json.Valid(data) {
				return errors.New("runtime emitted an oversized or invalid event")
			}
			copyData := append(json.RawMessage(nil), data...)
			select {
			case chunks <- copyData:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		close(chunks)
		result <- execution{value, err}
	}()
	ticker := time.NewTicker(w.flushEvery)
	defer ticker.Stop()
	pending := []cloud.WorkEvent{}
	bytes := 0
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		err := w.send(ctx, job, state, pending)
		if err == nil {
			pending = nil
			bytes = 0
		}
		return err
	}
	var outcome execution
	for chunks != nil {
		select {
		case <-ctx.Done():
			// The backend contract requires cancellation to stop the trusted subprocess.
			<-result
			_ = j.record(job.ID, "abandoned")
			return state.failure()
		case data, ok := <-chunks:
			if !ok {
				chunks = nil
				break
			}
			if len(pending) > 0 && (len(pending) >= 32 || bytes+len(data) > 24<<10) {
				if err := flush(); err != nil {
					cancel()
					<-result
					_ = j.record(job.ID, "abandoned")
					return err
				}
			}
			sequence++
			pending = append(pending, cloud.WorkEvent{Sequence: sequence, Type: "chunk", Data: data})
			bytes += len(data)
		case <-ticker.C:
			if err := flush(); err != nil {
				cancel()
				<-result
				_ = j.record(job.ID, "abandoned")
				return err
			}
		}
	}
	outcome = <-result
	if err := flush(); err != nil {
		_ = j.record(job.ID, "abandoned")
		return err
	}
	sequence++
	event := cloud.WorkEvent{Sequence: sequence, Type: "completed", Data: outcome.result}
	if outcome.err != nil {
		event.Type = "failed"
		event.Data = json.RawMessage(`{"code":"runtime_failed"}`)
	}
	if len(event.Data) > 32<<10 || (len(event.Data) > 0 && !json.Valid(event.Data)) {
		event.Type = "failed"
		event.Data = json.RawMessage(`{"code":"invalid_runtime_result"}`)
	}
	state.mu.Lock()
	state.finishing = true
	state.mu.Unlock()
	if err := w.send(ctx, job, state, []cloud.WorkEvent{event}); err != nil {
		_ = j.record(job.ID, "abandoned")
		return err
	}
	if err := j.record(job.ID, event.Type); err != nil {
		return err
	}
	if w.notify != nil {
		w.notify("Hosted work finished: " + event.Type)
	}
	return nil
}
