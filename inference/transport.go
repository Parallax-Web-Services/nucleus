package inference

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
)

type WorkerControl interface {
	Register(context.Context, Advertisement) error
	Acquire(context.Context) (*Lease, error)
	Push(context.Context, string, Event) error
	Job(context.Context, string) (JobView, error)
}
type LocalControl struct {
	Scheduler *Scheduler
	NodeID    string
}

func (c LocalControl) Register(_ context.Context, a Advertisement) error {
	return c.Scheduler.Register(c.NodeID, a)
}
func (c LocalControl) Acquire(_ context.Context) (*Lease, error) {
	return c.Scheduler.Acquire(c.NodeID)
}
func (c LocalControl) Push(_ context.Context, id string, e Event) error {
	return c.Scheduler.Push(c.NodeID, id, e)
}
func (c LocalControl) Job(_ context.Context, id string) (JobView, error) {
	j, ok := c.Scheduler.WorkerJob(c.NodeID, id)
	if !ok {
		return j, errors.New("job no longer assigned")
	}
	return j, nil
}

type RemoteControl struct {
	client   *http.Client
	endpoint string
}

func NewRemoteControl(home string) (*RemoteControl, error) {
	state, err := fabric.Load(home)
	if err != nil {
		return nil, err
	}
	if err = fabric.ValidateEndpoint(state.Endpoint); err != nil {
		return nil, err
	}
	config, err := fabric.ClientTLS(home)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext, TLSClientConfig: config, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 5 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	return &RemoteControl{endpoint: strings.TrimRight(state.Endpoint, "/"), client: &http.Client{Transport: transport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fabric redirects disabled") }}}, nil
}
func (c *RemoteControl) call(ctx context.Context, method, path string, body, result any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	r, err := http.NewRequestWithContext(ctx, method, c.endpoint+workerPrefix+path, reader)
	if err != nil {
		return 0, err
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(r)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return resp.StatusCode, fmt.Errorf("worker control rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if result != nil && resp.StatusCode == 200 {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil {
			return resp.StatusCode, err
		}
		if len(data) > 1<<20 {
			return resp.StatusCode, errors.New("worker control response exceeds limit")
		}
		return resp.StatusCode, decodeStrict(bytes.NewReader(data), result)
	}
	return resp.StatusCode, nil
}
func (c *RemoteControl) Register(ctx context.Context, a Advertisement) error {
	_, err := c.call(ctx, "POST", "register", a, nil)
	return err
}
func (c *RemoteControl) Acquire(ctx context.Context) (*Lease, error) {
	var lease Lease
	code, err := c.call(ctx, "POST", "acquire", nil, &lease)
	if code == 204 || err != nil {
		return nil, err
	}
	return &lease, nil
}
func (c *RemoteControl) Push(ctx context.Context, id string, e Event) error {
	_, err := c.call(ctx, "POST", "jobs/"+id+"/events", e, nil)
	return err
}
func (c *RemoteControl) Job(ctx context.Context, id string) (JobView, error) {
	var j JobView
	_, err := c.call(ctx, "GET", "jobs/"+id, nil, &j)
	return j, err
}
