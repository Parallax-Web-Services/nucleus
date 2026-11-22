package cloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

const Version = "0.5.0-alpha"
const DefaultURL = "https://nucleus.parallax.link/dashboard"

var hex64 = regexp.MustCompile("^[0-9a-f]{64}$")
var enrollmentID = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
var userCode = regexp.MustCompile("^[A-Z0-9]{4}-?[A-Z0-9]{4}$")
var organizationID = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")

type serviceBase struct {
	origin string
	path   string
}

type Client struct {
	home    string
	base    serviceBase
	http    *http.Client
	monitor inventory.Monitor
	now     func() time.Time
}

type EnrollmentNotice struct {
	NodeID          string
	UserCode        string
	VerificationURI string
	ExpiresAt       time.Time
}

// APIError contains a status and a bounded machine-readable code, never a body.
type APIError struct {
	Status int
	Code   string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("hosted service rejected the request (HTTP %d: %s)", e.Status, e.Code)
	}
	return fmt.Sprintf("hosted service rejected the request (HTTP %d)", e.Status)
}

func New(home, rawURL string) (*Client, error) {
	base, err := parseBase(rawURL)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, IdleConnTimeout: 30 * time.Second,
	}
	return &Client{
		home: home, base: base, now: time.Now,
		http: &http.Client{
			Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func FromBinding(home string) (*Client, error) {
	binding, err := LoadBinding(home)
	if err != nil {
		return nil, err
	}
	return New(home, binding.Origin+binding.BasePath)
}

func parseBase(raw string) (serviceBase, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" {
		return serviceBase{}, errors.New("cloud URL must be an HTTPS origin followed by /dashboard")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback()) {
		return serviceBase{}, errors.New("cloud URL requires HTTPS; HTTP is permitted only on a literal loopback test address")
	}
	if strings.TrimRight(u.Path, "/") != "/dashboard" {
		return serviceBase{}, errors.New("cloud URL must end with /dashboard")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, "%\r\n\t ") || strings.HasSuffix(host, ".") {
		return serviceBase{}, errors.New("invalid cloud service hostname")
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return serviceBase{}, errors.New("invalid cloud service port")
		}
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return serviceBase{origin: u.Scheme + "://" + host, path: "/dashboard"}, nil
}

func (c *Client) Connect(ctx context.Context, notify func(EnrollmentNotice)) (*Binding, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, errors.New("cannot determine node hostname")
	}
	return c.ConnectNamed(ctx, hostname, notify)
}

// ConnectNamed enrolls with an operator-visible device label. The signing key remains the identity.
func (c *Client) ConnectNamed(ctx context.Context, name string, notify func(EnrollmentNotice)) (*Binding, error) {
	if strings.TrimSpace(name) == "" || len(name) > 128 || strings.ContainsAny(name, "\r\n\x00") {
		return nil, errors.New("invalid device name")
	}
	if _, err := LoadBinding(c.home); err == nil {
		return nil, errors.New("hosted registration already exists; inspect cloud status or disconnect first")
	} else if !errors.Is(err, ErrNotRegistered) {
		return nil, err
	}
	state, publicKey, err := fabric.CloudIdentity(c.home)
	if err != nil {
		return nil, err
	}
	var fabricID *string
	if state.FabricID != "" {
		fabricID = &state.FabricID
	}
	payload, err := json.Marshal(struct {
		NodeID    string  `json:"node_id"`
		PublicKey string  `json:"public_key"`
		FabricID  *string `json:"fabric_id"`
		Hostname  string  `json:"hostname"`
		Platform  string  `json:"platform"`
		Arch      string  `json:"arch"`
		Version   string  `json:"version"`
	}{state.NodeID, base64.StdEncoding.EncodeToString(publicKey), fabricID, name, runtime.GOOS, runtime.GOARCH, Version})
	if err != nil {
		return nil, err
	}
	response, err := c.request(ctx, http.MethodPost, c.base.path+"/api/enroll", payload, false)
	if err != nil {
		return nil, err
	}
	var enrollment struct {
		ID              string `json:"enrollment_id"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		PollToken       string `json:"poll_token"`
		Challenge       string `json:"challenge"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if json.Unmarshal(response, &enrollment) != nil || !enrollmentID.MatchString(enrollment.ID) ||
		!userCode.MatchString(enrollment.UserCode) || !hex64.MatchString(enrollment.PollToken) ||
		!hex64.MatchString(enrollment.Challenge) || enrollment.ExpiresIn < 1 || enrollment.ExpiresIn > 3600 ||
		enrollment.Interval < 1 || enrollment.Interval > 60 {
		return nil, errors.New("hosted service returned an invalid enrollment response")
	}
	verification, err := c.serviceURL(enrollment.VerificationURI, c.base.path+"/enroll", url.Values{"code": {enrollment.UserCode}})
	if err != nil {
		return nil, errors.New("hosted service returned an invalid verification URL")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(enrollment.ExpiresIn)*time.Second)
	defer cancel()
	message := EnrollmentMessage(c.base.origin, enrollment.ID, state.NodeID, enrollment.Challenge)
	signature, err := fabric.SignCloud(c.home, []byte(message))
	if err != nil {
		return nil, err
	}
	proof, _ := json.Marshal(map[string]string{
		"poll_token": enrollment.PollToken, "signature": base64.StdEncoding.EncodeToString(signature),
	})
	if _, err = c.request(ctx, http.MethodPost, c.base.path+"/api/enroll/"+enrollment.ID+"/prove", proof, false); err != nil {
		return nil, err
	}
	if notify != nil {
		notify(EnrollmentNotice{NodeID: state.NodeID, UserCode: enrollment.UserCode, VerificationURI: verification, ExpiresAt: c.now().Add(time.Duration(enrollment.ExpiresIn) * time.Second)})
	}
	pollBody, _ := json.Marshal(map[string]string{"poll_token": enrollment.PollToken})
	for {
		body, err := c.request(ctx, http.MethodPost, c.base.path+"/api/enroll/"+enrollment.ID+"/poll", pollBody, false)
		if err != nil {
			return nil, err
		}
		var result struct {
			State                    string          `json:"state"`
			NodeID                   string          `json:"node_id"`
			OrganizationID           json.RawMessage `json:"organization_id"`
			HeartbeatURL             string          `json:"heartbeat_url"`
			HeartbeatIntervalSeconds int             `json:"heartbeat_interval_seconds"`
		}
		if json.Unmarshal(body, &result) != nil {
			return nil, errors.New("hosted service returned an invalid enrollment state")
		}
		switch result.State {
		case "approved":
			org, err := decodeOrganizationID(result.OrganizationID)
			if err != nil || result.NodeID != state.NodeID ||
				result.HeartbeatIntervalSeconds < 5 || result.HeartbeatIntervalSeconds > 3600 {
				return nil, errors.New("hosted approval does not match this node")
			}
			if _, err = c.serviceURL(result.HeartbeatURL, c.nodePath(state.NodeID)+"/heartbeat", nil); err != nil {
				return nil, errors.New("hosted service returned an invalid heartbeat URL")
			}
			binding := &Binding{
				SchemaVersion: 1, Origin: c.base.origin, BasePath: c.base.path, NodeID: state.NodeID,
				OrganizationID: org, HeartbeatIntervalSeconds: result.HeartbeatIntervalSeconds, RegisteredAt: c.now().UTC(),
			}
			if err = saveBinding(c.home, binding, true); err != nil {
				return nil, err
			}
			return binding, nil
		case "denied":
			return nil, errors.New("hosted enrollment was denied; no registration was saved")
		case "expired":
			return nil, errors.New("hosted enrollment expired; no registration was saved")
		case "pending":
			timer := time.NewTimer(time.Duration(enrollment.Interval) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, errors.New("hosted enrollment stopped or expired; no registration was saved")
			case <-timer.C:
			}
		default:
			return nil, errors.New("hosted service returned an unsupported enrollment state")
		}
	}
}

func EnrollmentMessage(origin, id, nodeID, challenge string) string {
	return strings.Join([]string{"nucleus-enroll-v1", origin, id, nodeID, challenge}, "\n")
}

func RequestMessage(method, origin, path, timestamp, nonce string, body []byte) string {
	hash := sha256.Sum256(body)
	return strings.Join([]string{"nucleus-cloud-v1", method, origin, path, timestamp, nonce, hex.EncodeToString(hash[:])}, "\n")
}

func (c *Client) nodePath(nodeID string) string {
	return c.base.path + "/api/nodes/" + nodeID
}

// Heartbeat sends real local measurements. Only an acknowledged response updates
// the local last-heartbeat timestamp; an enrollment alone is never called online.
func (c *Client) Heartbeat(ctx context.Context) error {
	binding, err := LoadBinding(c.home)
	if err != nil {
		return err
	}
	if binding.Origin != c.base.origin || binding.BasePath != c.base.path {
		return errors.New("cloud client origin does not match the saved registration")
	}
	if binding.Revoked {
		return &APIError{Status: http.StatusForbidden, Code: "node_revoked"}
	}
	snapshot, err := c.monitor.Snapshot()
	if err != nil {
		return errors.New("cannot collect local resource telemetry")
	}
	body, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	_, err = c.request(ctx, http.MethodPost, c.nodePath(binding.NodeID)+"/heartbeat", body, true)
	if err != nil {
		var apiError *APIError
		if errors.As(err, &apiError) && apiError.Status == http.StatusForbidden && apiError.Code == "node_revoked" {
			binding.Revoked = true
			_ = saveBinding(c.home, binding, false)
		}
		return err
	}
	now := c.now().UTC()
	binding.LastHeartbeatAt = &now
	return saveBinding(c.home, binding, false)
}

func (c *Client) Run(ctx context.Context, once bool, notify func(string)) error {
	for {
		err := c.Heartbeat(ctx)
		if err == nil {
			if notify != nil {
				notify("Telemetry acknowledged by " + c.base.origin)
			}
		} else {
			if ctx.Err() != nil {
				return nil
			}
			var apiError *APIError
			if once || (errors.As(err, &apiError) && apiError.Status >= 400 && apiError.Status < 500 && apiError.Status != 429) {
				return err
			}
			if notify != nil {
				notify("Cloud telemetry unavailable; retrying. No successful contact was recorded.")
			}
		}
		if once {
			return nil
		}
		binding, loadErr := LoadBinding(c.home)
		if loadErr != nil {
			return loadErr
		}
		timer := time.NewTimer(time.Duration(binding.HeartbeatIntervalSeconds) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func (c *Client) Disconnect(ctx context.Context, localOnly bool) error {
	binding, err := LoadBinding(c.home)
	if err != nil {
		return err
	}
	if !localOnly && !binding.Revoked {
		if binding.Origin != c.base.origin {
			return errors.New("cloud client origin does not match the saved registration")
		}
		_, err = c.request(ctx, http.MethodDelete, c.nodePath(binding.NodeID), nil, true)
		if err != nil {
			var apiError *APIError
			if !errors.As(err, &apiError) || apiError.Status != http.StatusForbidden || apiError.Code != "node_revoked" {
				return err
			}
		}
	}
	return forgetBinding(c.home, binding)
}

func (c *Client) serviceURL(raw, expectedPath string, expectedQuery url.Values) (string, error) {
	ref, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	base, _ := url.Parse(c.base.origin)
	resolved := base.ResolveReference(ref)
	if resolved.Scheme+"://"+resolved.Host != c.base.origin || resolved.Path != expectedPath ||
		resolved.RawPath != "" || resolved.User != nil || resolved.Fragment != "" {
		return "", errors.New("unexpected service URL")
	}
	if resolved.Query().Encode() != expectedQuery.Encode() || resolved.ForceQuery {
		return "", errors.New("unexpected service URL query")
	}
	return resolved.String(), nil
}

func decodeOrganizationID(raw json.RawMessage) (string, error) {
	var value string
	if json.Unmarshal(raw, &value) != nil {
		var number json.Number
		if json.Unmarshal(raw, &number) != nil {
			return "", errors.New("invalid organization ID")
		}
		value = number.String()
	}
	if !organizationID.MatchString(value) {
		return "", errors.New("invalid organization ID")
	}
	return value, nil
}

func (c *Client) request(ctx context.Context, method, path string, body []byte, signed bool) ([]byte, error) {
	return c.requestBounded(ctx, method, path, body, signed, 16384)
}

func (c *Client) requestBounded(ctx context.Context, method, path string, body []byte, signed bool, responseLimit int64) ([]byte, error) {
	if len(body) > 65536 || !strings.HasPrefix(path, c.base.path+"/api/") || strings.ContainsAny(path, "?#\r\n") {
		return nil, errors.New("invalid hosted request")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base.origin+path, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("cannot create hosted request")
	}
	request.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if signed {
		state, _, err := fabric.CloudIdentity(c.home)
		if err != nil {
			return nil, err
		}
		if !c.validSignedPath(state.NodeID, path) {
			return nil, errors.New("hosted request does not match this node")
		}
		var nonceBytes [16]byte
		if _, err = rand.Read(nonceBytes[:]); err != nil {
			return nil, errors.New("cannot generate request nonce")
		}
		timestamp := strconv.FormatInt(c.now().Unix(), 10)
		nonce := hex.EncodeToString(nonceBytes[:])
		signature, err := fabric.SignCloud(c.home, []byte(RequestMessage(method, c.base.origin, path, timestamp, nonce, body)))
		if err != nil {
			return nil, err
		}
		request.Header.Set("X-Nucleus-Timestamp", timestamp)
		request.Header.Set("X-Nucleus-Nonce", nonce)
		request.Header.Set("X-Nucleus-Signature", base64.StdEncoding.EncodeToString(signature))
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("cannot reach hosted service over its authenticated connection")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, responseLimit+1))
	if err != nil || int64(len(data)) > responseLimit {
		return nil, errors.New("hosted response exceeds its size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &payload)
		allowed := map[string]bool{
			"subscription_required": true, "node_revoked": true, "node_already_enrolled": true,
			"lease_lost": true, "job_cancelled": true, "work_disabled": true, "job_not_found": true, "event_conflict": true, "worker_busy": true,
			"invalid_signature": true, "replayed_request": true, "enrollment_expired": true,
			"enrollment_denied": true, "invalid_poll_token": true, "rate_limited": true,
			"request_replayed": true, "invalid_timestamp": true, "invalid_nonce": true,
			"enrollment_not_found": true, "node_not_found": true, "node_identity_mismatch": true, "payload_too_large": true,
		}
		code := ""
		if allowed[payload.Error] {
			code = payload.Error
		}
		return nil, &APIError{Status: response.StatusCode, Code: code}
	}
	return data, nil
}
