package nucleusapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const deviceTestCode = "SYNTHETIC-PRIVATE-DEVICE-CODE-0123456789abcdef"
const deviceTestUserCode = "ABCD-EFGH"
const deviceTestAccess = "SYNTHETIC-PRIVATE-DEVICE-ACCESS"
const deviceTestRefresh = "SYNTHETIC-PRIVATE-DEVICE-REFRESH"

type deviceTestClock struct {
	mu    sync.Mutex
	now   time.Time
	waits []time.Duration
}

func (c *deviceTestClock) current() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *deviceTestClock) sleep(ctx context.Context, duration time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.waits = append(c.waits, duration)
	c.now = c.now.Add(duration)
	c.mu.Unlock()
	return nil
}
func (c *deviceTestClock) durations() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

type deviceTestReply struct {
	status int
	body   string
}
type deviceTestRequest struct {
	path          string
	at            time.Time
	form          url.Values
	authorization string
}
type deviceTestFixture struct {
	t          *testing.T
	server     *httptest.Server
	cli        *hostedCLI
	clock      *deviceTestClock
	mu         sync.Mutex
	requests   []deviceTestRequest
	opened     []string
	unexpected []string
	discovery  func(string) deviceTestReply
	authorize  func(string) deviceTestReply
	poll       func(int, url.Values) deviceTestReply
	beforePoll func(int)
}

func deviceTestJSON(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return string(raw)
}
func deviceTestAuthorization(origin string) map[string]any {
	return map[string]any{"device_code": deviceTestCode, "user_code": deviceTestUserCode, "verification_uri": origin + "/dashboard/cli/device", "verification_uri_complete": origin + "/dashboard/cli/device?user_code=" + deviceTestUserCode, "expires_in": 120, "interval": 5}
}
func deviceTestToken() map[string]any {
	return map[string]any{"access_token": deviceTestAccess, "refresh_token": deviceTestRefresh, "token_type": "Bearer", "expires_in": 900, "scope": "nebula:read"}
}
func deviceTestDiscovery(origin string) map[string]any {
	return map[string]any{"schema_version": 1, "issuer": origin, "client_id": "cli-fixture-id", "authorization_endpoint": origin + "/oauth/authorize", "device_authorization_endpoint": origin + "/oauth/device/code", "verification_endpoint": origin + "/dashboard/cli/device", "token_endpoint": origin + "/oauth/token", "revocation_endpoint": origin + "/api/v1/session/revoke", "api_endpoint": origin + "/api/v1", "callback_path": "/oauth/callback", "scopes_supported": []string{"nebula:read", "nebula:manage"}}
}
func newHostedDeviceFixture(t *testing.T) *deviceTestFixture {
	t.Helper()
	f := &deviceTestFixture{t: t, clock: &deviceTestClock{now: time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC)}}
	f.discovery = func(origin string) deviceTestReply {
		return deviceTestReply{200, deviceTestJSON(deviceTestDiscovery(origin))}
	}
	f.authorize = func(origin string) deviceTestReply {
		return deviceTestReply{200, deviceTestJSON(deviceTestAuthorization(origin))}
	}
	f.poll = func(int, url.Values) deviceTestReply { return deviceTestReply{200, deviceTestJSON(deviceTestToken())} }
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	f.cli = hostedFixture(t, f.server)
	f.cli.now = f.clock.current
	f.cli.sleep = f.clock.sleep
	f.cli.open = func(address string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.opened = append(f.opened, address)
		return nil
	}
	return f
}
func (f *deviceTestFixture) configure(change func(*deviceTestFixture)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f)
}
func (f *deviceTestFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.t.Helper()
	form := url.Values{}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			f.t.Error("invalid local fixture request", err)
		}
		for k, v := range r.PostForm {
			form[k] = append([]string(nil), v...)
		}
	}
	f.mu.Lock()
	index := 0
	for _, request := range f.requests {
		if request.path == "/oauth/token" {
			index++
		}
	}
	f.requests = append(f.requests, deviceTestRequest{r.URL.Path, f.clock.current(), form, r.Header.Get("Authorization")})
	discovery, authorize, poll, before := f.discovery, f.authorize, f.poll, f.beforePoll
	f.mu.Unlock()
	var reply deviceTestReply
	switch r.URL.Path {
	case "/.well-known/nebula-cli":
		if r.Method != http.MethodGet {
			f.t.Error("discovery was not GET")
		}
		reply = discovery(f.server.URL)
	case "/oauth/device/code", "/oauth/token":
		if r.Method != http.MethodPost || r.Header.Get("Accept") != "application/json" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			f.t.Error("unsafe device POST headers or method")
		}
		if r.URL.Path == "/oauth/device/code" {
			reply = authorize(f.server.URL)
		} else {
			if before != nil {
				before(index)
			}
			reply = poll(index, form)
		}
	default:
		f.mu.Lock()
		f.unexpected = append(f.unexpected, r.URL.Path)
		f.mu.Unlock()
		reply = deviceTestReply{404, `{"error":"unexpected_fixture_endpoint"}`}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(reply.status)
	fmt.Fprint(w, reply.body)
}
func (f *deviceTestFixture) records(path string) []deviceTestRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	var result []deviceTestRequest
	for _, record := range f.requests {
		if record.path == path {
			result = append(result, record)
		}
	}
	return result
}
func (f *deviceTestFixture) noSecrets(err error) {
	f.t.Helper()
	text := f.cli.output.(*bytes.Buffer).String()
	if err != nil {
		text += "\n" + err.Error()
	}
	secrets := []string{deviceTestCode, deviceTestAccess, deviceTestRefresh, "private-access-fixture", "private-refresh-fixture"}
	for _, record := range f.records("/oauth/token") {
		secrets = append(secrets, record.form.Get("code_verifier"))
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(text, secret) {
			f.t.Fatal("device sign-in printed a private value")
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.unexpected) != 0 {
		f.t.Fatal("device sign-in used an unexpected or legacy endpoint", f.unexpected)
	}
}
func (f *deviceTestFixture) seed() (*hostedFile, []byte) {
	f.t.Helper()
	previous, err := f.cli.save(nil, hostedState(f.cli, f.server.URL))
	if err != nil {
		f.t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(f.cli.home, "hosted-auth.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	return previous, raw
}
func (f *deviceTestFixture) unchanged(previous *hostedFile, raw []byte) {
	f.t.Helper()
	current, err := f.cli.load()
	if err != nil || current == nil {
		f.t.Fatal("failed sign-in lost old credentials", err)
	}
	if !bytes.Equal(raw, current.data) || !os.SameFile(previous.info, current.info) || current.info.Mode().Perm() != 0600 {
		f.t.Fatal("failed sign-in changed existing credentials")
	}
}

func TestHostedDeviceS256PrivatePersistenceAndDefaultDispatch(t *testing.T) {
	f := newHostedDeviceFixture(t)
	start := f.clock.current()
	if err := f.cli.run(context.Background(), []string{"login", "--url", f.server.URL}); err != nil {
		t.Fatal(err)
	}
	initial, polls := f.records("/oauth/device/code"), f.records("/oauth/token")
	if len(initial) != 1 || len(polls) != 1 {
		t.Fatal("device authorization or exchange repeated")
	}
	a, p := initial[0].form, polls[0].form
	sum := sha256.Sum256([]byte(p.Get("code_verifier")))
	if len(a) != 4 || a.Get("client_id") != "cli-fixture-id" || a.Get("scope") != "nebula:read" || a.Get("code_challenge_method") != "S256" || a.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("device request did not bind S256 and read-only scope")
	}
	if len(p) != 4 || p.Get("grant_type") != hostedDeviceGrant || p.Get("device_code") != deviceTestCode || p.Get("client_id") != "cli-fixture-id" || len(p.Get("code_verifier")) != 43 {
		t.Fatal("exchange lost the private original proof")
	}
	if initial[0].authorization != "" || polls[0].authorization != "" {
		t.Fatal("existing bearer token sent to device endpoint")
	}
	if polls[0].at.Sub(start) != 5*time.Second {
		t.Fatal("first poll did not wait for the full interval")
	}
	f.mu.Lock()
	opened := append([]string(nil), f.opened...)
	f.mu.Unlock()
	if !reflect.DeepEqual(opened, []string{f.server.URL + "/dashboard/cli/device?user_code=" + deviceTestUserCode}) {
		t.Fatal("browser did not open the exact verification URL")
	}
	file, err := f.cli.load()
	if err != nil || file == nil || file.state.AccessToken != deviceTestAccess || file.state.RefreshToken != deviceTestRefresh || file.state.Origin != f.server.URL || file.state.ClientID != "cli-fixture-id" || file.info.Mode().Perm() != 0600 {
		t.Fatal("private device credentials were not persisted", err)
	}
	f.noSecrets(nil)
}
func TestHostedDevicePendingSlowDownAndSubsequentIntervals(t *testing.T) {
	f := newHostedDeviceFixture(t)
	start := f.clock.current()
	f.configure(func(f *deviceTestFixture) {
		f.poll = func(index int, _ url.Values) deviceTestReply {
			switch index {
			case 0:
				return deviceTestReply{400, `{"error":"authorization_pending"}`}
			case 1:
				return deviceTestReply{429, `{"error":"slow_down"}`}
			case 2:
				return deviceTestReply{400, `{"error":"authorization_pending"}`}
			default:
				return deviceTestReply{200, deviceTestJSON(deviceTestToken())}
			}
		}
	})
	if err := f.cli.deviceLogin(context.Background(), f.server.URL, true); err != nil {
		t.Fatal(err)
	}
	expected := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if !reflect.DeepEqual(f.clock.durations(), expected) {
		t.Fatal("slow_down did not permanently increase each later wait", f.clock.durations())
	}
	var at []time.Duration
	for _, p := range f.records("/oauth/token") {
		at = append(at, p.at.Sub(start))
	}
	if !reflect.DeepEqual(at, []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second}) {
		t.Fatal("polling did not enforce first and subsequent intervals", at)
	}
	f.mu.Lock()
	opened := len(f.opened)
	f.mu.Unlock()
	if opened != 0 {
		t.Fatal("--no-open opened a browser")
	}
	f.noSecrets(nil)
}
func TestHostedDeviceOmittedIntervalDefaultsToFiveAndExplicitIntervalIsHonored(t *testing.T) {
	for _, interval := range []int{0, 7, 30} {
		t.Run(fmt.Sprint(interval), func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			f.configure(func(f *deviceTestFixture) {
				f.authorize = func(origin string) deviceTestReply {
					v := deviceTestAuthorization(origin)
					if interval == 0 {
						delete(v, "interval")
					} else {
						v["interval"] = interval
					}
					return deviceTestReply{200, deviceTestJSON(v)}
				}
			})
			if err := f.cli.deviceLogin(context.Background(), f.server.URL, true); err != nil {
				t.Fatal(err)
			}
			want := time.Duration(interval) * time.Second
			if interval == 0 {
				want = 5 * time.Second
			}
			if !reflect.DeepEqual(f.clock.durations(), []time.Duration{want}) {
				t.Fatal("wrong initial polling interval")
			}
		})
	}
}
func TestHostedDeviceTerminalErrorsPreserveExistingCredentials(t *testing.T) {
	for _, failure := range []string{"access_denied", "expired_token", "invalid_grant", "unsupported_error"} {
		t.Run(failure, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.poll = func(int, url.Values) deviceTestReply {
					return deviceTestReply{400, deviceTestJSON(map[string]string{"error": failure, "error_description": deviceTestCode + deviceTestAccess})}
				}
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil || len(f.records("/oauth/token")) != 1 || len(f.records("/oauth/device/code")) != 1 {
				t.Fatal("terminal exchange was retried or accepted")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceExpiryStopsPendingWithoutPollAtDeadline(t *testing.T) {
	f := newHostedDeviceFixture(t)
	previous, raw := f.seed()
	f.configure(func(f *deviceTestFixture) {
		f.authorize = func(origin string) deviceTestReply {
			v := deviceTestAuthorization(origin)
			v["expires_in"] = 10
			return deviceTestReply{200, deviceTestJSON(v)}
		}
		f.poll = func(int, url.Values) deviceTestReply {
			return deviceTestReply{400, `{"error":"authorization_pending"}`}
		}
	})
	err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
	if err == nil || !strings.Contains(err.Error(), "expired") || len(f.records("/oauth/token")) != 1 {
		t.Fatal("expired device sign-in polled again or succeeded", err)
	}
	f.unchanged(previous, raw)
	f.noSecrets(err)
}
func TestHostedDeviceCancellationStopsBeforeNextPoll(t *testing.T) {
	f := newHostedDeviceFixture(t)
	previous, raw := f.seed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waits := 0
	f.configure(func(f *deviceTestFixture) {
		f.poll = func(int, url.Values) deviceTestReply {
			return deviceTestReply{400, `{"error":"authorization_pending"}`}
		}
	})
	f.cli.sleep = func(ctx context.Context, d time.Duration) error {
		waits++
		if waits == 2 {
			cancel()
			return ctx.Err()
		}
		return f.clock.sleep(ctx, d)
	}
	err := f.cli.deviceLogin(ctx, f.server.URL, true)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || len(f.records("/oauth/token")) != 1 {
		t.Fatal("cancelled device sign-in polled or saved again", err)
	}
	f.unchanged(previous, raw)
	f.noSecrets(err)
}
func TestHostedDeviceVerificationURLsAreStrictAndSameOrigin(t *testing.T) {
	mutations := map[string]func(map[string]any, string){
		"verification-origin": func(v map[string]any, _ string) { v["verification_uri"] = "https://other.invalid/dashboard/cli/device" },
		"complete-origin": func(v map[string]any, _ string) {
			v["verification_uri_complete"] = "https://other.invalid/dashboard/cli/device?user_code=" + deviceTestUserCode
		},
		"complete-http": func(v map[string]any, o string) {
			v["verification_uri_complete"] = strings.Replace(o, "https://", "http://", 1) + "/dashboard/cli/device?user_code=" + deviceTestUserCode
		},
		"complete-path": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device/other?user_code=" + deviceTestUserCode
		},
		"complete-fragment": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=" + deviceTestUserCode + "#fragment"
		},
		"complete-empty-fragment": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=" + deviceTestUserCode + "#"
		},
		"duplicate-code": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=" + deviceTestUserCode + "&user_code=" + deviceTestUserCode
		},
		"extra-query": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=" + deviceTestUserCode + "&token=private"
		},
		"wrong-code": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=ZZZZ-ZZZZ"
		},
		"encoded-code": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/device?user_code=%41BCD-EFGH"
		},
		"encoded-path": func(v map[string]any, o string) {
			v["verification_uri_complete"] = o + "/dashboard/cli/%64evice?user_code=" + deviceTestUserCode
		},
		"userinfo": func(v map[string]any, o string) {
			v["verification_uri_complete"] = strings.Replace(o, "https://", "https://user:secret@", 1) + "/dashboard/cli/device?user_code=" + deviceTestUserCode
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.authorize = func(origin string) deviceTestReply {
					v := deviceTestAuthorization(origin)
					mutate(v, origin)
					return deviceTestReply{200, deviceTestJSON(v)}
				}
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, false)
			if err == nil || len(f.records("/oauth/token")) != 0 {
				t.Fatal("unsafe verification URL accepted")
			}
			f.mu.Lock()
			opened := len(f.opened)
			f.mu.Unlock()
			if opened != 0 {
				t.Fatal("unsafe URL opened before validation")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceVerificationCompleteMayBeOmitted(t *testing.T) {
	f := newHostedDeviceFixture(t)
	f.configure(func(f *deviceTestFixture) {
		f.authorize = func(origin string) deviceTestReply {
			v := deviceTestAuthorization(origin)
			delete(v, "verification_uri_complete")
			return deviceTestReply{200, deviceTestJSON(v)}
		}
	})
	if err := f.cli.deviceLogin(context.Background(), f.server.URL, false); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !reflect.DeepEqual(f.opened, []string{f.server.URL + "/dashboard/cli/device"}) {
		t.Fatal("missing complete URL did not use the safe verification page")
	}
}
func TestHostedDeviceUnsafeAuthorizationFieldsNeverPoll(t *testing.T) {
	cases := map[string]func(map[string]any){"short-code": func(v map[string]any) { v["device_code"] = "short" }, "device-code-control": func(v map[string]any) { v["device_code"] = strings.Repeat("x", 32) + "\n" }, "user-code": func(v map[string]any) { v["user_code"] = "user@example.invalid" }, "expires-zero": func(v map[string]any) { v["expires_in"] = 0 }, "expires-over": func(v map[string]any) { v["expires_in"] = 601 }, "expires-bool": func(v map[string]any) { v["expires_in"] = true }, "interval-low": func(v map[string]any) { v["interval"] = 4 }, "interval-high": func(v map[string]any) { v["interval"] = 31 }, "interval-string": func(v map[string]any) { v["interval"] = "5" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.authorize = func(origin string) deviceTestReply {
					v := deviceTestAuthorization(origin)
					mutate(v)
					return deviceTestReply{200, deviceTestJSON(v)}
				}
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil || len(f.records("/oauth/token")) != 0 {
				t.Fatal("unsafe device fields accepted")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceMalformedDuplicateAndOversizedAuthorizationResponses(t *testing.T) {
	bad := map[string]func(string) string{
		"duplicate": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"device_code":"` + deviceTestCode + `"}`
		},
		"case-alias": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"INTERVAL":7}`
		},
		"unicode-alias": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"expire\u017f_in":120}`
		},
		"nested-duplicate": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"extension":{"x":1,"x":2}}`
		},
		"null": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"extension":null}`
		},
		"trailing-json": func(o string) string { return deviceTestJSON(deviceTestAuthorization(o)) + `{}` },
		"oversize": func(o string) string {
			v := deviceTestAuthorization(o)
			v["extension"] = strings.Repeat("x", 131073)
			return deviceTestJSON(v)
		},
		"too-deep": func(o string) string {
			return strings.TrimSuffix(deviceTestJSON(deviceTestAuthorization(o)), "}") + `,"extension":[[[[[[[[[1]]]]]]]]]}`
		},
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.authorize = func(origin string) deviceTestReply { return deviceTestReply{200, body(origin)} }
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil || len(f.records("/oauth/token")) != 0 {
				t.Fatal("ambiguous authorization response accepted")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceTokenScopeAndFieldsCannotEscalate(t *testing.T) {
	cases := map[string]func(map[string]any){"manage": func(v map[string]any) { v["scope"] = "nebula:manage" }, "extra-scope": func(v map[string]any) { v["scope"] = "nebula:read nebula:manage" }, "missing-scope": func(v map[string]any) { delete(v, "scope") }, "case-scope": func(v map[string]any) { v["scope"] = "NEBULA:READ" }, "wrong-type": func(v map[string]any) { v["token_type"] = "Basic" }, "access-empty": func(v map[string]any) { v["access_token"] = "" }, "refresh-empty": func(v map[string]any) { v["refresh_token"] = "" }, "expires-long": func(v map[string]any) { v["expires_in"] = 3601 }, "expires-zero": func(v map[string]any) { v["expires_in"] = 0 }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.poll = func(int, url.Values) deviceTestReply {
					v := deviceTestToken()
					mutate(v)
					return deviceTestReply{200, deviceTestJSON(v)}
				}
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil || len(f.records("/oauth/token")) != 1 {
				t.Fatal("invalid read-only token accepted or retried")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceMalformedTokenResponsesDoNotPersistOrReplay(t *testing.T) {
	bad := map[string]string{
		"duplicate":     `{"access_token":"a","access_token":"b"}`,
		"case-alias":    strings.TrimSuffix(deviceTestJSON(deviceTestToken()), "}") + `,"ACCESS_TOKEN":"other"}`,
		"unicode-alias": strings.TrimSuffix(deviceTestJSON(deviceTestToken()), "}") + `,"access_to\u212aen":"other"}`,
		"null":          `null`, "array": `[]`, "trailing": deviceTestJSON(deviceTestToken()) + `{}`,
		"oversize": `{"extra":"` + strings.Repeat("x", 131073) + `"}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.poll = func(int, url.Values) deviceTestReply { return deviceTestReply{200, body} }
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil || len(f.records("/oauth/token")) != 1 {
				t.Fatal("malformed token response accepted or retried")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
func TestHostedDeviceMissingOrCrossOriginDiscoveryHasNoFallback(t *testing.T) {
	cases := map[string]func(map[string]any){"missing-both": func(v map[string]any) { delete(v, "device_authorization_endpoint"); delete(v, "verification_endpoint") }, "missing-one": func(v map[string]any) { delete(v, "verification_endpoint") }, "foreign-code": func(v map[string]any) { v["device_authorization_endpoint"] = "https://other.invalid/oauth/device/code" }, "foreign-verification": func(v map[string]any) { v["verification_endpoint"] = "https://other.invalid/dashboard/cli/device" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			f.configure(func(f *deviceTestFixture) {
				f.discovery = func(origin string) deviceTestReply {
					v := deviceTestDiscovery(origin)
					mutate(v)
					return deviceTestReply{200, deviceTestJSON(v)}
				}
			})
			err := f.cli.run(context.Background(), []string{"login", "--url", f.server.URL, "--no-open"})
			if err == nil || len(f.records("/oauth/device/code")) != 0 || len(f.records("/oauth/token")) != 0 {
				t.Fatal("unsupported discovery started device or legacy authorization")
			}
			f.noSecrets(err)
		})
	}
}

type deviceTestRoundTrip func(*http.Request) (*http.Response, error)

func (f deviceTestRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHostedDeviceUncertainTransportFailureNeverRetriesExchange(t *testing.T) {
	f := newHostedDeviceFixture(t)
	previous, raw := f.seed()
	base := f.cli.client.Transport
	attempts := 0
	f.cli.client.Transport = deviceTestRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/oauth/token" {
			attempts++
			return nil, errors.New("synthetic unconfirmed issuance " + deviceTestCode + deviceTestAccess)
		}
		return base.RoundTrip(r)
	})
	err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
	if err == nil || attempts != 1 || len(f.records("/oauth/device/code")) != 1 || !strings.Contains(err.Error(), "could not be confirmed") {
		t.Fatal("uncertain exchange replayed or unsafe error returned", err)
	}
	f.unchanged(previous, raw)
	f.noSecrets(err)
}
func TestHostedDeviceRedirectNeverForwardsPrivateExchange(t *testing.T) {
	received := 0
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received++; fmt.Fprint(w, `{}`) }))
	defer destination.Close()
	f := newHostedDeviceFixture(t)
	previous, raw := f.seed()
	f.configure(func(f *deviceTestFixture) {
		f.poll = func(int, url.Values) deviceTestReply { return deviceTestReply{302, `{"error":"do-not-follow"}`} }
	})
	// A second synthetic TLS listener is deliberately unreachable through this client;
	// its counter must remain zero even when redirect checking is otherwise permissive.
	base := f.cli.client.Transport
	f.cli.client.CheckRedirect = func(*http.Request, []*http.Request) error { return nil }
	f.cli.client.Transport = deviceTestRoundTrip(func(r *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(r)
		if err == nil && r.URL.Path == "/oauth/token" {
			response.Header.Set("Location", destination.URL+"/leak")
		}
		return response, err
	})
	err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
	if err == nil || !strings.Contains(err.Error(), "redirect") || received != 0 || len(f.records("/oauth/token")) != 1 {
		t.Fatal("device redirect followed or exchange repeated", err)
	}
	f.unchanged(previous, raw)
	f.noSecrets(err)
}
func TestHostedDeviceConcurrentCredentialsAreNeverOverwritten(t *testing.T) {
	f := newHostedDeviceFixture(t)
	previous, _ := f.seed()
	changed := make(chan error, 1)
	f.configure(func(f *deviceTestFixture) {
		f.beforePoll = func(int) {
			replacement := previous.state
			replacement.AccessToken = "foreign-new-access"
			replacement.RefreshToken = "foreign-new-refresh"
			replacement.OrganizationID = "202"
			_, err := f.cli.save(previous, replacement)
			changed <- err
		}
	})
	err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
	if mutation := <-changed; mutation != nil {
		t.Fatal(mutation)
	}
	if err == nil || !strings.Contains(err.Error(), "changed concurrently") {
		t.Fatal("concurrent credential replacement was overwritten", err)
	}
	current, loadErr := f.cli.load()
	if loadErr != nil || current.state.AccessToken != "foreign-new-access" || current.state.OrganizationID != "202" {
		t.Fatal("foreign credential state was not preserved", loadErr)
	}
	f.noSecrets(err)
}

func TestHostedDeviceRequestTimeoutClampsToCallerDeadline(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "device-30s-exceeds-base-15s"
		if short {
			name = "shorter-caller-context-wins"
		}
		t.Run(name, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			f.cli.client.Timeout = 15 * time.Second
			base := f.cli.client.Transport
			var deadlines []time.Duration
			f.cli.client.Transport = deviceTestRoundTrip(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/oauth/device/code" || r.URL.Path == "/oauth/token" {
					deadline, ok := r.Context().Deadline()
					if !ok {
						t.Error("device request has no finite deadline")
					} else {
						deadlines = append(deadlines, time.Until(deadline))
					}
				}
				return base.RoundTrip(r)
			})
			ctx := context.Background()
			if short {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 4*time.Second)
				defer cancel()
			}
			if err := f.cli.deviceLogin(ctx, f.server.URL, true); err != nil {
				t.Fatal(err)
			}
			if len(deadlines) != 2 {
				t.Fatal("did not inspect both device request deadlines", len(deadlines))
			}
			for _, remaining := range deadlines {
				if short {
					if remaining < 3*time.Second || remaining > 4100*time.Millisecond {
						t.Fatal("device timeout overrode the shorter caller deadline", remaining)
					}
				} else if remaining < 25*time.Second || remaining > 31*time.Second {
					t.Fatal("device request retained the insufficient base timeout", remaining)
				}
			}
			if f.cli.client.Timeout != 15*time.Second {
				t.Fatal("device timeout mutated the shared HTTP client")
			}
			f.noSecrets(nil)
		})
	}
}

func TestHostedDeviceUnauthorizedRepliesAreTerminal(t *testing.T) {
	for _, failure := range []string{"access_denied", "authorization_pending", "slow_down"} {
		t.Run(failure, func(t *testing.T) {
			f := newHostedDeviceFixture(t)
			previous, raw := f.seed()
			f.configure(func(f *deviceTestFixture) {
				f.poll = func(int, url.Values) deviceTestReply {
					return deviceTestReply{http.StatusUnauthorized, deviceTestJSON(map[string]string{"error": failure, "error_description": deviceTestCode + deviceTestAccess})}
				}
			})
			err := f.cli.deviceLogin(context.Background(), f.server.URL, true)
			if err == nil {
				t.Fatal("HTTP 401 device reply was accepted")
			}
			if failure == "access_denied" && !strings.Contains(err.Error(), "not approved") {
				t.Fatal("League HTTP 401 denial did not report not-approved", err)
			}
			if len(f.records("/oauth/token")) != 1 || len(f.records("/oauth/device/code")) != 1 || len(f.clock.durations()) != 1 {
				t.Fatal("HTTP 401 device reply was polled or authorized again")
			}
			f.unchanged(previous, raw)
			f.noSecrets(err)
		})
	}
}
