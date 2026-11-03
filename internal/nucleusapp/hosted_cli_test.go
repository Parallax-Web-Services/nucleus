package nucleusapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hostedFixture(t *testing.T, server *httptest.Server) *hostedCLI {
	t.Helper()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &hostedCLI{home: t.TempDir(), client: client, output: new(bytes.Buffer), open: func(string) error { return nil }, now: func() time.Time { return time.Date(2026, 11, 2, 20, 0, 0, 0, time.UTC) }}
}
func hostedState(c *hostedCLI, origin string) hostedCredentials {
	return hostedCredentials{SchemaVersion: 1, Origin: origin, ClientID: "cli-fixture-id", AccessToken: "private-access-fixture", RefreshToken: "private-refresh-fixture", ExpiresAt: c.now().Add(15 * time.Minute).Unix(), OrganizationID: "201"}
}
func discoveryFixture(origin string) hostedDiscovery {
	return hostedDiscovery{SchemaVersion: 1, Issuer: origin, ClientID: "cli-fixture-id", Authorization: origin + "/oauth/authorize", Token: origin + "/oauth/token", Revocation: origin + "/api/v1/session/revoke", API: origin + "/api/v1", CallbackPath: "/oauth/callback", Scopes: []string{"nebula:read", "nebula:manage"}}
}
func TestHostedLoginExplicitLoopbackPKCEAndPrivatePersistence(t *testing.T) {
	var origin, challenge, redirect string
	exchanges := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/nebula-cli":
			json.NewEncoder(w).Encode(discoveryFixture(origin))
		case "/oauth/token":
			exchanges++
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Method != "POST" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "single-code-fixture" || r.Form.Get("redirect_uri") != redirect || r.Form.Get("client_id") != "cli-fixture-id" || r.Form.Get("client_secret") != "" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
				t.Error("PKCE exchange did not prove the original verifier and callback")
			}
			fmt.Fprint(w, `{"access_token":"private-access-fixture","refresh_token":"private-refresh-fixture","expires_in":900,"token_type":"Bearer"}`)
		default:
			t.Error("unexpected hosted endpoint")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	c := hostedFixture(t, server)
	c.open = func(address string) error {
		parsed, err := url.Parse(address)
		if err != nil {
			return err
		}
		query := parsed.Query()
		redirect = query.Get("redirect_uri")
		callback, err := url.Parse(redirect)
		if err != nil {
			return err
		}
		if callback.Hostname() != "127.0.0.1" || callback.Port() == "" || callback.Path != "/oauth/callback" || query.Get("code_challenge_method") != "S256" || query.Get("scope") != "nebula:read" || query.Get("prompt") != "consent" {
			return errors.New("unsafe browser authorization")
		}
		challenge = query.Get("code_challenge")
		for _, values := range []url.Values{{"state": {"wrong"}, "code": {"single-code-fixture"}}, {"state": {query.Get("state")}, "code": {"a", "b"}}} {
			response, err := http.Get(redirect + "?" + values.Encode())
			if err != nil {
				return err
			}
			response.Body.Close()
			if response.StatusCode != 400 {
				return errors.New("invalid callback accepted")
			}
		}
		request, _ := http.NewRequest("GET", redirect+"?"+url.Values{"state": {query.Get("state")}, "code": {"single-code-fixture"}}.Encode(), nil)
		request.Host = "evil.example"
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != 400 {
			return errors.New("callback Host rebinding accepted")
		}
		response, err = http.Get(redirect + "?" + url.Values{"state": {query.Get("state")}, "code": {"single-code-fixture"}}.Encode())
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != 200 {
			return errors.New("valid callback refused")
		}
		response, err = http.Get(redirect + "?" + url.Values{"state": {query.Get("state")}, "code": {"single-code-fixture"}}.Encode())
		if err != nil {
			return err
		}
		response.Body.Close()
		if response.StatusCode != 409 {
			return errors.New("callback replay accepted")
		}
		return nil
	}
	if err := c.run(context.Background(), []string{"login", "--url", origin, "--loopback"}); err != nil {
		t.Fatal(err)
	}
	if exchanges != 1 {
		t.Fatal("authorization code was exchanged more than once")
	}
	file, err := c.load()
	if err != nil || file == nil {
		t.Fatalf("private token persistence failed: %v", err)
	}
	if file.state.Origin != origin || file.state.ClientID != "cli-fixture-id" || file.info.Mode().Perm() != 0600 {
		t.Fatal("wrong stored identity or file permissions")
	}
	output := c.output.(*bytes.Buffer).String()
	if strings.Contains(output, "private-access-fixture") || strings.Contains(output, "private-refresh-fixture") || strings.Contains(output, "code_verifier") {
		t.Fatal("CLI output exposed credentials")
	}
}
func TestHostedDiscoveryCannotSendTokensToAnotherService(t *testing.T) {
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := discoveryFixture(origin)
		d.Token = "https://other.example/oauth/token"
		json.NewEncoder(w).Encode(d)
	}))
	defer server.Close()
	origin = server.URL
	c := hostedFixture(t, server)
	opened := false
	c.open = func(string) error { opened = true; return nil }
	if err := c.login(context.Background(), origin, false); err == nil || opened {
		t.Fatal("cross-origin discovery accepted")
	}
	if file, err := c.load(); err != nil || file != nil {
		t.Fatal("rejected discovery created credentials")
	}
}
func TestHostedCancellationClosesLoopbackWithoutCredentials(t *testing.T) {
	var origin string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(discoveryFixture(origin)) }))
	defer server.Close()
	origin = server.URL
	c := hostedFixture(t, server)
	ctx, cancel := context.WithCancel(context.Background())
	var callback string
	c.open = func(address string) error {
		u, _ := url.Parse(address)
		cb, _ := url.Parse(u.Query().Get("redirect_uri"))
		callback = cb.Host
		cancel()
		return nil
	}
	if err := c.login(ctx, origin, false); err == nil {
		t.Fatal("cancelled login succeeded")
	}
	connection, err := net.DialTimeout("tcp4", callback, time.Second)
	if err == nil {
		connection.Close()
		t.Fatal("cancelled login left a callback listener")
	}
	if file, _ := c.load(); file != nil {
		t.Fatal("cancelled login saved credentials")
	}
}
func TestHostedCredentialsRefuseSymlinksWorldReadableFilesAndConcurrentChanges(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	c := hostedFixture(t, server)
	file, err := c.save(nil, hostedState(c, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.home, "hosted-auth.json")
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = c.load(); err == nil {
		t.Fatal("world-readable credential file accepted")
	}
	os.Chmod(path, 0600)
	replacement := hostedState(c, server.URL)
	replacement.OrganizationID = "202"
	if _, err = c.save(file, replacement); err != nil {
		t.Fatal(err)
	}
	if _, err = c.save(file, replacement); err == nil {
		t.Fatal("concurrent credential replacement was overwritten")
	}
	external := filepath.Join(t.TempDir(), "external")
	os.WriteFile(external, []byte("unrelated"), 0600)
	os.Remove(path)
	os.Symlink(external, path)
	if _, err = c.load(); err == nil {
		t.Fatal("credential symlink accepted")
	}
	if stringMustRead(t, external) != "unrelated" {
		t.Fatal("external file mutated")
	}
}
func stringMustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestHostedPrivateHomeRejectsSymlinkAndPublicDirectory(t *testing.T) {
	home := t.TempDir()
	os.Chmod(home, 0755)
	if err := hostedPrivateHome(home); err == nil {
		t.Fatal("public state directory accepted")
	}
	os.Chmod(home, 0700)
	link := filepath.Join(t.TempDir(), "linked")
	os.Symlink(home, link)
	if err := hostedPrivateHome(link); err == nil {
		t.Fatal("symlink state directory accepted")
	}
}
func TestHostedRefreshAndClusterReadsPreserveOrganizationWithoutFakeState(t *testing.T) {
	var origin string
	refreshes := 0
	reads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshes++
			r.ParseForm()
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "private-refresh-fixture" {
				t.Error("refresh did not use its own credential")
			}
			fmt.Fprint(w, `{"access_token":"rotated-access-fixture","refresh_token":"rotated-refresh-fixture","expires_in":900,"token_type":"Bearer"}`)
		case "/api/v1/organizations/201/clusters":
			reads++
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer rotated-access-fixture" || r.URL.Query().Get("page") != "2" {
				t.Error("cluster read used wrong scope, page or token")
			}
			fmt.Fprint(w, `{"data":[{"id":"cluster-fixture","state":"unobserved","observed_generation":0}],"current_page":2}`)
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	origin = server.URL
	c := hostedFixture(t, server)
	state := hostedState(c, origin)
	state.ExpiresAt = c.now().Add(-time.Minute).Unix()
	if _, err := c.save(nil, state); err != nil {
		t.Fatal(err)
	}
	if err := c.run(context.Background(), []string{"cluster", "list", "--page", "2"}); err != nil {
		t.Fatal(err)
	}
	file, err := c.load()
	if err != nil || file.state.RefreshToken != "rotated-refresh-fixture" || file.state.OrganizationID != "201" || refreshes != 1 || reads != 1 {
		t.Fatal("refresh rotation or selected organization was not preserved")
	}
	output := c.output.(*bytes.Buffer).String()
	if !strings.Contains(output, "unobserved") || strings.Contains(output, "Ready") || strings.Contains(output, "rotated-access-fixture") {
		t.Fatal("cluster output fabricated readiness or exposed a token")
	}
}
func TestHostedOrganizationSelectionRequiresReturnedMembership(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/api/v1/organizations" {
			t.Error("organization selection attempted a write")
		}
		fmt.Fprint(w, `{"data":[{"id":"201","name":"Approved team","role":"member"}]}`)
	}))
	defer server.Close()
	c := hostedFixture(t, server)
	state := hostedState(c, server.URL)
	state.OrganizationID = ""
	if _, err := c.save(nil, state); err != nil {
		t.Fatal(err)
	}
	if err := c.run(context.Background(), []string{"org", "use", "999"}); err == nil {
		t.Fatal("unknown membership selected")
	}
	file, _ := c.load()
	if file.state.OrganizationID != "" {
		t.Fatal("unknown selection persisted")
	}
	if err := c.run(context.Background(), []string{"org", "use", "201"}); err != nil {
		t.Fatal(err)
	}
	file, _ = c.load()
	if file.state.OrganizationID != "201" {
		t.Fatal("approved selection not saved")
	}
}
func TestHostedLogoutRemovesPrivateCredentialsWhenServerRevocationUnavailable(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/session/revoke" || r.Header.Get("Authorization") != "Bearer private-access-fixture" {
			t.Error("wrong token revocation request")
		}
		w.WriteHeader(503)
		fmt.Fprint(w, `{"secret":"do-not-print-response-fixture"}`)
	}))
	defer server.Close()
	c := hostedFixture(t, server)
	if _, err := c.save(nil, hostedState(c, server.URL)); err != nil {
		t.Fatal(err)
	}
	err := c.run(context.Background(), []string{"logout"})
	if err == nil || !strings.Contains(err.Error(), "local credentials removed") || strings.Contains(err.Error(), "do-not-print-response-fixture") {
		t.Fatal("logout did not report unconfirmed server revocation safely")
	}
	if file, _ := c.load(); file != nil {
		t.Fatal("logout retained local credentials")
	}
}
func TestHostedHTTPRedirectDoesNotForwardAuthorization(t *testing.T) {
	received := false
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true; fmt.Fprint(w, `{}`) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer server.Close()
	c := hostedFixture(t, server)
	if _, err := c.request(context.Background(), "GET", server.URL+"/api/v1/organizations", "private-access-fixture", nil); err == nil || received {
		t.Fatal("redirect followed with bearer authorization")
	}
}
func TestHostedOriginsRejectCredentialBearingOrNonHTTPSURLs(t *testing.T) {
	for _, value := range []string{"http://nebula.example", "https://user:secret@nebula.example", "https://nebula.example/dashboard", "https://nebula.example?token=secret", "https://nebula.example/#fragment"} {
		if _, err := hostedOrigin(value); err == nil {
			t.Fatal("unsafe service origin accepted")
		}
	}
}
