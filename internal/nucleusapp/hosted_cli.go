package nucleusapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const hostedHelp = `NEBULA hosted control panel

  nebula login [--url https://nebula.parallax.link] [--no-open]
  nebula logout
  nebula org list
  nebula org use ORGANIZATION_ID
  nebula cluster list [--org ORGANIZATION_ID] [--page 1]
  nebula cluster show CLUSTER_ID [--org ORGANIZATION_ID]

Login uses browser consent, PKCE and an IPv4 loopback callback. It is separate
from machine enrollment. API reads require current Nexus membership.
Credentials stay in a private hosted-auth.json file under NEBULA_HOME.
Cluster provisioning commands are not available in this release.
`

var hostedIdentifier = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

type hostedCredentials struct {
	SchemaVersion  int    `json:"schema_version"`
	Origin         string `json:"origin"`
	ClientID       string `json:"client_id"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	ExpiresAt      int64  `json:"expires_at"`
	OrganizationID string `json:"organization_id,omitempty"`
}
type hostedFile struct {
	state hostedCredentials
	data  []byte
	info  os.FileInfo
}
type hostedDiscovery struct {
	SchemaVersion int      `json:"schema_version"`
	Issuer        string   `json:"issuer"`
	ClientID      string   `json:"client_id"`
	Authorization string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Revocation    string   `json:"revocation_endpoint"`
	API           string   `json:"api_endpoint"`
	CallbackPath  string   `json:"callback_path"`
	Scopes        []string `json:"scopes_supported"`
}
type hostedToken struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Type    string `json:"token_type"`
	Expires int64  `json:"expires_in"`
}
type hostedOrganization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}
type hostedCLI struct {
	home   string
	client *http.Client
	output io.Writer
	open   func(string) error
	now    func() time.Time
}

func hostedCommand(args []string) error {
	if len(args) == 0 || isHelp(args[0]) {
		fmt.Print(hostedHelp)
		return nil
	}
	for _, arg := range args[1:] {
		if isHelp(arg) {
			fmt.Print(hostedHelp)
			return nil
		}
	}
	if (args[0] == "org" && (len(args) < 2 || (args[1] != "list" && args[1] != "use"))) || (args[0] == "cluster" && (len(args) < 2 || (args[1] != "list" && args[1] != "show"))) {
		return errors.New("unsupported hosted command; see nebula help")
	}
	home, err := nebulaHomePath()
	if err != nil {
		return err
	}
	if err = hostedPrivateHome(home); err != nil {
		return err
	}
	fd, err := syscall.Open(filepath.Join(home, "hosted-auth.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("cannot open private hosted credential lock")
	}
	lock := os.NewFile(uintptr(fd), "hosted-auth.lock")
	defer lock.Close()
	if err = hostedPrivateFile(lock); err != nil {
		return err
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another hosted NEBULA command is running")
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	cli := &hostedCLI{home: home, client: client, output: os.Stdout, open: hostedOpenBrowser, now: time.Now}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return cli.run(ctx, args)
}
func hostedPrivateHome(home string) error {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return errors.New("hosted state directory must be an absolute clean path")
	}
	for path := home; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("hosted state path must not contain symlinks")
		}
		if err != nil && !os.IsNotExist(err) {
			return errors.New("cannot inspect hosted state path")
		}
		if path == filepath.Dir(path) {
			break
		}
	}
	if err := os.MkdirAll(home, 0700); err != nil {
		return errors.New("cannot create private hosted state directory")
	}
	info, err := os.Lstat(home)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("hosted state directory must be private and owned by the current user")
	}
	return nil
}
func hostedPrivateFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		return errors.New("hosted credential file must be an ordinary private file owned by the current user")
	}
	return nil
}
func (c *hostedCLI) load() (*hostedFile, error) {
	fd, err := syscall.Open(filepath.Join(c.home, "hosted-auth.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("cannot safely open hosted credentials")
	}
	file := os.NewFile(uintptr(fd), "hosted-auth.json")
	defer file.Close()
	if err = hostedPrivateFile(file); err != nil {
		return nil, err
	}
	info, _ := file.Stat()
	data, err := io.ReadAll(io.LimitReader(file, 131073))
	if err != nil || len(data) > 131072 {
		return nil, errors.New("cannot read bounded hosted credentials")
	}
	var state hostedCredentials
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("hosted credentials are malformed")
	}
	origin, err := hostedOrigin(state.Origin)
	if err != nil || origin != state.Origin || state.SchemaVersion != 1 || !hostedIdentifier.MatchString(state.ClientID) || state.AccessToken == "" || state.RefreshToken == "" || state.ExpiresAt <= 0 {
		return nil, errors.New("hosted credentials are invalid; no machine credentials will be used")
	}
	return &hostedFile{state: state, data: data, info: info}, nil
}
func (c *hostedCLI) unchanged(previous *hostedFile) error {
	current, err := c.load()
	if err != nil {
		return err
	}
	if previous == nil && current == nil {
		return nil
	}
	if previous == nil || current == nil || !os.SameFile(previous.info, current.info) || !bytes.Equal(previous.data, current.data) {
		return errors.New("hosted credentials changed concurrently")
	}
	return nil
}
func (c *hostedCLI) save(previous *hostedFile, state hostedCredentials) (*hostedFile, error) {
	if err := c.unchanged(previous); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	file, err := os.CreateTemp(c.home, ".hosted-auth-")
	if err != nil {
		return nil, err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, errors.New("cannot save private hosted credentials")
	}
	if err = c.unchanged(previous); err != nil {
		return nil, err
	}
	path := filepath.Join(c.home, "hosted-auth.json")
	if previous == nil {
		err = os.Link(temp, path)
		if err == nil {
			err = os.Remove(temp)
		}
	} else {
		err = os.Rename(temp, path)
	}
	if err != nil {
		return nil, errors.New("cannot atomically save private hosted credentials")
	}
	return c.load()
}
func hostedOrigin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("hosted URL must be an HTTPS origin without credentials, path, query or fragment")
	}
	return "https://" + u.Host, nil
}
func (c *hostedCLI) request(ctx context.Context, method, address, bearer string, form url.Values) ([]byte, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request, err := http.NewRequestWithContext(ctx, method, address, body)
	if err != nil {
		return nil, errors.New("invalid NEBULA request")
	}
	request.Header.Set("Accept", "application/json")
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, errors.New("NEBULA request failed; verify service connectivity")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == 401 {
			return nil, errors.New("NEBULA sign-in expired or was revoked; run nebula login")
		}
		return nil, fmt.Errorf("NEBULA returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(data) > 1048576 || !json.Valid(data) {
		return nil, errors.New("NEBULA returned an invalid or oversized response")
	}
	return data, nil
}
func (c *hostedCLI) discovery(ctx context.Context, origin string) (hostedDiscovery, error) {
	var d hostedDiscovery
	data, err := c.request(ctx, "GET", origin+"/.well-known/nebula-cli", "", nil)
	if err != nil {
		return d, err
	}
	if json.Unmarshal(data, &d) != nil {
		return d, errors.New("invalid NEBULA CLI discovery")
	}
	if d.SchemaVersion != 1 || d.Issuer != origin || !hostedIdentifier.MatchString(d.ClientID) || d.Authorization != origin+"/oauth/authorize" || d.Token != origin+"/oauth/token" || d.Revocation != origin+"/api/v1/session/revoke" || d.API != origin+"/api/v1" || d.CallbackPath != "/oauth/callback" {
		return d, errors.New("NEBULA discovery must keep all endpoints on the selected service")
	}
	read := false
	for _, scope := range d.Scopes {
		if scope == "nebula:read" {
			read = true
		}
	}
	if !read {
		return d, errors.New("NEBULA read scope unavailable")
	}
	return d, nil
}
func hostedRandom() (string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
func (c *hostedCLI) exchange(ctx context.Context, origin string, values url.Values) (hostedToken, error) {
	var result hostedToken
	data, err := c.request(ctx, "POST", origin+"/oauth/token", "", values)
	if err != nil {
		return result, err
	}
	if json.Unmarshal(data, &result) != nil || !strings.EqualFold(result.Type, "Bearer") || result.Access == "" || result.Refresh == "" || len(result.Access) > 32768 || len(result.Refresh) > 32768 || result.Expires <= 0 || result.Expires > 3600 {
		return result, errors.New("NEBULA returned invalid token fields")
	}
	return result, nil
}
func (c *hostedCLI) login(ctx context.Context, origin string, noOpen bool) error {
	old, err := c.load()
	if err != nil {
		return err
	}
	d, err := c.discovery(ctx, origin)
	if err != nil {
		return err
	}
	state, err := hostedRandom()
	if err != nil {
		return err
	}
	verifier, err := hostedRandom()
	if err != nil {
		return err
	}
	challenge := sha256.Sum256([]byte(verifier))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return errors.New("cannot bind IPv4 loopback callback")
	}
	defer listener.Close()
	callback := "http://" + listener.Addr().String() + d.CallbackPath
	type answer struct {
		code   string
		denied bool
	}
	received := make(chan answer, 1)
	var completed atomic.Bool
	server := &http.Server{ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 3 * time.Second, MaxHeaderBytes: 8192}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		query, parseErr := url.ParseQuery(r.URL.RawQuery)
		values := query["state"]
		codes := query["code"]
		denial := query["error"]
		valid := parseErr == nil && r.Method == "GET" && r.Host == listener.Addr().String() && r.URL.Path == d.CallbackPath && len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(state)) == 1 && ((len(codes) == 1 && len(codes[0]) > 0 && len(codes[0]) <= 4096 && len(denial) == 0) || (len(denial) == 1 && len(codes) == 0))
		if !valid {
			http.Error(w, "Invalid sign-in callback.", http.StatusBadRequest)
			return
		}
		if !completed.CompareAndSwap(false, true) {
			http.Error(w, "Sign-in callback already received.", http.StatusConflict)
			return
		}
		result := answer{denied: len(denial) == 1}
		if len(codes) == 1 {
			result.code = codes[0]
		}
		select {
		case received <- result:
		default:
			http.Error(w, "Sign-in callback already received.", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><title>NEBULA</title><p>Sign-in received. Return to the terminal.</p>")
	})
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(closeCtx)
	}()
	query := url.Values{"client_id": {d.ClientID}, "redirect_uri": {callback}, "response_type": {"code"}, "scope": {"nebula:read"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}, "prompt": {"consent"}}
	address := d.Authorization + "?" + query.Encode()
	fmt.Fprintln(c.output, "Open this URL to authorize the NEBULA CLI:\n"+address)
	if !noOpen {
		_ = c.open(address)
	}
	var result answer
	select {
	case result = <-received:
	case <-ctx.Done():
		return errors.New("NEBULA sign-in cancelled or timed out")
	case <-serveErrors:
		return errors.New("NEBULA loopback callback stopped")
	}
	if result.denied {
		return errors.New("NEBULA CLI access was not approved")
	}
	token, err := c.exchange(ctx, origin, url.Values{"grant_type": {"authorization_code"}, "client_id": {d.ClientID}, "redirect_uri": {callback}, "code": {result.code}, "code_verifier": {verifier}})
	if err != nil {
		return err
	}
	_, err = c.save(old, hostedCredentials{SchemaVersion: 1, Origin: origin, ClientID: d.ClientID, AccessToken: token.Access, RefreshToken: token.Refresh, ExpiresAt: c.now().Add(time.Duration(token.Expires) * time.Second).Unix()})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.output, "Signed in to NEBULA. Run nebula org list, then nebula org use ORGANIZATION_ID.")
	return nil
}
func (c *hostedCLI) fresh(ctx context.Context, file *hostedFile) (*hostedFile, error) {
	if file == nil {
		return nil, errors.New("not signed in; run nebula login")
	}
	if file.state.ExpiresAt > c.now().Add(30*time.Second).Unix() {
		return file, nil
	}
	token, err := c.exchange(ctx, file.state.Origin, url.Values{"grant_type": {"refresh_token"}, "client_id": {file.state.ClientID}, "refresh_token": {file.state.RefreshToken}})
	if err != nil {
		return nil, err
	}
	state := file.state
	state.AccessToken = token.Access
	state.RefreshToken = token.Refresh
	state.ExpiresAt = c.now().Add(time.Duration(token.Expires) * time.Second).Unix()
	return c.save(file, state)
}
func (c *hostedCLI) organizations(ctx context.Context, file *hostedFile) ([]hostedOrganization, error) {
	data, err := c.request(ctx, "GET", file.state.Origin+"/api/v1/organizations", file.state.AccessToken, nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Data []hostedOrganization `json:"data"`
	}
	if json.Unmarshal(data, &result) != nil {
		return nil, errors.New("invalid organization list")
	}
	for _, org := range result.Data {
		if !hostedIdentifier.MatchString(org.ID) {
			return nil, errors.New("invalid organization identifier")
		}
	}
	return result.Data, nil
}
func (c *hostedCLI) run(ctx context.Context, args []string) error {
	if args[0] == "login" {
		var origin string
		var noOpen bool
		rest, err := options("login", args[1:], func(f *flag.FlagSet) {
			f.StringVar(&origin, "url", "https://nebula.parallax.link", "own hosted service origin")
			f.BoolVar(&noOpen, "no-open", false, "print authorization URL only")
		})
		if err != nil {
			return err
		}
		if len(rest) > 0 {
			return errors.New("usage: nebula login [--url HTTPS_ORIGIN] [--no-open]")
		}
		origin, err = hostedOrigin(origin)
		if err != nil {
			return err
		}
		loginCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		return c.login(loginCtx, origin, noOpen)
	}
	file, err := c.load()
	if err != nil {
		return err
	}
	if args[0] == "logout" {
		if len(args) != 1 {
			return errors.New("usage: nebula logout")
		}
		if file == nil {
			fmt.Fprintln(c.output, "Already signed out of the hosted NEBULA service.")
			return nil
		}
		current, refreshErr := c.fresh(ctx, file)
		if refreshErr == nil {
			file = current
			_, err = c.request(ctx, "POST", file.state.Origin+"/api/v1/session/revoke", file.state.AccessToken, url.Values{})
		} else {
			err = refreshErr
		}
		if guardErr := c.unchanged(file); guardErr != nil {
			return guardErr
		}
		if removeErr := os.Remove(filepath.Join(c.home, "hosted-auth.json")); removeErr != nil {
			return errors.New("cannot remove private hosted credentials")
		}
		if err != nil {
			return errors.New("local credentials removed; server token revocation could not be confirmed")
		}
		fmt.Fprintln(c.output, "Signed out. This CLI token and its refresh token were revoked.")
		return nil
	}
	file, err = c.fresh(ctx, file)
	if err != nil {
		return err
	}
	if args[0] == "org" {
		if (args[1] == "list" && len(args) != 2) || (args[1] == "use" && len(args) != 3) {
			return errors.New("usage: nebula org list | nebula org use ORGANIZATION_ID")
		}
		organizations, err := c.organizations(ctx, file)
		if err != nil {
			return err
		}
		if args[1] == "list" {
			return hostedJSON(c.output, map[string]any{"data": organizations, "selected_organization_id": file.state.OrganizationID})
		}
		for _, organization := range organizations {
			if organization.ID == args[2] {
				state := file.state
				state.OrganizationID = organization.ID
				if _, err = c.save(file, state); err != nil {
					return err
				}
				fmt.Fprintf(c.output, "Selected organization %q (%s).\n", organization.Name, organization.ID)
				return nil
			}
		}
		return errors.New("organization is not in your current Nexus memberships")
	}
	if args[0] == "cluster" {
		var organization string
		var page int
		rest, err := options("cluster", args[2:], func(f *flag.FlagSet) {
			f.StringVar(&organization, "org", file.state.OrganizationID, "organization identifier")
			f.IntVar(&page, "page", 1, "list page")
		})
		if err != nil {
			return err
		}
		if !hostedIdentifier.MatchString(organization) {
			return errors.New("select an organization with nebula org use or --org")
		}
		if page < 1 || page > 100000 {
			return errors.New("invalid cluster page")
		}
		address := file.state.Origin + "/api/v1/organizations/" + url.PathEscape(organization) + "/clusters"
		if args[1] == "show" {
			if len(rest) != 1 || !hostedIdentifier.MatchString(rest[0]) {
				return errors.New("usage: nebula cluster show CLUSTER_ID [--org ORGANIZATION_ID]")
			}
			address += "/" + url.PathEscape(rest[0])
		} else {
			if len(rest) != 0 {
				return errors.New("usage: nebula cluster list [--org ORGANIZATION_ID] [--page 1]")
			}
			address += "?page=" + fmt.Sprint(page)
		}
		data, err := c.request(ctx, "GET", address, file.state.AccessToken, nil)
		if err != nil {
			return err
		}
		var result any
		if json.Unmarshal(data, &result) != nil {
			return errors.New("invalid cluster response")
		}
		return hostedJSON(c.output, result)
	}
	return errors.New("unsupported hosted command; see nebula help")
}
func hostedJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
func hostedOpenBrowser(address string) error {
	path, err := exec.LookPath("xdg-open")
	if err != nil {
		return err
	}
	command := exec.Command(path, address)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err = command.Start(); err == nil {
		go command.Wait()
	}
	return err
}
