package nucleusapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const hostedDeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

var hostedUserCode = regexp.MustCompile(`^[A-Z2-9]{4}-?[A-Z2-9]{4}$`)

type hostedDeviceAuthorization struct {
	DeviceCode           string `json:"device_code"`
	UserCode             string `json:"user_code"`
	VerificationURI      string `json:"verification_uri"`
	VerificationComplete string `json:"verification_uri_complete"`
	Expires              int64  `json:"expires_in"`
	Interval             *int64 `json:"interval"`
}

type hostedDeviceToken struct {
	hostedToken
	Scope string `json:"scope"`
}

// Device responses may carry OAuth extension fields, but duplicate JSON members,
// trailing values, nulls and excessive nesting never override security fields.
func hostedDeviceDecode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 8 {
			return errors.New("invalid NEBULA device response")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("invalid NEBULA device response")
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := []string{}
			for d.More() {
				value, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := value.(string)
				if !ok || len(seen) >= 128 {
					return errors.New("ambiguous NEBULA device response")
				}
				// encoding/json matches struct fields case-insensitively, including
				// Unicode simple folding; reject aliases before it can overwrite one.
				for _, previous := range seen {
					if strings.EqualFold(previous, key) {
						return errors.New("ambiguous NEBULA device response")
					}
				}
				seen = append(seen, key)
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			value, err := d.Token()
			if err != nil || value != json.Delim('}') {
				return errors.New("invalid NEBULA device response")
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			value, err := d.Token()
			if err != nil || value != json.Delim(']') {
				return errors.New("invalid NEBULA device response")
			}
		default:
			return errors.New("invalid NEBULA device response")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return errors.New("invalid or ambiguous NEBULA device response")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("invalid or ambiguous NEBULA device response")
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return errors.New("invalid NEBULA device response")
	}
	return nil
}

func (c *hostedCLI) devicePost(ctx context.Context, address string, form url.Values) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, address, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, errors.New("invalid NEBULA device request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No redirect may forward a device secret or PKCE verifier to another endpoint.
	client := *c.client
	// A successful poll can refresh and revalidate the upstream NEXUS grant.
	// Its bounded work can exceed the ordinary API client timeout; the device
	// context still enforces the remaining authorization lifetime.
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, errors.New("NEBULA device sign-in could not be confirmed; run nebula login again")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, response.StatusCode, errors.New("NEBULA device sign-in refused an HTTP redirect")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 131073))
	if err != nil || len(data) > 131072 || !json.Valid(data) {
		return nil, response.StatusCode, errors.New("NEBULA returned an invalid or oversized device response")
	}
	return data, response.StatusCode, nil
}

func hostedDeviceOpaque(value string) bool {
	if len(value) < 32 || len(value) > 8192 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
func hostedDeviceVerification(d hostedDiscovery, response hostedDeviceAuthorization) (string, error) {
	if response.VerificationURI != d.Verification {
		return "", errors.New("NEBULA device verification must stay on the selected dashboard")
	}
	if response.VerificationComplete == "" {
		return d.Verification, nil
	}
	parsed, err := url.Parse(response.VerificationComplete)
	if err != nil || parsed.User != nil || strings.Contains(response.VerificationComplete, "#") || parsed.RawPath != "" || parsed.Opaque != "" {
		return "", errors.New("invalid NEBULA device verification URL")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 1 || len(query["user_code"]) != 1 || query.Get("user_code") != response.UserCode || parsed.RawQuery != query.Encode() {
		return "", errors.New("invalid NEBULA device verification URL")
	}
	parsed.RawQuery = ""
	if parsed.String() != d.Verification {
		return "", errors.New("NEBULA device verification must stay on the selected dashboard")
	}
	return response.VerificationComplete, nil
}
func (c *hostedCLI) deviceWait(ctx context.Context, duration time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, duration)
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func hostedDeviceStopped(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return errors.New("NEBULA device sign-in cancelled")
	}
	return errors.New("NEBULA device sign-in expired; run nebula login again")
}

func (c *hostedCLI) deviceLogin(ctx context.Context, origin string, noOpen bool) error {
	previous, err := c.load()
	if err != nil {
		return err
	}
	discovery, err := c.discovery(ctx, origin)
	if err != nil {
		return err
	}
	if discovery.DeviceAuthorization != origin+"/oauth/device/code" || discovery.Verification != origin+"/dashboard/cli/device" {
		return errors.New("device sign-in is unavailable on this NEBULA service; update the CLI or service")
	}
	verifier, err := hostedRandom()
	if err != nil {
		return errors.New("cannot create a private NEBULA sign-in proof")
	}
	challenge := sha256.Sum256([]byte(verifier))
	data, status, err := c.devicePost(ctx, discovery.DeviceAuthorization, url.Values{"client_id": {discovery.ClientID}, "scope": {"nebula:read"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}, "code_challenge_method": {"S256"}})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("NEBULA device sign-in is unavailable (HTTP %d)", status)
	}
	var authorization hostedDeviceAuthorization
	if err = hostedDeviceDecode(data, &authorization); err != nil {
		return err
	}
	interval := int64(5)
	if authorization.Interval != nil {
		interval = *authorization.Interval
	}
	if !hostedDeviceOpaque(authorization.DeviceCode) || !hostedUserCode.MatchString(authorization.UserCode) || authorization.Expires < 1 || authorization.Expires > 600 || interval < 5 || interval > 30 {
		return errors.New("NEBULA returned unsafe device sign-in fields")
	}
	verification, err := hostedDeviceVerification(discovery, authorization)
	if err != nil {
		return err
	}
	expires := c.now().Add(time.Duration(authorization.Expires) * time.Second)
	pollingCtx, cancel := context.WithTimeout(ctx, time.Duration(authorization.Expires)*time.Second)
	defer cancel()
	fmt.Fprintf(c.output, "Open this NEBULA dashboard page to approve CLI access:\n%s\n\nEnter code: %s\nWaiting for approval. You can use a browser on another device.\n", authorization.VerificationURI, authorization.UserCode)
	if !noOpen {
		_ = c.open(verification)
	}
	for {
		if !c.now().Before(expires) {
			return hostedDeviceStopped(pollingCtx)
		}
		if err = c.deviceWait(pollingCtx, time.Duration(interval)*time.Second); err != nil {
			return hostedDeviceStopped(pollingCtx)
		}
		if !c.now().Before(expires) || pollingCtx.Err() != nil {
			return hostedDeviceStopped(pollingCtx)
		}
		data, status, err = c.devicePost(pollingCtx, discovery.Token, url.Values{"grant_type": {hostedDeviceGrant}, "client_id": {discovery.ClientID}, "device_code": {authorization.DeviceCode}, "code_verifier": {verifier}})
		// A transport failure may follow successful issuance. Never replay an uncertain
		// exchange, create another request automatically, or fall back to localhost.
		if err != nil {
			return err
		}
		if status == http.StatusOK {
			var token hostedDeviceToken
			if err = hostedDeviceDecode(data, &token); err != nil {
				return err
			}
			if token.Type != "Bearer" || token.Access == "" || token.Refresh == "" || len(token.Access) > 32768 || len(token.Refresh) > 32768 || token.Expires < 1 || token.Expires > 3600 || token.Scope != "nebula:read" {
				return errors.New("NEBULA returned invalid read-only device tokens")
			}
			if _, err = c.save(previous, hostedCredentials{SchemaVersion: 1, Origin: origin, ClientID: discovery.ClientID, AccessToken: token.Access, RefreshToken: token.Refresh, ExpiresAt: c.now().Add(time.Duration(token.Expires) * time.Second).Unix()}); err != nil {
				return err
			}
			fmt.Fprintln(c.output, "Signed in to NEBULA. Run nebula org list, then nebula org use ORGANIZATION_ID.")
			return nil
		}
		var failure struct {
			Error string `json:"error"`
		}
		if err = hostedDeviceDecode(data, &failure); err != nil {
			return err
		}
		// League emits an authenticated user's denial as HTTP 401. Other 401
		// responses remain terminal even if they contain a pending/backoff code.
		if status == http.StatusUnauthorized {
			if failure.Error == "access_denied" {
				return errors.New("NEBULA CLI access was not approved")
			}
			return fmt.Errorf("NEBULA device sign-in stopped (HTTP %d)", status)
		}
		if status != http.StatusBadRequest && status != http.StatusTooManyRequests {
			return fmt.Errorf("NEBULA device sign-in stopped (HTTP %d)", status)
		}
		switch failure.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5
			if interval > 600 {
				return hostedDeviceStopped(pollingCtx)
			}
			continue
		case "access_denied":
			return errors.New("NEBULA CLI access was not approved")
		case "expired_token", "invalid_grant":
			return errors.New("NEBULA device sign-in expired or was already used; run nebula login again")
		default:
			return errors.New("NEBULA device sign-in stopped; run nebula login again")
		}
	}
}
