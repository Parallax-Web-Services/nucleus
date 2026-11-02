package nebula

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func capabilityFixture(t *testing.T) (Capability, ed25519.PrivateKey, ed25519.PrivateKey, time.Time) {
	t.Helper()
	issuer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{27}, 32))
	node := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{91}, 32))
	public := node.Public().(ed25519.PublicKey)
	prefix, err := hex.DecodeString("302a300506032b6570032100")
	if err != nil {
		t.Fatal(err)
	}
	nodeHash := sha256.Sum256(append(prefix, public...))
	now := time.Unix(1793646000, 0)
	return Capability{
		V: 1, Issuer: "https://positronic.app", Audience: "nebula-relay", TeamID: "201",
		NodeID: hex.EncodeToString(nodeHash[:]), PublicKey: base64.RawURLEncoding.EncodeToString(public),
		FabricID: strings.Repeat("a", 64), Service: "nucleus-fabric", Mode: "listen",
		ConnectionID: strings.Repeat("b", 64), IssuedAt: now.Unix(), ExpiresAt: now.Unix() + 30,
		JTI: strings.Repeat("c", 32),
	}, issuer, node, now
}

func capabilityRaw(t *testing.T, capability Capability) []byte {
	t.Helper()
	raw, err := json.Marshal(capability)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func capabilitySignedRaw(raw []byte, issuer ed25519.PrivateKey) string {
	signature := ed25519.Sign(issuer, append([]byte("nebula-capability-v1\n"), raw...))
	return base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func capabilitySigned(t *testing.T, capability Capability, issuer ed25519.PrivateKey) string {
	t.Helper()
	return capabilitySignedRaw(capabilityRaw(t, capability), issuer)
}

func TestCapabilityAcceptsBoundedSignedModes(t *testing.T) {
	for _, mode := range []string{"listen", "dial", "accept"} {
		t.Run(mode, func(t *testing.T) {
			capability, issuer, _, now := capabilityFixture(t)
			capability.Mode = mode
			if mode != "listen" {
				capability.PeerID = strings.Repeat("d", 64)
			}
			if mode == "accept" {
				capability.StreamID = strings.Repeat("e", 32)
			}
			got, err := VerifyCapability(capabilitySigned(t, capability, issuer), issuer.Public().(ed25519.PublicKey), now)
			if err != nil || got != capability {
				t.Fatalf("valid %s capability rejected: %v", mode, err)
			}
		})
	}
}

func TestCapabilityRejectsInvalidAuthorityIdentityAndConnectionClaims(t *testing.T) {
	tests := map[string]func(*Capability){
		"version":              func(c *Capability) { c.V = 2 },
		"issuer":               func(c *Capability) { c.Issuer = "https://positronic.app.attacker.example" },
		"audience":             func(c *Capability) { c.Audience = "another-service" },
		"empty organization":   func(c *Capability) { c.TeamID = "" },
		"long organization":    func(c *Capability) { c.TeamID = strings.Repeat("a", 129) },
		"organization control": func(c *Capability) { c.TeamID = "201\nother" },
		"organization prefix":  func(c *Capability) { c.TeamID = "_201" },
		"node mismatch":        func(c *Capability) { c.NodeID = strings.Repeat("a", 64) },
		"uppercase fabric":     func(c *Capability) { c.FabricID = strings.Repeat("A", 64) },
		"public key padding":   func(c *Capability) { c.PublicKey += "=" },
		"service":              func(c *Capability) { c.Service = "arbitrary-tcp" },
		"mode":                 func(c *Capability) { c.Mode = "exec" },
		"connection":           func(c *Capability) { c.ConnectionID = strings.Repeat("b", 63) },
		"jti":                  func(c *Capability) { c.JTI = strings.Repeat("c", 33) },
		"listen peer":          func(c *Capability) { c.PeerID = strings.Repeat("d", 64) },
		"listen stream":        func(c *Capability) { c.StreamID = strings.Repeat("e", 32) },
		"dial no peer":         func(c *Capability) { c.Mode = "dial" },
		"dial self":            func(c *Capability) { c.Mode = "dial"; c.PeerID = c.NodeID },
		"dial stream": func(c *Capability) {
			c.Mode = "dial"
			c.PeerID = strings.Repeat("d", 64)
			c.StreamID = strings.Repeat("e", 32)
		},
		"accept no stream": func(c *Capability) { c.Mode = "accept"; c.PeerID = strings.Repeat("d", 64) },
		"accept self":      func(c *Capability) { c.Mode = "accept"; c.PeerID = c.NodeID; c.StreamID = strings.Repeat("e", 32) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			capability, issuer, _, now := capabilityFixture(t)
			mutate(&capability)
			token := capabilitySigned(t, capability, issuer)
			_, err := VerifyCapability(token, issuer.Public().(ed25519.PublicKey), now)
			if !errors.Is(err, ErrInvalidCapability) {
				t.Fatalf("invalid claim accepted or wrong failure: %v", err)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), capability.PublicKey) {
				t.Fatal("private capability material leaked in error")
			}
		})
	}
}

func TestCapabilityRejectsTamperingWrongIssuerAndNoncanonicalEncoding(t *testing.T) {
	capability, issuer, _, now := capabilityFixture(t)
	token := capabilitySigned(t, capability, issuer)
	parts := strings.Split(token, ".")
	raw := capabilityRaw(t, capability)
	tampered := bytes.Replace(raw, []byte("201"), []byte("202"), 1)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	wrongDomain := ed25519.Sign(issuer, append([]byte("different-domain\n"), raw...))
	tests := []struct {
		token string
		key   ed25519.PublicKey
	}{
		{base64.RawURLEncoding.EncodeToString(tampered) + "." + parts[1], issuer.Public().(ed25519.PublicKey)},
		{token, other.Public().(ed25519.PublicKey)},
		{token, nil},
		{parts[0] + "=." + parts[1], issuer.Public().(ed25519.PublicKey)},
		{parts[0] + "." + parts[1] + "\n", issuer.Public().(ed25519.PublicKey)},
		{parts[0] + "." + base64.RawURLEncoding.EncodeToString(wrongDomain), issuer.Public().(ed25519.PublicKey)},
		{token + ".extra", issuer.Public().(ed25519.PublicKey)},
	}
	for index, test := range tests {
		if _, err := VerifyCapability(test.token, test.key, now); !errors.Is(err, ErrInvalidCapability) {
			t.Fatalf("case %d accepted invalid signature or encoding: %v", index, err)
		}
	}
}

func TestCapabilityRequiresStrictFlatJSON(t *testing.T) {
	capability, issuer, _, now := capabilityFixture(t)
	raw := capabilityRaw(t, capability)
	tests := map[string][]byte{
		"duplicate":            append([]byte(`{"v":1,`), raw[1:]...),
		"unknown":              append([]byte(`{"extra":"not permitted",`), raw[1:]...),
		"case variant":         bytes.Replace(raw, []byte(`"v":`), []byte(`"V":`), 1),
		"missing peer":         bytes.Replace(raw, []byte(`"peer_id":"",`), nil, 1),
		"null stream":          bytes.Replace(raw, []byte(`"stream_id":""`), []byte(`"stream_id":null`), 1),
		"numeric organization": bytes.Replace(raw, []byte(`"team_id":"201"`), []byte(`"team_id":201`), 1),
		"float timestamp":      bytes.Replace(raw, []byte(`"iat":1793646000`), []byte(`"iat":1793646000.0`), 1),
		"nested value":         bytes.Replace(raw, []byte(`"team_id":"201"`), []byte(`"team_id":{"id":"201"}`), 1),
		"trailing object":      append(append([]byte(nil), raw...), []byte(" {}")...),
		"array":                []byte("[]"),
		"oversize":             append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), CapabilityMaxJSONBytes)...),
		"invalid utf8":         bytes.Replace(raw, []byte("201"), []byte{255}, 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyCapability(capabilitySignedRaw(data, issuer), issuer.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrInvalidCapability) {
				t.Fatalf("non-strict JSON accepted: %v", err)
			}
		})
	}
}

func TestCapabilityLifetimeHasNoExpirationGrace(t *testing.T) {
	tests := []struct {
		name           string
		issued, expiry int64
		expected       error
	}{
		{"normal", 0, 30, nil}, {"last second", -29, 1, nil}, {"clock skew", 5, 35, nil},
		{"future", 6, 36, ErrInvalidCapability}, {"long lifetime", 0, 31, ErrInvalidCapability},
		{"expired", -31, -1, ErrExpiredCapability}, {"exact expiry", -30, 0, ErrExpiredCapability},
		{"empty lifetime", 0, 0, ErrInvalidCapability}, {"reversed", 1, 0, ErrInvalidCapability},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capability, issuer, _, now := capabilityFixture(t)
			capability.IssuedAt = now.Unix() + test.issued
			capability.ExpiresAt = now.Unix() + test.expiry
			_, err := VerifyCapability(capabilitySigned(t, capability, issuer), issuer.Public().(ed25519.PublicKey), now)
			if !errors.Is(err, test.expected) {
				t.Fatalf("wrong lifetime outcome: got %v want %v", err, test.expected)
			}
		})
	}
}

func TestNodeProofBindsExistingIdentityToExactCapability(t *testing.T) {
	capability, issuer, node, _ := capabilityFixture(t)
	token := capabilitySigned(t, capability, issuer)
	proof := base64.StdEncoding.EncodeToString(ed25519.Sign(node, NodeProofMessage(token)))
	if err := VerifyNodeProof(token, proof, capability); err != nil {
		t.Fatal(err)
	}
	renewed := capability
	renewed.JTI = strings.Repeat("d", 32)
	renewal := capabilitySigned(t, renewed, issuer)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	tests := []struct{ token, proof string }{
		{renewal, proof},
		{token, base64.StdEncoding.EncodeToString(ed25519.Sign(other, NodeProofMessage(token)))},
		{token, proof + "\n"},
		{token, strings.TrimRight(proof, "=")},
		{"", proof},
	}
	for index, test := range tests {
		if err := VerifyNodeProof(test.token, test.proof, capability); !errors.Is(err, ErrInvalidNodeProof) {
			t.Fatalf("invalid proof case%d accepted: %v", index, err)
		}
	}
}

func TestCapabilityRenewalCannotChangeOrganizationIdentityOrConnection(t *testing.T) {
	capability, _, _, _ := capabilityFixture(t)
	renewal := capability
	renewal.IssuedAt += 10
	renewal.ExpiresAt += 10
	renewal.JTI = strings.Repeat("d", 32)
	if !capability.SameBinding(renewal) {
		t.Fatal("fresh lifetime and JTI must permit renewal")
	}
	tests := []func(*Capability){
		func(c *Capability) { c.V++ }, func(c *Capability) { c.Issuer = "different" }, func(c *Capability) { c.Audience = "different" },
		func(c *Capability) { c.TeamID = "202" }, func(c *Capability) { c.NodeID = strings.Repeat("e", 64) },
		func(c *Capability) { c.PublicKey = "different" }, func(c *Capability) { c.FabricID = strings.Repeat("f", 64) },
		func(c *Capability) { c.Service = "different" }, func(c *Capability) { c.Mode = "dial" },
		func(c *Capability) { c.PeerID = strings.Repeat("d", 64) }, func(c *Capability) { c.ConnectionID = strings.Repeat("c", 64) },
		func(c *Capability) { c.StreamID = strings.Repeat("f", 32) },
	}
	for index, mutate := range tests {
		changed := renewal
		mutate(&changed)
		if capability.SameBinding(changed) {
			t.Fatalf("renewal changed protected binding field %d", index)
		}
	}
}

// This vector was produced by PHP sodium. It contains public test artifacts only,
// with no signing seeds or private node identity material.
func TestCapabilityInteroperatesWithPHPAuthorityAndNodeProof(t *testing.T) {
	raw, err := os.ReadFile("testdata/php-capability-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		IssuerPublicKey string `json:"issuer_public_key_base64url"`
		Token           string `json:"token"`
		Proof           string `json:"relay_proof_base64"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	issuer, err := base64.RawURLEncoding.Strict().DecodeString(vector.IssuerPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	capability, err := VerifyCapability(vector.Token, ed25519.PublicKey(issuer), time.Unix(1800000000, 0))
	if err != nil {
		t.Fatalf("PHP capability rejected: %v", err)
	}
	if err = VerifyNodeProof(vector.Token, vector.Proof, capability); err != nil {
		t.Fatalf("PHP node proof rejected: %v", err)
	}
	if capability.Issuer != "https://positronic.app" || capability.TeamID != "42" || capability.Mode != "dial" {
		t.Fatal("PHP fixture lost the expected service/organization binding")
	}
}
