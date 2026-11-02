package nebula

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	CapabilityMaxJSONBytes  = 8192
	CapabilityMaxTokenBytes = (CapabilityMaxJSONBytes*8+5)/6 + 1 + (ed25519.SignatureSize*8+5)/6
	CapabilityLifetime      = 30 * time.Second
)

var (
	ErrInvalidCapability = errors.New("invalid NEBULA capability")
	ErrExpiredCapability = errors.New("expired NEBULA capability")
	ErrInvalidNodeProof  = errors.New("invalid NEBULA node proof")
)

// Capability is the authority's short-lived authorization for one connection.
// PeerID and StreamID are empty strings when their mode does not use them.
type Capability struct {
	V            int    `json:"v"`
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	TeamID       string `json:"team_id"`
	NodeID       string `json:"node_id"`
	PublicKey    string `json:"public_key"`
	FabricID     string `json:"fabric_id"`
	Service      string `json:"service"`
	Mode         string `json:"mode"`
	PeerID       string `json:"peer_id"`
	ConnectionID string `json:"connection_id"`
	StreamID     string `json:"stream_id"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	JTI          string `json:"jti"`
}

// VerifyCapability verifies the authority signature and the complete connection
// binding. The relay must separately consume JTI atomically to reject replay.
func VerifyCapability(token string, issuer ed25519.PublicKey, now time.Time) (Capability, error) {
	var capability Capability
	if len(issuer) != ed25519.PublicKeySize || len(token) == 0 || len(token) > CapabilityMaxTokenBytes {
		return capability, ErrInvalidCapability
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return capability, ErrInvalidCapability
	}
	raw, err := decodeCanonical(parts[0], base64.RawURLEncoding, CapabilityMaxJSONBytes)
	if err != nil {
		return capability, ErrInvalidCapability
	}
	signature, err := decodeCanonical(parts[1], base64.RawURLEncoding, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(issuer, append([]byte("nebula-capability-v1\n"), raw...), signature) {
		return capability, ErrInvalidCapability
	}
	if err := decodeCapability(raw, &capability); err != nil {
		return Capability{}, ErrInvalidCapability
	}
	if capability.V != 1 || capability.Issuer != "https://positronic.app" ||
		capability.Audience != "nebula-relay" || capability.Service != "nucleus-fabric" ||
		!validTeamID(capability.TeamID) || !lowerHex(capability.NodeID, 64) ||
		!lowerHex(capability.FabricID, 64) || !lowerHex(capability.ConnectionID, 64) ||
		!lowerHex(capability.JTI, 32) {
		return Capability{}, ErrInvalidCapability
	}
	if _, err := capabilityPublicKey(capability); err != nil {
		return Capability{}, ErrInvalidCapability
	}
	switch capability.Mode {
	case "listen":
		if capability.PeerID != "" || capability.StreamID != "" {
			return Capability{}, ErrInvalidCapability
		}
	case "dial":
		if !lowerHex(capability.PeerID, 64) || capability.PeerID == capability.NodeID || capability.StreamID != "" {
			return Capability{}, ErrInvalidCapability
		}
	case "accept":
		if !lowerHex(capability.PeerID, 64) || capability.PeerID == capability.NodeID || !lowerHex(capability.StreamID, 32) {
			return Capability{}, ErrInvalidCapability
		}
	default:
		return Capability{}, ErrInvalidCapability
	}
	if capability.IssuedAt <= 0 || capability.ExpiresAt <= capability.IssuedAt ||
		capability.ExpiresAt-capability.IssuedAt > int64(CapabilityLifetime/time.Second) ||
		capability.IssuedAt > now.Unix()+5 {
		return Capability{}, ErrInvalidCapability
	}
	if capability.ExpiresAt <= now.Unix() {
		return Capability{}, ErrExpiredCapability
	}
	return capability, nil
}

// SameBinding allows renewal only for the original identity and connection.
// The renewed authority signature, timestamps and fresh JTI still need checking.
func (c Capability) SameBinding(other Capability) bool {
	return c.V == other.V && c.Issuer == other.Issuer && c.Audience == other.Audience &&
		c.TeamID == other.TeamID && c.NodeID == other.NodeID && c.PublicKey == other.PublicKey &&
		c.FabricID == other.FabricID && c.Service == other.Service && c.Mode == other.Mode &&
		c.PeerID == other.PeerID && c.ConnectionID == other.ConnectionID && c.StreamID == other.StreamID
}

// NodeProofMessage binds possession of the existing node identity to this exact
// signed capability, including its one-time JTI and connection binding.
func NodeProofMessage(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return []byte("nebula-relay-v1\n" + hex.EncodeToString(sum[:]))
}

// VerifyNodeProof checks node-key possession after VerifyCapability succeeds.
func VerifyNodeProof(token, proof string, capability Capability) error {
	if token == "" || len(token) > CapabilityMaxTokenBytes {
		return ErrInvalidNodeProof
	}
	public, err := capabilityPublicKey(capability)
	if err != nil {
		return ErrInvalidNodeProof
	}
	signature, err := decodeCanonical(proof, base64.StdEncoding, ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		!ed25519.Verify(public, NodeProofMessage(token), signature) {
		return ErrInvalidNodeProof
	}
	return nil
}

func capabilityPublicKey(capability Capability) (ed25519.PublicKey, error) {
	raw, err := decodeCanonical(capability.PublicKey, base64.RawURLEncoding, ed25519.PublicKeySize)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidCapability
	}
	public := ed25519.PublicKey(raw)
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, ErrInvalidCapability
	}
	hash := sha256.Sum256(der)
	if hex.EncodeToString(hash[:]) != capability.NodeID {
		return nil, ErrInvalidCapability
	}
	return public, nil
}

func decodeCanonical(value string, encoding *base64.Encoding, limit int) ([]byte, error) {
	if value == "" || len(value) > encoding.EncodedLen(limit) {
		return nil, ErrInvalidCapability
	}
	raw, err := encoding.Strict().DecodeString(value)
	if err != nil || len(raw) > limit || encoding.EncodeToString(raw) != value {
		return nil, ErrInvalidCapability
	}
	return raw, nil
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9') && !(char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

func validTeamID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			continue
		}
		if i == 0 || char != '_' && char != '-' {
			return false
		}
	}
	return true
}

func decodeCapability(raw []byte, capability *Capability) error {
	if len(raw) == 0 || len(raw) > CapabilityMaxJSONBytes || !utf8.Valid(raw) {
		return ErrInvalidCapability
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInvalidCapability
	}
	seen := make(map[string]bool, 15)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return ErrInvalidCapability
		}
		switch key {
		case "v", "iss", "aud", "team_id", "node_id", "public_key", "fabric_id", "service",
			"mode", "peer_id", "connection_id", "stream_id", "iat", "exp", "jti":
		default:
			return ErrInvalidCapability
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInvalidCapability
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 15 {
		return ErrInvalidCapability
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrInvalidCapability
	}
	return json.Unmarshal(raw, capability)
}
