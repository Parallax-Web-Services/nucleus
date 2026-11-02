package fabric

import (
	"crypto/ed25519"
	"errors"
	"strings"
)

// CloudIdentity exposes the existing public identity, never its private key.
func CloudIdentity(home string) (*State, ed25519.PublicKey, error) {
	root, err := checkedHome(home, false)
	if err != nil {
		return nil, nil, err
	}
	state, err := loadDisk(root)
	if err != nil {
		return nil, nil, err
	}
	key, err := parseKey(state.IdentityKey)
	if err != nil {
		return nil, nil, err
	}
	public := append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
	return &state.Public, public, nil
}

// SignCloud signs only the two domain-separated hosted protocol messages.
// Fabric membership, TLS certificates, and CA authority are unchanged.
func SignCloud(home string, message []byte) ([]byte, error) {
	if len(message) > 8192 || (!strings.HasPrefix(string(message), "nucleus-enroll-v1\n") &&
		!strings.HasPrefix(string(message), "nucleus-cloud-v1\n")) {
		return nil, errors.New("unsupported hosted signing message")
	}
	root, err := checkedHome(home, false)
	if err != nil {
		return nil, err
	}
	state, err := loadDisk(root)
	if err != nil {
		return nil, err
	}
	key, err := parseKey(state.IdentityKey)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}
