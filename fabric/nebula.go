package fabric

import (
	"crypto/ed25519"
	"errors"
	"regexp"
)

var nebulaProofMessage = regexp.MustCompile("\\Anebula-relay-v1\\n[a-f0-9]{64}\\z")

// SignNebula uses the existing node key for one bounded relay proof domain.
func SignNebula(home string, message []byte) ([]byte, error) {
	if !nebulaProofMessage.Match(message) {
		return nil, errors.New("unsupported NEBULA signing message")
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
