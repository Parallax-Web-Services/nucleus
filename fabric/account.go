package fabric

import (
	"crypto/ed25519"
	"errors"
	"strings"
)

// SignAccount proves control of the existing fabric CA to a Parallax account.
// Members cannot sign this domain; CA private bytes never leave the state store.
func SignAccount(home string, message []byte) ([]byte, error) {
	if len(message) > 8192 || (!strings.HasPrefix(string(message), "parallax-cluster-connect-v1\n") && !strings.HasPrefix(string(message), "parallax-cluster-report-v1\n")) {
		return nil, errors.New("unsupported Parallax account signing message")
	}
	root, err := checkedHome(home, false)
	if err != nil {
		return nil, err
	}
	state, err := loadDisk(root)
	if err != nil {
		return nil, err
	}
	if state.Public.FabricID == "" || state.Public.NodeID != state.Public.OwnerID || len(state.CAKey) == 0 {
		return nil, errors.New("connect the fabric from its existing owner/coordinator")
	}
	key, err := parseKey(state.CAKey)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}
