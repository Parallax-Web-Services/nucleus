package fabric

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestNebulaProofUsesExistingIdentityAndRejectsOtherSigningDomains(t *testing.T) {
	home := t.TempDir() + "/node"
	state, err := Init(home, "network-node")
	if err != nil {
		t.Fatal(err)
	}
	_, public, err := CloudIdentity(home)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("nebula-relay-v1\n" + strings.Repeat("a", 64))
	proof, err := SignNebula(home, message)
	if err != nil || !ed25519.Verify(public, message, proof) {
		t.Fatal("existing identity did not sign exact relay proof")
	}
	after, err := Load(home)
	if err != nil || after.NodeID != state.NodeID {
		t.Fatal("identity changed")
	}
	for _, bad := range []string{"nucleus-cloud-v1\n" + strings.Repeat("a", 64), "nebula-relay-v1\n" + strings.Repeat("a", 63), "nebula-relay-v1\n" + strings.Repeat("a", 64) + "\n"} {
		if _, err := SignNebula(home, []byte(bad)); err == nil {
			t.Fatal("unsupported signing domain accepted")
		}
	}
}
