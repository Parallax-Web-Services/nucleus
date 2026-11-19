package fabric

import (
	"crypto/ed25519"
	"crypto/x509"
	"path/filepath"
	"testing"
	"time"
)

func TestAccountProofRequiresFabricOwnerAndSeparateSigningDomain(t *testing.T) {
	owner := filepath.Join(t.TempDir(), "owner")
	if _, err := Init(owner, "owner"); err != nil {
		t.Fatal(err)
	}
	message := []byte("parallax-cluster-connect-v1\nhttps://parallax.example\nrequest\n")
	if _, err := SignAccount(owner, message); err == nil {
		t.Fatal("unpaired node signed an account proof")
	}
	invite, err := Invite(owner, "https://127.0.0.1:9461", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	state, err := Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(state.CACertificate)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignAccount(owner, message)
	if err != nil || !ed25519.Verify(cert.PublicKey.(ed25519.PublicKey), message, proof) {
		t.Fatal("owner CA proof failed", err)
	}
	member := filepath.Join(t.TempDir(), "member")
	if _, err := Init(member, "member"); err != nil {
		t.Fatal(err)
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := FinishJoin(member, grant); err != nil {
		t.Fatal(err)
	}
	if _, err := SignAccount(member, message); err == nil {
		t.Fatal("member claimed CA ownership")
	}
	if _, err := SignAccount(owner, []byte("nucleus-cloud-v1\nother-domain")); err == nil {
		t.Fatal("account signer signed another protocol")
	}
	after, _ := Load(owner)
	if after.NodeID != state.NodeID || after.FabricID != state.FabricID {
		t.Fatal("account proof changed identity")
	}
}
