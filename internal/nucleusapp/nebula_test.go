package nucleusapp

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestNebulaRelayPublicKeyIsProtectedAndNeverAPrivateIdentity(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "issuer.pub")
	key := bytes.Repeat([]byte{17}, ed25519.PublicKeySize)
	if err := os.WriteFile(path, key, 0o444); err != nil {
		t.Fatal(err)
	}
	actual, err := readNebulaPublicKey(path)
	if err != nil || !bytes.Equal(actual, key) {
		t.Fatal("raw public key not accepted")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.RawURLEncoding.EncodeToString(key)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	actual, err = readNebulaPublicKey(path)
	if err != nil || !bytes.Equal(actual, key) {
		t.Fatal("encoded public key not accepted")
	}
	link := filepath.Join(root, "link.pub")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readNebulaPublicKey(link); err == nil {
		t.Fatal("symlink public key accepted")
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err = readNebulaPublicKey(path); err == nil {
		t.Fatal("writable public key accepted")
	}
}
func TestNebulaRelayRejectsPublicListenersBeforeStarting(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8743", "192.168.1.5:8743", "localhost:8743", "[::]:8743", "127.0.0.1:0"} {
		if err := nebulaCommand([]string{"relay", "--listen", address}); err == nil {
			t.Fatal("unsafe relay listener accepted")
		}
	}
}
