package nucleusapp

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Parallax-Web-Services/nucleus/fabric"
)

func TestNebulaNetworkCannotDisableRelayTransport(t *testing.T) {
	for _, flag := range []string{"--nebula=false", "-nebula=false", "--nebula", "-nebula", "--nebula=true"} {
		t.Run(flag, func(t *testing.T) {
			if _, _, err := nebulaInvocation([]string{"network", "connect", flag}); err == nil {
				t.Fatal("transport override accepted")
			}
		})
	}
	command, help, err := nebulaInvocation([]string{"network", "connect", "--no-open"})
	if err != nil || help != "" || len(command) < 2 || command[0] != "run" || command[1] != "--nebula" {
		t.Fatalf("relay not forced: %v %v", command, err)
	}
}

func TestNebulaStandaloneBinariesShareRealFabricIdentity(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	goBin := filepath.Join(root, ".tools", "go", "bin", "go")
	if _, err = os.Stat(goBin); err != nil {
		goBin, err = exec.LookPath("go")
		if err != nil {
			t.Fatal("Go toolchain required for CLI integration test")
		}
	}
	bin := t.TempDir()
	programs := map[string]string{}
	for _, name := range []string{"nucleus", "nebula"} {
		target := filepath.Join(bin, name)
		build := exec.Command(goBin, "build", "-o", target, "./cmd/"+name)
		build.Dir = root
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", name, err, output)
		}
		programs[name] = target
	}
	owner, member, unused := filepath.Join(t.TempDir(), "owner"), filepath.Join(t.TempDir(), "member"), filepath.Join(t.TempDir(), "unused")
	environment := func(nebulaHome, nucleusHome string) []string {
		var result []string
		for _, entry := range os.Environ() {
			if strings.HasPrefix(entry, "PATH=") || strings.HasPrefix(entry, "NEBULA_HOME=") || strings.HasPrefix(entry, "NUCLEUS_HOME=") {
				continue
			}
			result = append(result, entry)
		}
		// Executables are addressed directly. No installed nucleus, shell, or
		// browser command is available to the standalone NEBULA process.
		return append(result, "PATH="+filepath.Join(bin, "empty-path"), "NEBULA_HOME="+nebulaHome, "NUCLEUS_HOME="+nucleusHome)
	}
	run := func(program, nebulaHome, nucleusHome string, success bool, args ...string) string {
		t.Helper()
		command := exec.Command(programs[program], args...)
		command.Env = environment(nebulaHome, nucleusHome)
		output, err := command.CombinedOutput()
		if success && err != nil {
			t.Fatalf("%s %v: %v\n%s", program, args, err, output)
		}
		if !success && err == nil {
			t.Fatalf("%s %v unexpectedly succeeded: %s", program, args, output)
		}
		return string(output)
	}
	if got := run("nebula", "relative", unused, true, "version"); got != "nebula 0.6.0-dev\n" {
		t.Fatalf("own version: %q", got)
	}
	if got := run("nucleus", "relative", unused, true, "--version"); got != "nucleus 0.5.0-alpha\n" {
		t.Fatalf("legacy version changed: %q", got)
	}
	help := run("nebula", "relative", unused, true, "--help")
	if !strings.Contains(help, "nebula network connect") || strings.Contains(help, "nucleus init") {
		t.Fatal("standalone help is not NEBULA's")
	}
	run("nebula", unused, unused, false, "cluster", "create")
	if _, err := os.Stat(unused); !os.IsNotExist(err) {
		t.Fatal("help/version/unsupported command created state")
	}
	run("nebula", owner, unused, true, "machine", "init", "--name", "owner")
	run("nucleus", "relative", member, true, "init", "--name", "member")
	// Explicit NEBULA_HOME selects the owner; legacy Nucleus ignores it.
	ownerState, err := fabric.Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	memberState, err := fabric.Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if ownerState.NodeID == memberState.NodeID {
		t.Fatal("independent machines share identity")
	}
	ownerIdentity := run("nebula", owner, unused, true, "machine", "identity")
	if !strings.Contains(ownerIdentity, ownerState.NodeID) || strings.Contains(ownerIdentity, "identity_key") || strings.Contains(ownerIdentity, "ca_key") {
		t.Fatal("identity response is not public owner metadata")
	}
	var status struct {
		Registered bool `json:"registered"`
	}
	if err := json.Unmarshal([]byte(run("nebula", owner, unused, true, "machine", "status")), &status); err != nil || status.Registered {
		t.Fatal("unregistered machine status is false")
	}
	pairing := t.TempDir()
	invite, request, grant := filepath.Join(pairing, "invite.json"), filepath.Join(pairing, "request.json"), filepath.Join(pairing, "grant.json")
	run("nebula", owner, unused, true, "fabric", "invite", "--endpoint", "https://10.17.0.1:9461", "--out", invite)
	run("nucleus", "relative", member, true, "join", invite, "--out", request)
	if output := run("nebula", owner, unused, true, "fabric", "inspect", request); !strings.Contains(output, memberState.NodeID) {
		t.Fatal("signed legacy join request not inspected")
	}
	run("nebula", owner, unused, true, "fabric", "accept", request, "--out", grant)
	legacyJoin := run("nucleus", "relative", member, true, "join", "--accept", grant)
	if !strings.Contains(legacyJoin, "Start nucleus run") || strings.Contains(legacyJoin, `\n`) {
		t.Fatalf("legacy join message changed: %q", legacyJoin)
	}
	ownerState, err = fabric.Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	memberState, err = fabric.Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if ownerState.FabricID == "" || ownerState.FabricID != memberState.FabricID || memberState.OwnerID != ownerState.NodeID {
		t.Fatal("cross-product grant did not establish a real shared fabric")
	}
	for _, path := range []string{invite, request, grant} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("pairing capability file is not private")
		}
	}
	// With a paired fabric and no hosted binding, the forced relay path must
	// fail enrollment validation before opening a listener or a local UI.
	refused := run("nebula", owner, unused, false, "network", "connect", "--no-open")
	if !strings.Contains(refused, "nebula machine enroll") || strings.Contains(refused, "nucleus cloud connect") {
		t.Fatalf("relay enrollment was not required: %s", refused)
	}
	run("nebula", owner, unused, false, "network", "connect", "--nebula=false")
	if output := run("nebula", owner, unused, false, "relay", "serve", "--listen", "0.0.0.0:8743"); !strings.Contains(output, "requires explicit 127.0.0.1:PORT") {
		t.Fatal("public relay listener was accepted")
	}
	run("nebula", owner, unused, true, "fabric", "revoke", memberState.NodeID)
	ownerState, err = fabric.Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := ownerState.Members[memberState.NodeID]; exists {
		t.Fatal("revocation did not remove membership")
	}
	// Default NEBULA_HOME fallback preserves the same enrolled Nucleus identity.
	fallback := run("nebula", "", owner, true, "machine", "identity")
	if !strings.Contains(fallback, ownerState.NodeID) {
		t.Fatal("legacy identity fallback changed")
	}
	if _, err = os.Stat(unused); !os.IsNotExist(err) {
		t.Fatal("explicit home unexpectedly modified fallback state")
	}
}
