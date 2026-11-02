package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newNode(t *testing.T, name string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), name)
	if _, err := Init(home, name); err != nil {
		t.Fatal(err)
	}
	return home
}
func pairNodes(t *testing.T) (string, string, []byte) {
	t.Helper()
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
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
	return owner, member, grant
}
func mustDisk(t *testing.T, home string) *diskState {
	t.Helper()
	state, err := loadDisk(home)
	if err != nil {
		t.Fatal(err)
	}
	return state
}
func encodeTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestInitPersistentPrivateIdentity(t *testing.T) {
	home := newNode(t, "node")
	first, err := Load(home)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Init(home, "different name")
	if err != nil {
		t.Fatal(err)
	}
	if first.NodeID != second.NodeID || second.Name != "node" || !validID(first.NodeID) {
		t.Fatal("init replaced persistent identity")
	}
	if first.FabricID != "" || len(first.Certificate) != 0 || len(first.Members) != 0 {
		t.Fatal("init silently joined a fabric")
	}
	for _, path := range []string{home, filepath.Join(home, "state.json"), filepath.Join(home, "state.lock")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if path == home {
			want = 0700
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want=%o", path, info.Mode().Perm(), want)
		}
	}
	publicJSON := encodeTest(t, first)
	if bytes.Contains(publicJSON, []byte("private")) || bytes.Contains(publicJSON, []byte("identity_key")) {
		t.Fatal("public State exposes key material")
	}
}

func TestEndpointRestrictions(t *testing.T) {
	for _, value := range []string{"https://127.0.0.1:9443", "https://10.0.0.1:443", "https://172.16.1.2:8080", "https://192.168.50.3:65535/"} {
		if err := ValidateEndpoint(value); err != nil {
			t.Errorf("rejected private endpoint %s: %v", value, err)
		}
	}
	for _, value := range []string{
		"http://192.168.1.1:443", "https://8.8.8.8:443", "https://0.0.0.0:443",
		"https://example.test:443", "https://[::1]:443", "https://192.168.1.1",
		"https://192.168.1.1:0", "https://192.168.1.1:65536", "https://192.168.1.1:abc",
		"https://user@192.168.1.1:443", "https://192.168.1.1:443?x=y",
		"https://192.168.1.1:443/path", "https://192.168.1.1:443#secret",
		"https://172.32.0.1:443", "https://169.254.1.2:443", "https://100.64.0.1:443",
	} {
		if err := ValidateEndpoint(value); err == nil {
			t.Errorf("accepted unsafe endpoint %s", value)
		}
	}
}

func TestExplicitBilateralPairingAndRetry(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://192.168.1.2:9443", 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseInvitation(invite)
	if err != nil {
		t.Fatal(err)
	}
	ownerState := mustDisk(t, owner)
	ca, _ := parseCA(ownerState.Public.CACertificate)
	caID, _ := publicID(ca.PublicKey)
	if caID == ownerState.Public.NodeID {
		t.Fatal("owner identity key is reused as CA key")
	}
	ownerBytes, err := os.ReadFile(filepath.Join(owner, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	encodedSecret := []byte(base64.StdEncoding.EncodeToString(parsed.Secret))
	if bytes.Contains(ownerBytes, encodedSecret) {
		t.Fatal("owner persisted the invitation secret")
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(request, again) {
		t.Fatal("join retry generated a different request")
	}
	before, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if before.FabricID != "" {
		t.Fatal("Join granted membership before owner acceptance")
	}
	memberBytes, err := os.ReadFile(filepath.Join(member, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(memberBytes, encodedSecret) {
		t.Fatal("joining node persisted the invitation secret")
	}
	grant, err := Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(grant, retry) {
		t.Fatal("accept retry did not return the exact persisted grant")
	}
	if err := FinishJoin(member, grant); err != nil {
		t.Fatal(err)
	}
	if err := FinishJoin(member, grant); err != nil {
		t.Fatalf("finish retry: %v", err)
	}
	joined, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	ownerPublic, err := Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	if joined.FabricID != ownerPublic.FabricID || joined.OwnerID != ownerPublic.NodeID ||
		joined.Endpoint != ownerPublic.Endpoint || len(joined.Members) != 2 {
		t.Fatal("shared fabric metadata did not converge")
	}
	if _, err := Invite(member, joined.Endpoint, time.Minute); err == nil {
		t.Fatal("member issued an owner invitation")
	}
}

func TestReplayExpiryAndInvalidCSR(t *testing.T) {
	owner := newNode(t, "owner")
	first := newNode(t, "first")
	second := newNode(t, "second")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Join(first, invite)
	if err != nil {
		t.Fatal(err)
	}
	other, err := Join(second, invite)
	if err != nil {
		t.Fatal(err)
	}
	var tampered joinRequest
	if err := decode(request, &tampered); err != nil {
		t.Fatal(err)
	}
	tampered.CSR[len(tampered.CSR)-1] ^= 1
	if _, err := Accept(owner, encodeTest(t, tampered)); err == nil {
		t.Fatal("invalid CSR signature accepted")
	}
	if _, err := Accept(owner, request); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(owner, other); err == nil {
		t.Fatal("one-use invitation authorized a second node")
	}
	expired, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var document invitation
	if err := decode(expired, &document); err != nil {
		t.Fatal(err)
	}
	third := newNode(t, "third")
	thirdRequest, err := Join(third, expired)
	if err != nil {
		t.Fatal(err)
	}
	state := mustDisk(t, owner)
	record := state.Invitations[document.InvitationID]
	record.ExpiresAt = time.Now().Add(-time.Minute)
	state.Invitations[document.InvitationID] = record
	if err := saveDisk(owner, state); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(owner, thirdRequest); err == nil {
		t.Fatal("expired invitation accepted")
	}
}

func TestCSRRequestedPrivilegesAreDiscarded(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	var document joinRequest
	if err := decode(request, &document); err != nil {
		t.Fatal(err)
	}
	state := mustDisk(t, member)
	key, err := parseKey(state.IdentityKey)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := bindingHash(document)
	if err != nil {
		t.Fatal(err)
	}
	constraints, err := asn1.Marshal(struct{ IsCA bool }{true})
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker-requested-ca"},
		DNSNames: []string{"attacker.example"}, SignatureAlgorithm: x509.PureEd25519,
		ExtraExtensions: []pkix.Extension{
			{Id: requestBindingOID, Value: binding},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: constraints},
		},
	}
	document.CSR, err = x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	result, err := Accept(owner, encodeTest(t, document))
	if err != nil {
		t.Fatal(err)
	}
	var issued grant
	if err := decode(result, &issued); err != nil {
		t.Fatal(err)
	}
	ca, err := parseCA(issued.CACertificate)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := verifyLeaf(issued.Certificate, ca, state.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != state.Public.NodeID+".nodes.nucleus" {
		t.Fatal("CSR escalated leaf privileges")
	}
}

func TestGrantTamperingAndWrongKeyAreRejected(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	var original grant
	if err := decode(accepted, &original); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*grant){
		func(g *grant) { g.Endpoint = "https://127.0.0.1:9555" },
		func(g *grant) { g.RequestHash = strings.Repeat("a", 64) },
		func(g *grant) {
			g.Members[strings.Repeat("b", 64)] = Member{NodeID: strings.Repeat("b", 64), Name: "injected"}
		},
		func(g *grant) { g.Certificate = g.OwnerCertificate },
		func(g *grant) { g.Signature[0] ^= 1 },
	} {
		var document grant
		if err := decode(accepted, &document); err != nil {
			t.Fatal(err)
		}
		mutate(&document)
		if err := FinishJoin(member, encodeTest(t, document)); err == nil {
			t.Fatal("tampered grant was accepted")
		}
		state, err := Load(member)
		if err != nil {
			t.Fatal(err)
		}
		if state.FabricID != "" {
			t.Fatal("failed grant changed membership")
		}
	}
	if err := FinishJoin(member, accepted); err != nil {
		t.Fatal(err)
	}
	other := newNode(t, "other")
	if err := FinishJoin(other, accepted); err == nil {
		t.Fatal("grant was installed on a different node key")
	}
}

func TestConcurrentAcceptConsumesInvitationOnce(t *testing.T) {
	owner := newNode(t, "owner")
	a := newNode(t, "a")
	b := newNode(t, "b")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ar, err := Join(a, invite)
	if err != nil {
		t.Fatal(err)
	}
	br, err := Join(b, invite)
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	for _, request := range [][]byte{ar, br} {
		wait.Add(1)
		go func(data []byte) { defer wait.Done(); _, err := Accept(owner, data); results <- err }(request)
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("one invitation accepted %d concurrent requests", successes)
	}
	state, err := Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Members) != 2 {
		t.Fatal("concurrent state updates lost or duplicated membership")
	}
}

func TestTLSMutualAuthenticationRevocationAndWrongFabric(t *testing.T) {
	owner, member, accepted := pairNodes(t)
	serverConfig, err := ServerTLS(owner)
	if err != nil {
		t.Fatal(err)
	}
	if serverConfig.MinVersion != tls.VersionTLS13 || serverConfig.MaxVersion != tls.VersionTLS13 ||
		serverConfig.ClientAuth != tls.RequireAndVerifyClientCert || !serverConfig.SessionTicketsDisabled {
		t.Fatal("server weakened TLS requirements")
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("authenticated")) })
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Config.SetKeepAlivesEnabled(false)
	server.TLS = serverConfig
	server.StartTLS()
	defer server.Close()
	clientConfig, err := ClientTLS(member)
	if err != nil {
		t.Fatal(err)
	}
	if clientConfig.InsecureSkipVerify || clientConfig.ClientSessionCache != nil || !clientConfig.SessionTicketsDisabled {
		t.Fatal("client weakened certificate verification")
	}
	transport := &http.Transport{TLSClientConfig: clientConfig, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "authenticated" {
		t.Fatal("authenticated exchange failed")
	}
	// A trusted server never accepts a client that supplies no certificate.
	noCert := clientConfig.Clone()
	noCert.Certificates = nil
	anonymous := &http.Client{Transport: &http.Transport{TLSClientConfig: noCert, DisableKeepAlives: true}, Timeout: time.Second}
	if response, err := anonymous.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("anonymous client accepted")
	}
	// Even a correctly CA-signed but unlisted node must be denied.
	disk := mustDisk(t, owner)
	ca, _ := parseCA(disk.Public.CACertificate)
	caKey, _ := parseKey(disk.CAKey)
	rogueKey, _ := generateKey()
	rogueID, _ := publicID(rogueKey.Public())
	rogueLeaf, err := issueLeaf(ca, caKey, rogueKey.Public().(ed25519.PublicKey), rogueID)
	if err != nil {
		t.Fatal(err)
	}
	rogue := clientConfig.Clone()
	rogue.Certificates = []tls.Certificate{{Certificate: [][]byte{rogueLeaf}, PrivateKey: rogueKey}}
	rogueClient := &http.Client{Transport: &http.Transport{TLSClientConfig: rogue, DisableKeepAlives: true}, Timeout: time.Second}
	if response, err := rogueClient.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("unlisted node accepted")
	}
	// A certificate from an unrelated fabric is not a member certificate.
	other := newNode(t, "other-fabric")
	if _, err := Invite(other, "https://127.0.0.1:9443", time.Minute); err != nil {
		t.Fatal(err)
	}
	otherConfig, err := ClientTLS(other)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := clientConfig.Clone()
	unrelated.Certificates = otherConfig.Certificates
	unrelatedClient := &http.Client{Transport: &http.Transport{TLSClientConfig: unrelated, DisableKeepAlives: true}, Timeout: time.Second}
	if response, err := unrelatedClient.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("unrelated fabric certificate accepted")
	}
	memberState, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(owner, memberState.NodeID); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get(server.URL); err == nil {
		response.Body.Close()
		t.Fatal("revoked member reconnected through cached TLS config")
	}
	// Returning an old accepted request may not resurrect revoked membership.
	var grantDoc grant
	if err := decode(accepted, &grantDoc); err != nil {
		t.Fatal(err)
	}
	disk = mustDisk(t, owner)
	record := disk.Invitations[grantDoc.InvitationID]
	if len(record.Grant) == 0 {
		t.Fatal("accepted retry receipt missing")
	}
	ownerState, err := Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(owner, ownerState.NodeID); err == nil {
		t.Fatal("owner revoked itself")
	}
}

func TestPrivateStateRejectsSymlinksAndLoosePermissions(t *testing.T) {
	home := newNode(t, "safe")
	target := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(home, target); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(target); err == nil {
		t.Fatal("symlinked home accepted")
	}
	statePath := filepath.Join(home, "state.json")
	if err := os.Chmod(statePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home); err == nil {
		t.Fatal("world-readable identity state accepted")
	}
	if err := os.Chmod(statePath, 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(saved, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(saved, statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home); err == nil {
		t.Fatal("symlinked state accepted")
	}
	if _, err := Init(home, "safe"); err == nil {
		t.Fatal("init followed an existing state symlink")
	}
}

// Inspection reveals only the signed human-review metadata; changing the name
// or invitation context invalidates proof of possession.
func TestInspectRequestBindsHumanReviewToSignedKey(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	local, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if inspected.NodeID != local.NodeID || inspected.Name != local.Name {
		t.Fatal("inspection did not derive the signing key's node identity")
	}
	encoded := encodeTest(t, inspected)
	if bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("csr")) {
		t.Fatal("inspection exposed bearer material")
	}
	var changed joinRequest
	if err := decode(request, &changed); err != nil {
		t.Fatal(err)
	}
	changed.Name = "different-node"
	if _, err := InspectRequest(encodeTest(t, changed)); err == nil {
		t.Fatal("inspection trusted unsigned outer metadata")
	}
}

func TestLoadRejectsLooseHomeAndOversizedState(t *testing.T) {
	home := newNode(t, "private")
	if err := os.Chmod(home, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home); err == nil {
		t.Fatal("non-private fabric directory accepted")
	}
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "state.json"), bytes.Repeat([]byte("x"), maxDocument+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(home); err == nil {
		t.Fatal("oversized state accepted")
	}
}

func TestGrantCannotBypassPendingKeyBindingEvenWithOwnerSignature(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	other := newNode(t, "other")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	var document grant
	if err := decode(accepted, &document); err != nil {
		t.Fatal(err)
	}
	disk := mustDisk(t, owner)
	ca, _ := parseCA(disk.Public.CACertificate)
	caKey, _ := parseKey(disk.CAKey)
	otherDisk := mustDisk(t, other)
	otherKey, _ := parseKey(otherDisk.IdentityKey)
	document.Certificate, err = issueLeaf(ca, caKey, otherKey.Public().(ed25519.PublicKey), otherDisk.Public.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	document.Signature = nil
	unsigned := encodeTest(t, document)
	identity, _ := parseKey(disk.IdentityKey)
	document.Signature = ed25519.Sign(identity, unsigned)
	if err := FinishJoin(member, encodeTest(t, document)); err == nil {
		t.Fatal("valid owner signature installed a different node's certificate")
	}
}

func TestExpiredPendingJoinCanBeReplacedWithoutChangingIdentity(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	initial, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	firstInvite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	firstRequest, err := Join(member, firstInvite)
	if err != nil {
		t.Fatal(err)
	}
	secondInvite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Join(member, secondInvite); err == nil {
		t.Fatal("a live pending invitation was silently replaced")
	}
	disk := mustDisk(t, member)
	oldRequestHash := disk.Pending.RequestHash
	disk.Pending.ExpiresAt = time.Now().Add(-time.Minute)
	identityKey := append([]byte(nil), disk.IdentityKey...)
	if err := saveDisk(member, disk); err != nil {
		t.Fatal(err)
	}
	secondRequest, err := Join(member, secondInvite)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstRequest, secondRequest) {
		t.Fatal("replacement did not bind a new invitation")
	}
	replaced := mustDisk(t, member)
	if replaced.Pending.RequestHash == oldRequestHash || replaced.Public.NodeID != initial.NodeID ||
		!bytes.Equal(replaced.IdentityKey, identityKey) || replaced.Public.FabricID != "" {
		t.Fatal("pending recovery changed identity or prematurely joined a fabric")
	}
	// The consumed enrollment is the new pending request; it can finish normally.
	accepted, err := Accept(owner, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := FinishJoin(member, accepted); err != nil {
		t.Fatal(err)
	}
	joined, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if joined.NodeID != initial.NodeID || joined.FabricID == "" {
		t.Fatal("recovered join did not preserve identity")
	}
}

func TestRevokedNodeCannotReplayOriginalAcceptedRequest(t *testing.T) {
	owner := newNode(t, "owner")
	member := newNode(t, "member")
	invite, err := Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	originalRequest, err := Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := Accept(owner, originalRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := FinishJoin(member, accepted); err != nil {
		t.Fatal(err)
	}
	node, err := Load(member)
	if err != nil {
		t.Fatal(err)
	}
	if err := Revoke(owner, node.NodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := Accept(owner, originalRequest); err == nil {
		t.Fatal("replaying the original request restored a revoked grant")
	}
	state, err := Load(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := state.Members[node.NodeID]; ok {
		t.Fatal("revoked member reappeared in owner membership")
	}
}
