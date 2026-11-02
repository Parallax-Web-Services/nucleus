package nebula

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/coder/websocket"
)

type relayTestFixture struct {
	relay         *Relay
	url           string
	issuer        ed25519.PrivateKey
	owner, member string
	now           func() time.Time
}

func relayTestPair(t *testing.T) (string, string) {
	t.Helper()
	owner, member := filepath.Join(t.TempDir(), "owner"), filepath.Join(t.TempDir(), "member")
	for home, name := range map[string]string{owner: "owner", member: "member"} {
		if _, err := fabric.Init(home, name); err != nil {
			t.Fatal(err)
		}
	}
	invite, err := fabric.Invite(owner, "https://127.0.0.1:9443", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	request, err := fabric.Join(member, invite)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := fabric.Accept(owner, request)
	if err != nil {
		t.Fatal(err)
	}
	if err = fabric.FinishJoin(member, grant); err != nil {
		t.Fatal(err)
	}
	return owner, member
}

func newRelayTestFixture(t *testing.T, config RelayConfig) *relayTestFixture {
	t.Helper()
	owner, member := relayTestPair(t)
	issuer := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{42}, 32))
	config.IssuerPublicKey = issuer.Public().(ed25519.PublicKey)
	if config.Now == nil {
		config.Now = time.Now
	}
	relay, err := NewRelay(config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(relay)
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = relay.Close() })
	return &relayTestFixture{relay: relay, url: "ws" + strings.TrimPrefix(server.URL, "http") + Path, issuer: issuer, owner: owner, member: member, now: config.Now}
}

func (f *relayTestFixture) ticket(home, team string, request CapabilityRequest) (Authorization, error) {
	state, public, err := fabric.CloudIdentity(home)
	if err != nil {
		return Authorization{}, err
	}
	jti, err := randomID(16)
	if err != nil {
		return Authorization{}, err
	}
	now := f.now().Unix()
	capability := Capability{V: 1, Issuer: "https://positronic.app", Audience: "nebula-relay", TeamID: team,
		NodeID: state.NodeID, PublicKey: base64.RawURLEncoding.EncodeToString(public), FabricID: request.FabricID,
		Service: request.Service, Mode: request.Mode, PeerID: request.PeerID, ConnectionID: request.ConnectionID,
		StreamID: request.StreamID, IssuedAt: now, ExpiresAt: now + 30, JTI: jti}
	raw, err := json.Marshal(capability)
	if err != nil {
		return Authorization{}, err
	}
	signature := ed25519.Sign(f.issuer, append([]byte("nebula-capability-v1\n"), raw...))
	return Authorization{SchemaVersion: 1, Capability: base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(signature), ExpiresAt: now + 30, RelayURL: f.url}, nil
}

func (f *relayTestFixture) source(home, team string, revoked *atomic.Bool, fabricOverride string) CapabilitySource {
	return func(ctx context.Context, request CapabilityRequest) (Authorization, error) {
		if err := ctx.Err(); err != nil {
			return Authorization{}, err
		}
		if revoked != nil && revoked.Load() {
			return Authorization{}, errors.New("synthetic node revocation")
		}
		if fabricOverride != "" {
			request.FabricID = fabricOverride
		}
		return f.ticket(home, team, request)
	}
}

func (f *relayTestFixture) client(t *testing.T, ctx context.Context, home, team string, revoked *atomic.Bool, override string) *Client {
	t.Helper()
	client, err := NewClient(ctx, ClientConfig{Home: home, RelayURL: f.url, Authorize: f.source(home, team, revoked, override), RenewInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func relayTestState(t *testing.T, home string) *fabric.State {
	t.Helper()
	state, err := fabric.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func relayTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx, cancel
}

func (f *relayTestFixture) native(t *testing.T, ctx context.Context, home string, authorization Authorization) *websocket.Conn {
	t.Helper()
	ws, response, err := websocket.Dial(ctx, f.url, &websocket.DialOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ws.CloseNow() })
	proof, err := fabric.SignNebula(home, NodeProofMessage(authorization.Capability))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeWire(ctx, ws, wireMessage{Type: "auth", Capability: authorization.Capability, Proof: base64.StdEncoding.EncodeToString(proof)}); err != nil {
		t.Fatal(err)
	}
	return ws
}

func (f *relayTestFixture) request(t *testing.T, home, mode, peer string) CapabilityRequest {
	t.Helper()
	id, err := randomID(32)
	if err != nil {
		t.Fatal(err)
	}
	return CapabilityRequest{FabricID: relayTestState(t, home).FabricID, Service: "nucleus-fabric", Mode: mode, PeerID: peer, ConnectionID: id}
}

func relayTestReady(t *testing.T, ctx context.Context, ws *websocket.Conn) {
	t.Helper()
	message, err := readWire(ctx, ws)
	if err != nil || message.Type != "ready" {
		t.Fatalf("native connection was not accepted: %v", err)
	}
}

func relayTestClosed(t *testing.T, ws *websocket.Conn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()
	if _, _, err := ws.Read(ctx); err == nil {
		t.Fatal("rejected connection remained readable")
	}
	if ctx.Err() != nil {
		t.Fatal("relay did not close rejected connection before the read deadline")
	}
}

func relayTestWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("relay state did not settle within its bound")
		}
	}
}

func TestRelayCarriesRealFabricMutualTLSAcrossOutboundConnections(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{})
	ctx, _ := relayTestContext(t)
	owner := f.client(t, ctx, f.owner, "201", nil, "")
	member := f.client(t, ctx, f.member, "201", nil, "")
	listener, err := owner.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serverConfig, err := fabric.ServerTLS(f.owner)
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, serverConfig)
	payload := bytes.Repeat([]byte("Nucleus authenticated WAN transport.\n"), 7000)
	done := make(chan error, 1)
	go func() {
		connection, err := tlsListener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer connection.Close()
		_ = connection.SetDeadline(time.Now().Add(2 * time.Second))
		secure := connection.(*tls.Conn)
		if err = secure.HandshakeContext(ctx); err != nil {
			done <- err
			return
		}
		if secure.ConnectionState().Version != tls.VersionTLS13 {
			done <- errors.New("wrong inner TLS version")
			return
		}
		body := make([]byte, len(payload))
		if _, err = io.ReadFull(connection, body); err != nil {
			done <- err
			return
		}
		if !bytes.Equal(body, payload) {
			done <- errors.New("opaque stream bytes changed")
			return
		}
		_, err = connection.Write(body)
		done <- err
	}()
	raw, err := member.DialPeer(ctx, relayTestState(t, f.owner).NodeID)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := fabric.ClientTLS(f.member)
	if err != nil {
		t.Fatal(err)
	}
	secure := tls.Client(raw, clientConfig)
	defer secure.Close()
	_ = secure.SetDeadline(time.Now().Add(2 * time.Second))
	if err = secure.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if secure.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("inner TLS 1.3 was not negotiated")
	}
	if _, err = secure.Write(payload); err != nil {
		t.Fatal(err)
	}
	result := make([]byte, len(payload))
	if _, err = io.ReadFull(secure, result); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result, payload) {
		t.Fatal("encrypted relay round trip changed data")
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRelayRejectsCrossOrganizationCrossFabricAndAbsentListeners(t *testing.T) {
	for _, test := range []struct {
		name, team, override string
		listen               bool
	}{
		{"cross organization", "202", "", true},
		{"cross fabric", "201", strings.Repeat("f", 64), true},
		{"no listener", "201", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newRelayTestFixture(t, RelayConfig{})
			ctx, _ := relayTestContext(t)
			if test.listen {
				owner := f.client(t, ctx, f.owner, "201", nil, "")
				listener, err := owner.Listen(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
			}
			member := f.client(t, ctx, f.member, test.team, nil, test.override)
			connection, err := member.DialPeer(ctx, relayTestState(t, f.owner).NodeID)
			if connection != nil {
				connection.Close()
			}
			if err == nil {
				t.Fatal("unauthorized peer connection was accepted")
			}
			if ctx.Err() != nil {
				t.Fatal("peer isolation relied on caller timeout")
			}
		})
	}
}

func TestRelayRejectsInitialAndRenewalCapabilityReplay(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{})
	ctx, _ := relayTestContext(t)
	request := f.request(t, f.owner, "listen", "")
	authorization, err := f.ticket(f.owner, "201", request)
	if err != nil {
		t.Fatal(err)
	}
	first := f.native(t, ctx, f.owner, authorization)
	relayTestReady(t, ctx, first)
	_ = first.CloseNow()
	relayTestWait(t, func() bool { f.relay.mu.Lock(); defer f.relay.mu.Unlock(); return len(f.relay.connections) == 0 })
	replayed := f.native(t, ctx, f.owner, authorization)
	relayTestClosed(t, replayed)

	request = f.request(t, f.owner, "listen", "")
	authorization, err = f.ticket(f.owner, "201", request)
	if err != nil {
		t.Fatal(err)
	}
	control := f.native(t, ctx, f.owner, authorization)
	relayTestReady(t, ctx, control)
	renewed, err := f.ticket(f.owner, "201", request)
	if err != nil {
		t.Fatal(err)
	}
	capability, err := VerifyCapability(renewed.Capability, f.issuer.Public().(ed25519.PublicKey), f.now())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := fabric.SignNebula(f.owner, NodeProofMessage(renewed.Capability))
	if err != nil {
		t.Fatal(err)
	}
	message := wireMessage{Type: "renew", Capability: renewed.Capability, Proof: base64.StdEncoding.EncodeToString(proof)}
	if err = writeWire(ctx, control, message); err != nil {
		t.Fatal(err)
	}
	relayTestWait(t, func() bool {
		f.relay.mu.Lock()
		defer f.relay.mu.Unlock()
		_, ok := f.relay.used[capability.JTI]
		return ok
	})
	acknowledgement, err := readWire(ctx, control)
	if err != nil || acknowledgement != (wireMessage{Type: "renewed"}) {
		t.Fatalf("valid renewal was not acknowledged: %v", err)
	}
	if err = writeWire(ctx, control, message); err != nil {
		t.Fatal(err)
	}
	relayTestClosed(t, control)
}

func TestRelayRevokedRenewalClosesThePairedDataStream(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{})
	ctx, _ := relayTestContext(t)
	var revoked atomic.Bool
	owner := f.client(t, ctx, f.owner, "201", nil, "")
	member := f.client(t, ctx, f.member, "201", &revoked, "")
	listener, err := owner.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outbound, err := member.DialPeer(ctx, relayTestState(t, f.owner).NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	inbound, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	revoked.Store(true)
	_ = inbound.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = inbound.Read(make([]byte, 1)); err == nil {
		t.Fatal("revoked stream remained readable")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("revocation did not close peer stream")
	}
	relayTestWait(t, func() bool { member.mu.Lock(); defer member.mu.Unlock(); return len(member.sockets) == 0 })
}

func TestRelayExpiresUnrenewedConnectionsWithoutAClockGracePeriod(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().Unix())
	f := newRelayTestFixture(t, RelayConfig{Now: func() time.Time { return time.Unix(clock.Load(), 0) }})
	ctx, _ := relayTestContext(t)
	authorization, err := f.ticket(f.owner, "201", f.request(t, f.owner, "listen", ""))
	if err != nil {
		t.Fatal(err)
	}
	control := f.native(t, ctx, f.owner, authorization)
	relayTestReady(t, ctx, control)
	clock.Add(31)
	relayTestClosed(t, control)
}

func TestRelayEnforcesGlobalAndPerNodeConnectionLimits(t *testing.T) {
	t.Run("global", func(t *testing.T) {
		f := newRelayTestFixture(t, RelayConfig{MaxConnections: 1})
		ctx, _ := relayTestContext(t)
		authorization, err := f.ticket(f.owner, "201", f.request(t, f.owner, "listen", ""))
		if err != nil {
			t.Fatal(err)
		}
		control := f.native(t, ctx, f.owner, authorization)
		relayTestReady(t, ctx, control)
		ws, response, err := websocket.Dial(ctx, f.url, &websocket.DialOptions{Subprotocols: []string{Subprotocol}})
		if ws != nil {
			ws.CloseNow()
		}
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		if err == nil || response == nil || response.StatusCode != 503 {
			t.Fatal("global connection bound was not enforced before upgrade")
		}
	})
	t.Run("per node", func(t *testing.T) {
		f := newRelayTestFixture(t, RelayConfig{MaxConnections: 4, MaxPerNode: 1})
		ctx, _ := relayTestContext(t)
		for _, home := range []string{f.owner, f.member} {
			authorization, err := f.ticket(home, "201", f.request(t, home, "listen", ""))
			if err != nil {
				t.Fatal(err)
			}
			relayTestReady(t, ctx, f.native(t, ctx, home, authorization))
		}
		authorization, err := f.ticket(f.owner, "201", f.request(t, f.owner, "dial", relayTestState(t, f.member).NodeID))
		if err != nil {
			t.Fatal(err)
		}
		relayTestClosed(t, f.native(t, ctx, f.owner, authorization))
	})
}

func TestRelayClientCancellationClosesStreamsAndBlockedAccept(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{})
	ctx, _ := relayTestContext(t)
	ownerContext, cancelOwner := context.WithCancel(ctx)
	owner := f.client(t, ownerContext, f.owner, "201", nil, "")
	member := f.client(t, ctx, f.member, "201", nil, "")
	listener, err := owner.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	outbound, err := member.DialPeer(ctx, relayTestState(t, f.owner).NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer outbound.Close()
	inbound, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	acceptDone := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if connection != nil {
			connection.Close()
		}
		acceptDone <- err
	}()
	cancelOwner()
	select {
	case err = <-acceptDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked accept did not close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client cancellation left Accept blocked")
	}
	_ = outbound.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = outbound.Read(make([]byte, 1)); err == nil {
		t.Fatal("client cancellation left peer stream readable")
	} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("client cancellation did not close peer stream")
	}
}

func TestRelayDoesNotReplaceFabricTLSIdentityVerification(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{})
	ctx, _ := relayTestContext(t)
	owner := f.client(t, ctx, f.owner, "201", nil, "")
	member := f.client(t, ctx, f.member, "201", nil, "")
	listener, err := owner.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverConfig, err := fabric.ServerTLS(f.owner)
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		connection, err := tls.NewListener(listener, serverConfig).Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		serverDone <- connection.(*tls.Conn).HandshakeContext(ctx)
	}()
	raw, err := member.DialPeer(ctx, relayTestState(t, f.owner).NodeID)
	if err != nil {
		t.Fatal(err)
	}
	_, differentMember := relayTestPair(t)
	wrongTrust, err := fabric.ClientTLS(differentMember)
	if err != nil {
		t.Fatal(err)
	}
	connection := tls.Client(raw, wrongTrust)
	defer connection.Close()
	if err = connection.HandshakeContext(ctx); err == nil {
		t.Fatal("another fabric passed inner TLS authentication")
	}
	select {
	case err = <-serverDone:
		if err == nil {
			t.Fatal("server accepted another fabric certificate")
		}
	case <-time.After(time.Second):
		t.Fatal("failed TLS handshake did not close promptly")
	}
}

func TestRelayPerNodeLimitCannotBeBypassedByDifferentFabric(t *testing.T) {
	f := newRelayTestFixture(t, RelayConfig{MaxConnections: 4, MaxPerNode: 1})
	ctx, _ := relayTestContext(t)
	initial, err := f.ticket(f.owner, "201", f.request(t, f.owner, "listen", ""))
	if err != nil {
		t.Fatal(err)
	}
	control := f.native(t, ctx, f.owner, initial)
	relayTestReady(t, ctx, control)
	request := f.request(t, f.owner, "listen", "")
	request.FabricID = strings.Repeat("f", 64)
	alternate, err := f.ticket(f.owner, "201", request)
	if err != nil {
		t.Fatal(err)
	}

	relayTestClosed(t, f.native(t, ctx, f.owner, alternate))
}
