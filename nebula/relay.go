package nebula

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type RelayConfig struct {
	IssuerPublicKey ed25519.PublicKey
	MaxConnections  int
	MaxPerNode      int
	MaxStreams      int
	Now             func() time.Time
}

// Relay forwards only opaque binary frames between explicitly authorized peers.
// It has no node identity keys, application credentials, or arbitrary TCP dialer.
type Relay struct {
	config          RelayConfig
	mu              sync.Mutex
	open            int
	closed          bool
	nodes           map[string]int
	connections     map[string]*relaySession
	listeners       map[string]*relaySession
	streams         map[string]*relayStream
	used            map[string]int64
	seenConnections map[string]int64
}

type relaySession struct {
	relay    *Relay
	ws       *websocket.Conn
	cap      Capability
	ctx      context.Context
	cancel   context.CancelFunc
	expiry   atomic.Int64
	activity atomic.Int64
	once     sync.Once
}
type relayStream struct {
	id       string
	dial     *relaySession
	accept   *relaySession
	listener *relaySession
	paired   chan struct{}
	started  chan struct{}
	ready    int
}

func NewRelay(config RelayConfig) (*Relay, error) {
	if len(config.IssuerPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("NEBULA issuer public key required")
	}
	if config.MaxConnections == 0 {
		config.MaxConnections = 256
	}
	if config.MaxPerNode == 0 {
		config.MaxPerNode = 8
	}
	if config.MaxStreams == 0 {
		config.MaxStreams = 64
	}
	if config.MaxConnections < 1 || config.MaxConnections > 4096 || config.MaxPerNode < 1 || config.MaxPerNode > 8 || config.MaxStreams < 1 || config.MaxStreams > 256 {
		return nil, errors.New("invalid NEBULA relay limits")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.IssuerPublicKey = append(ed25519.PublicKey(nil), config.IssuerPublicKey...)
	return &Relay{config: config, nodes: map[string]int{}, connections: map[string]*relaySession{}, listeners: map[string]*relaySession{}, streams: map[string]*relayStream{}, used: map[string]int64{}, seenConnections: map[string]int64{}}, nil
}
func nodeScope(c Capability) string       { return c.TeamID + "|" + c.FabricID + "|" + c.NodeID }
func connectionScope(c Capability) string { return nodeScope(c) + "|" + c.ConnectionID }
func (r *Relay) Close() error {
	r.mu.Lock()
	r.closed = true
	sessions := make([]*relaySession, 0, len(r.connections))
	for _, s := range r.connections {
		sessions = append(sessions, s)
	}
	r.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
	return nil
}
func (s *relaySession) close() { s.once.Do(func() { s.cancel(); _ = s.ws.CloseNow() }) }
func (r *Relay) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.URL.Path == "/healthz" && request.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"service\":\"nucleus-nebula\",\"status\":\"ok\"}"))
		return
	}
	if request.URL.Path != Path {
		http.NotFound(w, request)
		return
	}
	if request.Method != http.MethodGet || request.URL.RawQuery != "" || request.Header.Get("Origin") != "" {
		http.Error(w, "NEBULA native upgrade required", http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	if r.closed || r.open >= r.config.MaxConnections {
		r.mu.Unlock()
		http.Error(w, "NEBULA capacity unavailable", http.StatusServiceUnavailable)
		return
	}
	r.open++
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.open--; r.mu.Unlock() }()
	ws, err := websocket.Accept(w, request, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return
	}
	defer ws.CloseNow()
	ws.SetReadLimit(MaxFrame)
	if ws.Subprotocol() != Subprotocol {
		return
	}
	authctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	message, err := readWire(authctx, ws)
	cancel()
	if err != nil || message.Type != "auth" || message.StreamID != "" || message.PeerID != "" {
		return
	}
	capability, err := VerifyCapability(message.Capability, r.config.IssuerPublicKey, r.config.Now())
	if err != nil || VerifyNodeProof(message.Capability, message.Proof, capability) != nil {
		return
	}
	ctx, cancel := context.WithCancel(request.Context())
	defer cancel()
	session := &relaySession{relay: r, ws: ws, cap: capability, ctx: ctx, cancel: cancel}
	session.expiry.Store(capability.ExpiresAt)
	session.activity.Store(r.config.Now().Unix())
	r.mu.Lock()
	key := connectionScope(capability)
	if r.closed || r.nodes[capability.NodeID] >= r.config.MaxPerNode || r.connections[key] != nil || r.seenConnections[key] > r.config.Now().Unix() || !r.consumeLocked(capability) {
		r.mu.Unlock()
		return
	}
	r.seenConnections[key] = capability.ExpiresAt
	r.connections[key] = session
	r.nodes[capability.NodeID]++
	r.mu.Unlock()
	defer func() {
		session.close()
		r.mu.Lock()
		delete(r.connections, key)
		r.nodes[capability.NodeID]--
		if r.nodes[capability.NodeID] == 0 {
			delete(r.nodes, capability.NodeID)
		}
		r.mu.Unlock()
	}()
	go session.expire()
	switch capability.Mode {
	case "listen":
		r.listen(session)
	case "dial":
		r.dial(session)
	case "accept":
		r.accept(session)
	}
}
func (r *Relay) consumeLocked(c Capability) bool {
	now := r.config.Now().Unix()
	for id, expiry := range r.seenConnections {
		if expiry <= now {
			delete(r.seenConnections, id)
		}
	}
	for id, expiry := range r.used {
		if expiry <= now {
			delete(r.used, id)
		}
	}
	if _, ok := r.used[c.JTI]; ok || len(r.used) >= 8192 {
		return false
	}
	r.used[c.JTI] = c.ExpiresAt
	return true
}
func (s *relaySession) expire() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if s.relay.config.Now().Unix() >= s.expiry.Load() || (s.cap.Mode != "listen" && s.relay.config.Now().Unix()-s.activity.Load() >= 60) {
				s.close()
				return
			}
		}
	}
}
func (s *relaySession) renew(message wireMessage) error {
	if message.Type != "renew" || message.StreamID != "" || message.PeerID != "" {
		return errors.New("invalid NEBULA renewal")
	}
	c, err := VerifyCapability(message.Capability, s.relay.config.IssuerPublicKey, s.relay.config.Now())
	if err != nil || !s.cap.SameBinding(c) || VerifyNodeProof(message.Capability, message.Proof, c) != nil {
		return errors.New("NEBULA renewal rejected")
	}
	s.relay.mu.Lock()
	defer s.relay.mu.Unlock()
	if s.relay.config.Now().Unix() >= s.expiry.Load() || !s.relay.consumeLocked(c) {
		return errors.New("NEBULA renewal expired or replayed")
	}
	s.expiry.Store(c.ExpiresAt)
	s.relay.seenConnections[connectionScope(c)] = c.ExpiresAt
	return nil
}
func (r *Relay) listen(s *relaySession) {
	key := nodeScope(s.cap)
	r.mu.Lock()
	if r.listeners[key] != nil {
		r.mu.Unlock()
		return
	}
	r.listeners[key] = s
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		if r.listeners[key] == s {
			delete(r.listeners, key)
		}
		var streams []*relayStream
		for _, stream := range r.streams {
			if stream.listener == s {
				streams = append(streams, stream)
			}
		}
		r.mu.Unlock()
		for _, stream := range streams {
			r.dropStream(stream)
		}
	}()
	if writeWire(s.ctx, s.ws, wireMessage{Type: "ready"}) != nil {
		return
	}
	for {
		message, err := readWire(s.ctx, s.ws)
		if err != nil || s.renew(message) != nil {
			return
		}
		if writeWire(s.ctx, s.ws, wireMessage{Type: "renewed"}) != nil {
			return
		}
	}
}
func (r *Relay) dial(s *relaySession) {
	streamID, err := randomID(16)
	if err != nil {
		return
	}
	target := s.cap
	target.NodeID = s.cap.PeerID
	r.mu.Lock()
	listener := r.listeners[nodeScope(target)]
	if listener == nil || len(r.streams) >= r.config.MaxStreams {
		r.mu.Unlock()
		return
	}
	stream := &relayStream{id: streamID, dial: s, listener: listener, paired: make(chan struct{}), started: make(chan struct{})}
	r.streams[streamID] = stream
	r.mu.Unlock()
	defer r.dropStream(stream)
	if writeWire(listener.ctx, listener.ws, wireMessage{Type: "incoming", StreamID: streamID, PeerID: s.cap.NodeID}) != nil {
		return
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-stream.paired:
	case <-s.ctx.Done():
		return
	case <-timer.C:
		return
	}
	r.runStream(s, stream)
}
func (r *Relay) accept(s *relaySession) {
	r.mu.Lock()
	stream := r.streams[s.cap.StreamID]
	if stream == nil || stream.accept != nil || stream.listener.ctx.Err() != nil ||
		stream.listener.cap.TeamID != s.cap.TeamID || stream.listener.cap.FabricID != s.cap.FabricID ||
		stream.listener.cap.NodeID != s.cap.NodeID || stream.dial.cap.NodeID != s.cap.PeerID ||
		stream.dial.cap.PeerID != s.cap.NodeID || r.listeners[nodeScope(s.cap)] != stream.listener {
		r.mu.Unlock()
		return
	}
	stream.accept = s
	close(stream.paired)
	r.mu.Unlock()
	defer r.dropStream(stream)
	r.runStream(s, stream)
}
func (r *Relay) runStream(s *relaySession, stream *relayStream) {
	if writeWire(s.ctx, s.ws, wireMessage{Type: "ready"}) != nil {
		return
	}
	r.mu.Lock()
	stream.ready++
	if stream.ready == 2 {
		close(stream.started)
	}
	r.mu.Unlock()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case <-stream.started:
	case <-s.ctx.Done():
		return
	case <-timer.C:
		return
	}
	peer := stream.dial
	if peer == s {
		peer = stream.accept
	}
	if peer == nil {
		return
	}
	for {
		typ, data, err := s.ws.Read(s.ctx)
		if err != nil {
			return
		}
		if typ == websocket.MessageText {
			message, err := decodeWire(data)
			if err != nil || s.renew(message) != nil {
				return
			}
			keepalive, cancel := context.WithTimeout(s.ctx, 5*time.Second)
			err = s.ws.Write(keepalive, websocket.MessageBinary, nil)
			cancel()
			if err != nil {
				return
			}
			continue
		}
		if typ != websocket.MessageBinary || len(data) > MaxFrame {
			return
		}
		ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
		err = peer.ws.Write(ctx, websocket.MessageBinary, data)
		cancel()
		if err != nil {
			return
		}
		if len(data) > 0 {
			s.activity.Store(r.config.Now().Unix())
			peer.activity.Store(r.config.Now().Unix())
		}
	}
}
func (r *Relay) dropStream(stream *relayStream) {
	r.mu.Lock()
	if r.streams[stream.id] != stream {
		r.mu.Unlock()
		return
	}
	delete(r.streams, stream.id)
	sessions := []*relaySession{stream.dial, stream.accept}
	r.mu.Unlock()
	for _, s := range sessions {
		if s != nil {
			s.close()
		}
	}
}
