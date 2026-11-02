package nebula

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/coder/websocket"
)

type ClientConfig struct {
	Home          string
	RelayURL      string
	Authorize     CapabilitySource
	HTTPClient    *http.Client
	RenewInterval time.Duration
}
type Client struct {
	config   ClientConfig
	identity *fabric.State
	ctx      context.Context
	cancel   context.CancelFunc
	slots    chan struct{}
	mu       sync.Mutex
	sockets  map[*clientSocket]bool
}
type clientSocket struct {
	client  *Client
	ws      *websocket.Conn
	request CapabilityRequest
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
}

func NewClient(ctx context.Context, config ClientConfig) (*Client, error) {
	state, err := fabric.Load(config.Home)
	if err != nil {
		return nil, err
	}
	if state.FabricID == "" || state.OwnerID == "" || len(state.Certificate) == 0 {
		return nil, errors.New("NEBULA v1 requires accepted private fabric membership")
	}
	if config.RelayURL == "" {
		config.RelayURL = DefaultRelayURL
	}
	parsed, err := url.Parse(config.RelayURL)
	if err != nil || parsed.User != nil || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != Path || parsed.RawPath != "" ||
		(parsed.Scheme != "wss" && !(parsed.Scheme == "ws" && net.ParseIP(parsed.Hostname()).IsLoopback())) {
		return nil, errors.New("NEBULA relay must be an explicit secure relay endpoint")
	}
	if config.Authorize == nil {
		return nil, errors.New("NEBULA capability source required")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = secureHTTPClient()
	}
	if config.RenewInterval == 0 {
		config.RenewInterval = 10 * time.Second
	}
	if config.RenewInterval < 10*time.Millisecond || config.RenewInterval > 10*time.Second {
		return nil, errors.New("invalid NEBULA renewal interval")
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Client{config: config, identity: state, ctx: lifetime, cancel: cancel, slots: make(chan struct{}, 8), sockets: map[*clientSocket]bool{}}, nil
}
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	sockets := make([]*clientSocket, 0, len(c.sockets))
	for s := range c.sockets {
		sockets = append(sockets, s)
	}
	c.mu.Unlock()
	for _, s := range sockets {
		s.close()
	}
	return nil
}
func (s *clientSocket) close() {
	s.once.Do(func() {
		s.cancel()
		_ = s.ws.CloseNow()
		s.client.mu.Lock()
		delete(s.client.sockets, s)
		s.client.mu.Unlock()
		<-s.client.slots
	})
}
func (c *Client) open(ctx context.Context, mode, peer, stream string) (*clientSocket, error) {
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, net.ErrClosed
	}
	reserved := true
	defer func() {
		if reserved {
			<-c.slots
		}
	}()
	if c.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	id, err := randomID(32)
	if err != nil {
		return nil, err
	}
	request := CapabilityRequest{FabricID: c.identity.FabricID, Service: "nucleus-fabric", Mode: mode, PeerID: peer, ConnectionID: id, StreamID: stream}
	timeout, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	authorization, err := c.config.Authorize(timeout, request)
	if err != nil {
		return nil, err
	}
	if authorization.RelayURL != c.config.RelayURL || authorization.Capability == "" {
		return nil, errors.New("NEBULA authority returned another relay")
	}
	signature, err := fabric.SignNebula(c.config.Home, NodeProofMessage(authorization.Capability))
	if err != nil {
		return nil, err
	}
	ws, response, err := websocket.Dial(timeout, c.config.RelayURL, &websocket.DialOptions{HTTPClient: c.config.HTTPClient, Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	if response != nil && response.Body != nil {
		defer response.Body.Close()
	}
	if err != nil {
		return nil, errors.New("NEBULA relay connection unavailable")
	}
	if ws.Subprotocol() != Subprotocol {
		ws.CloseNow()
		return nil, errors.New("NEBULA relay protocol mismatch")
	}
	ws.SetReadLimit(MaxFrame)
	if err = writeWire(timeout, ws, wireMessage{Type: "auth", Capability: authorization.Capability, Proof: base64.StdEncoding.EncodeToString(signature)}); err != nil {
		ws.CloseNow()
		return nil, errors.New("NEBULA relay authentication failed")
	}
	ready, err := readWire(timeout, ws)
	if err != nil || ready.Type != "ready" || ready.Capability != "" || ready.Proof != "" || ready.StreamID != "" || ready.PeerID != "" {
		ws.CloseNow()
		return nil, errors.New("NEBULA peer unavailable or unauthorized")
	}
	socketctx, socketcancel := context.WithCancel(c.ctx)
	socket := &clientSocket{client: c, ws: ws, request: request, ctx: socketctx, cancel: socketcancel}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		socketcancel()
		ws.CloseNow()
		return nil, net.ErrClosed
	}
	c.sockets[socket] = true
	c.mu.Unlock()
	reserved = false
	go socket.renew()
	return socket, nil
}
func (s *clientSocket) renew() {
	ticker := time.NewTicker(s.client.config.RenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			s.close()
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
			authorization, err := s.client.config.Authorize(ctx, s.request)
			if err == nil && authorization.RelayURL == s.client.config.RelayURL {
				var proof []byte
				proof, err = fabric.SignNebula(s.client.config.Home, NodeProofMessage(authorization.Capability))
				if err == nil {
					err = writeWire(ctx, s.ws, wireMessage{Type: "renew", Capability: authorization.Capability, Proof: base64.StdEncoding.EncodeToString(proof)})
				}
			} else if err == nil {
				err = errors.New("NEBULA relay binding changed")
			}
			cancel()
			if err != nil {
				s.close()
				return
			}
		}
	}
}

type streamConn struct {
	net.Conn
	socket *clientSocket
}

func (c *streamConn) Close() error { c.socket.close(); return nil }
func (c *streamConn) Read(data []byte) (int, error) {
	n, err := c.Conn.Read(data)
	if err != nil {
		c.socket.close()
	}
	return n, err
}
func (c *streamConn) Write(data []byte) (int, error) {
	total := 0
	for len(data) > 0 {
		part := data
		if len(part) > MaxFrame {
			part = part[:MaxFrame]
		}
		n, err := c.Conn.Write(part)
		total += n
		data = data[n:]
		if err != nil {
			c.socket.close()
			return total, err
		}
		if n == 0 {
			c.socket.close()
			return total, errors.New("NEBULA stream write stopped")
		}
	}
	return total, nil
}
func (s *clientSocket) netConn() net.Conn {
	conn := websocket.NetConn(s.ctx, s.ws, websocket.MessageBinary)
	s.ws.SetReadLimit(MaxFrame)
	return &streamConn{Conn: conn, socket: s}
}
func (c *Client) DialPeer(ctx context.Context, peerID string) (net.Conn, error) {
	if _, ok := c.identity.Members[peerID]; !ok || peerID == c.identity.NodeID {
		return nil, errors.New("NEBULA peer is not an accepted fabric member")
	}
	socket, err := c.open(ctx, "dial", peerID, "")
	if err != nil {
		return nil, err
	}
	return socket.netConn(), nil
}

type Listener struct {
	client   *Client
	ctx      context.Context
	cancel   context.CancelFunc
	accepted chan net.Conn
	mu       sync.Mutex
	control  *clientSocket
}

func (c *Client) Listen(ctx context.Context) (net.Listener, error) {
	if c.identity.NodeID != c.identity.OwnerID {
		return nil, errors.New("NEBULA v1 fabric listener must be the owner")
	}
	life, cancel := context.WithCancel(ctx)
	control, err := c.open(life, "listen", "", "")
	if err != nil {
		cancel()
		return nil, err
	}
	listener := &Listener{client: c, ctx: life, cancel: cancel, accepted: make(chan net.Conn, 8), control: control}
	go listener.run(control)
	return listener, nil
}
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.accepted:
		return conn, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	case <-l.client.ctx.Done():
		return nil, net.ErrClosed
	}
}
func (l *Listener) Close() error {
	l.cancel()
	l.mu.Lock()
	control := l.control
	l.mu.Unlock()
	if control != nil {
		control.close()
	}
	for {
		select {
		case conn := <-l.accepted:
			_ = conn.Close()
		default:
			return nil
		}
	}
}

type relayAddress string

func (a relayAddress) Network() string { return "nebula" }
func (a relayAddress) String() string  { return string(a) }
func (l *Listener) Addr() net.Addr     { return relayAddress(l.client.identity.NodeID) }
func (l *Listener) run(control *clientSocket) {
	for {
		l.readControl(control)
		control.close()
		if l.ctx.Err() != nil || l.client.ctx.Err() != nil {
			return
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-timer.C:
		case <-l.ctx.Done():
			timer.Stop()
			return
		case <-l.client.ctx.Done():
			timer.Stop()
			return
		}
		next, err := l.client.open(l.ctx, "listen", "", "")
		if err != nil {
			continue
		}
		l.mu.Lock()
		l.control = next
		l.mu.Unlock()
		control = next
	}
}
func (l *Listener) readControl(control *clientSocket) {
	slots := make(chan struct{}, 7)
	for {
		message, err := readWire(l.ctx, control.ws)
		if err != nil {
			return
		}
		if message.Type == "renewed" && message.Capability == "" && message.Proof == "" && message.StreamID == "" && message.PeerID == "" {
			continue
		}
		if message.Type != "incoming" || !lowerHex(message.StreamID, 32) || !lowerHex(message.PeerID, 64) || message.Capability != "" || message.Proof != "" {
			return
		}
		current, err := fabric.Load(l.client.config.Home)
		if err != nil || current.FabricID != l.client.identity.FabricID {
			return
		}
		if _, ok := current.Members[message.PeerID]; !ok {
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			continue
		}
		go func(message wireMessage) {
			defer func() { <-slots }()
			socket, err := l.client.open(l.ctx, "accept", message.PeerID, message.StreamID)
			if err != nil {
				return
			}
			conn := socket.netConn()
			select {
			case l.accepted <- conn:
			case <-l.ctx.Done():
				_ = conn.Close()
			case <-l.client.ctx.Done():
				_ = conn.Close()
			}
		}(message)
	}
}
