package nebula

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/coder/websocket"
)

const Path = "/nebula/v1/relay"
const Subprotocol = "nucleus-nebula-v1"
const MaxFrame = 64 << 10

type wireMessage struct {
	Type       string `json:"type"`
	Capability string `json:"capability,omitempty"`
	Proof      string `json:"proof,omitempty"`
	StreamID   string `json:"stream_id,omitempty"`
	PeerID     string `json:"peer_id,omitempty"`
}

func randomID(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decodeWire(data []byte) (wireMessage, error) {
	var result wireMessage
	if len(data) > 16<<10 {
		return result, errors.New("invalid NEBULA control frame")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return result, errors.New("invalid NEBULA control frame")
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return result, errors.New("invalid NEBULA control frame")
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return result, errors.New("invalid NEBULA control frame")
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return result, errors.New("invalid NEBULA control frame")
		}
	}
	if _, err = d.Token(); err != nil {
		return result, errors.New("invalid NEBULA control frame")
	}
	if _, err = d.Token(); err != io.EOF {
		return result, errors.New("invalid NEBULA control frame")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil {
		return result, errors.New("invalid NEBULA control frame")
	}
	return result, nil
}

func writeWire(ctx context.Context, c *websocket.Conn, m wireMessage) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	timeout, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.Write(timeout, websocket.MessageText, data)
}

func readWire(ctx context.Context, c *websocket.Conn) (wireMessage, error) {
	typ, data, err := c.Read(ctx)
	if err != nil {
		return wireMessage{}, err
	}
	if typ != websocket.MessageText {
		return wireMessage{}, errors.New("NEBULA control frame required")
	}
	return decodeWire(data)
}
