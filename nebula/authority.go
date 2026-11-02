package nebula

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Parallax-Web-Services/nucleus/cloud"
	"github.com/Parallax-Web-Services/nucleus/fabric"
)

const DefaultRelayURL = "wss://positronic.app/nebula/v1/relay"

type CapabilityRequest struct {
	FabricID     string `json:"fabric_id"`
	Service      string `json:"service"`
	Mode         string `json:"mode"`
	PeerID       string `json:"peer_id"`
	ConnectionID string `json:"connection_id"`
	StreamID     string `json:"stream_id"`
}
type Authorization struct {
	SchemaVersion int    `json:"schema_version"`
	Capability    string `json:"capability"`
	ExpiresAt     int64  `json:"expires_at"`
	RelayURL      string `json:"relay_url"`
}
type CapabilitySource func(context.Context, CapabilityRequest) (Authorization, error)

func secureHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second},
		Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}

// HostedCapabilitySource authenticates every ticket with the saved registration
// and existing Ed25519 identity. There is no organization token or fallback.
func HostedCapabilitySource(home string) (CapabilitySource, error) {
	if _, err := cloud.LoadBinding(home); err != nil {
		return nil, err
	}
	client := secureHTTPClient()
	return func(ctx context.Context, input CapabilityRequest) (Authorization, error) {
		var result Authorization
		binding, err := cloud.LoadBinding(home)
		if err != nil {
			return result, err
		}
		state, err := fabric.Load(home)
		if err != nil || binding.Revoked || state.NodeID != binding.NodeID || state.FabricID == "" || input.FabricID != state.FabricID {
			return result, errors.New("NEBULA requires the current paired identity and active hosted registration")
		}
		body, err := json.Marshal(input)
		if err != nil {
			return result, err
		}
		path := binding.BasePath + "/api/nodes/" + binding.NodeID + "/nebula/authorize"
		nonce, err := randomID(16)
		if err != nil {
			return result, err
		}
		timestamp := fmt.Sprint(time.Now().Unix())
		proof, err := fabric.SignCloud(home, []byte(cloud.RequestMessage(http.MethodPost, binding.Origin, path, timestamp, nonce, body)))
		if err != nil {
			return result, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, binding.Origin+path, bytes.NewReader(body))
		if err != nil {
			return result, err
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/json")
		request.Header.Set("X-Nucleus-Timestamp", timestamp)
		request.Header.Set("X-Nucleus-Nonce", nonce)
		request.Header.Set("X-Nucleus-Signature", base64.StdEncoding.EncodeToString(proof))
		response, err := client.Do(request)
		if err != nil {
			return result, errors.New("NEBULA authorization unavailable")
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10+1))
		if err != nil || len(data) > 32<<10 {
			return result, errors.New("invalid NEBULA authority response")
		}
		if response.StatusCode != http.StatusOK {
			return result, fmt.Errorf("NEBULA authorization rejected (HTTP %d)", response.StatusCode)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.SchemaVersion != 1 || len(result.Capability) > CapabilityMaxTokenBytes ||
			result.Capability == "" || result.ExpiresAt <= time.Now().Unix() || result.ExpiresAt > time.Now().Unix()+35 {
			return Authorization{}, errors.New("invalid NEBULA authority response")
		}
		return result, nil
	}, nil
}
