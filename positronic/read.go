package positronic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
)

// ReadView reads the coordinator's existing authenticated inventory without
// creating membership, executing work or submitting another heartbeat.
func ReadView(ctx context.Context, home string) (View, error) {
	state, err := fabric.Load(home)
	if err != nil {
		return View{}, err
	}
	if err := fabric.ValidateEndpoint(state.Endpoint); err != nil {
		return View{}, err
	}
	config, err := fabric.ClientTLS(home)
	if err != nil {
		return View{}, err
	}
	return readView(ctx, state, config)
}

func readView(ctx context.Context, state *fabric.State, config *tls.Config) (View, error) {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSClientConfig: config, TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fabric redirects are disabled") }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(state.Endpoint, "/")+"/v1/fabric", nil)
	if err != nil {
		return View{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return View{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return View{}, fmt.Errorf("fabric inventory rejected (HTTP %d)", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxViewBytes+1))
	if err != nil || len(data) > maxViewBytes {
		return View{}, errors.New("fabric inventory exceeds its limit")
	}
	var view View
	if err := decodeJSON(bytes.NewReader(data), &view); err != nil {
		return View{}, err
	}
	if err := validateView(view, state.FabricID, state.NodeID); err != nil {
		return View{}, err
	}
	return view, nil
}
