package positronic

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/inventory"
)

// Exchange publishes a fresh measurement, then obtains the authoritative fabric view.
// Authentication is provided by the reusable fabric TLS configuration. No SSH or
// remote commands are involved.
func Exchange(home string, snapshot inventory.Snapshot) (View, error) {
	return ExchangeWithDialer(home, snapshot, nil)
}

// ExchangeWithDialer preserves fabric TLS and protocol validation while allowing
// an explicitly configured authenticated transport beneath the TLS connection.
func ExchangeWithDialer(home string, snapshot inventory.Snapshot, dial func(context.Context, string, string) (net.Conn, error)) (View, error) {
	if err := inventory.Validate(snapshot); err != nil {
		return View{}, fmt.Errorf("local inventory: %w", err)
	}
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
	if dial == nil {
		dial = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: -1}).DialContext
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           dial,
		TLSClientConfig:       config,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
		ForceAttemptHTTP2:     false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("fabric redirects are disabled") },
	}
	endpoint := strings.TrimRight(state.Endpoint, "/")
	heartbeat := Heartbeat{SchemaVersion: schemaVersion, FabricID: state.FabricID, NodeID: state.NodeID, Resources: snapshot}
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return View{}, err
	}
	if len(body) > maxHeartbeatBytes {
		return View{}, errors.New("local heartbeat exceeds size limit")
	}
	request, err := http.NewRequest(http.MethodPost, endpoint+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return View{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return View{}, fmt.Errorf("send authenticated heartbeat: %w", err)
	}
	if response.StatusCode != http.StatusNoContent {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		response.Body.Close()
		return View{}, fmt.Errorf("heartbeat rejected (%d): %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	response.Body.Close()
	request, err = http.NewRequest(http.MethodGet, endpoint+"/v1/fabric", nil)
	if err != nil {
		return View{}, err
	}
	response, err = client.Do(request)
	if err != nil {
		return View{}, fmt.Errorf("read authenticated fabric view: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return View{}, fmt.Errorf("fabric view rejected (%d): %s", response.StatusCode, strings.TrimSpace(string(message)))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxViewBytes+1))
	if err != nil {
		return View{}, err
	}
	if len(data) > maxViewBytes {
		return View{}, errors.New("fabric view exceeds size limit")
	}
	var view View
	if err := decodeJSON(bytes.NewReader(data), &view); err != nil {
		return View{}, fmt.Errorf("invalid fabric view: %w", err)
	}
	if err := validateView(view, state.FabricID, state.NodeID); err != nil {
		return View{}, err
	}
	return view, nil
}

func validateView(view View, fabricID, viewerID string) error {
	if view.SchemaVersion != schemaVersion || view.FabricID != fabricID || view.LocalNodeID != viewerID ||
		view.CollectedAtMS <= 0 || len(view.Nodes) == 0 || len(view.Nodes) > 128 {
		return errors.New("fabric view identity or schema mismatch")
	}
	seen := make(map[string]bool, len(view.Nodes))
	localCount := 0
	capacity := Capacity{}
	for _, node := range view.Nodes {
		decodedID, idError := hex.DecodeString(node.NodeID)
		if idError != nil || len(decodedID) != 32 || strings.ToLower(node.NodeID) != node.NodeID || node.Name == "" || len(node.Name) > 128 || strings.ContainsAny(node.Name, "\r\n\x00") || seen[node.NodeID] {
			return errors.New("invalid or duplicate fabric node")
		}
		seen[node.NodeID] = true
		if node.LastSeenMS != nil && *node.LastSeenMS <= 0 {
			return errors.New("invalid receipt time")
		}
		if node.NodeID == viewerID {
			if node.Kind != "local" {
				return errors.New("viewer is not marked local")
			}
			localCount++
		} else if node.Kind != "peer" {
			return errors.New("invalid peer kind")
		}
		switch node.Status {
		case "online":
			if node.Resources == nil || node.LastSeenMS == nil {
				return errors.New("online node has no current inventory")
			}
			if err := inventory.Validate(*node.Resources); err != nil {
				return err
			}
			if err := addCapacity(&capacity, *node.Resources); err != nil {
				return err
			}
		case "offline", "awaiting":
			if node.Resources != nil {
				if err := inventory.Validate(*node.Resources); err != nil {
					return err
				}
			}
		default:
			return errors.New("unknown fabric node status")
		}
	}
	if localCount != 1 || capacity != view.AvailableCapacity {
		return errors.New("fabric available capacity does not match online inventory")
	}
	return nil
}
