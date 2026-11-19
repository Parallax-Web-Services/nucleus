package cloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Parallax-Web-Services/nucleus/fabric"
	"github.com/Parallax-Web-Services/nucleus/positronic"
)

var ErrAccountNotConnected = errors.New("cluster is not connected to a Parallax account")
var accountCode = regexp.MustCompile(`^[a-f0-9-]{36}\.[a-f0-9]{64}$`)

type AccountBinding struct {
	Version   int    `json:"version"`
	Origin    string `json:"origin"`
	ClusterID string `json:"cluster_id"`
	FabricID  string `json:"fabric_id"`
	TeamID    string `json:"team_id"`
	Name      string `json:"name"`
}

type accountChallenge struct {
	ID        string    `json:"id"`
	TeamID    string    `json:"team_id"`
	Name      string    `json:"name"`
	Origin    string    `json:"origin"`
	Status    string    `json:"status"`
	ClusterID *string   `json:"cluster_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type accountNode struct {
	ID              string  `json:"node_id"`
	Name            string  `json:"name"`
	Status          string  `json:"status"`
	LastSeenMS      *int64  `json:"last_seen_ms"`
	LogicalCores    *int    `json:"logical_cores,omitempty"`
	MemoryTotal     *uint64 `json:"memory_total_bytes,omitempty"`
	MemoryAvailable *uint64 `json:"memory_available_bytes,omitempty"`
	OS              string  `json:"os,omitempty"`
	Architecture    string  `json:"architecture,omitempty"`
}

func accountOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("Parallax URL must be an origin without credentials, path, query or fragment")
	}
	loopback := u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return "", errors.New("Parallax requires HTTPS; HTTP is allowed only on loopback for development")
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func accountHTTP() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, ResponseHeaderTimeout: 5 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("Parallax account redirects are disabled")
	}}
}

func accountPost(ctx context.Context, client *http.Client, endpoint string, data any, result any) error {
	body, err := json.Marshal(data)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 32769))
	if err != nil || len(raw) > 32768 {
		return errors.New("Parallax account response exceeds its limit")
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Parallax account request rejected (HTTP %d)", response.StatusCode)
	}
	if result != nil {
		return json.Unmarshal(raw, result)
	}
	return nil
}

// ConnectAccount uses a short-lived code plus a CA ownership proof. A signed-in
// team administrator separately confirms the fingerprint before binding is saved.
func ConnectAccount(ctx context.Context, home, rawOrigin, code string, output io.Writer) error {
	origin, err := accountOrigin(rawOrigin)
	if err != nil {
		return err
	}
	if !accountCode.MatchString(code) {
		return errors.New("use the complete connection code from your signed-in Parallax account")
	}
	state, err := fabric.Load(home)
	if err != nil {
		return err
	}
	if state.FabricID == "" || state.NodeID != state.OwnerID {
		return errors.New("run account connect on the existing fabric owner/coordinator")
	}
	existing, err := LoadAccountBinding(home)
	if err != nil && !errors.Is(err, ErrAccountNotConnected) {
		return err
	}
	if existing != nil {
		return errors.New("this coordinator already has an account binding; disconnect it explicitly before reconnecting")
	}
	client := accountHTTP()
	defer client.CloseIdleConnections()
	var challenge accountChallenge
	payload := map[string]string{"code": code}
	if err := accountPost(ctx, client, origin+"/api/cluster-enrollments/challenge", payload, &challenge); err != nil {
		return err
	}
	if challenge.Origin != origin || challenge.ID != strings.SplitN(code, ".", 2)[0] || !organizationID.MatchString(challenge.TeamID) || challenge.Name == "" || len(challenge.Name) > 320 || strings.ContainsAny(challenge.Name, "\r\n") || !challenge.ExpiresAt.After(time.Now()) || challenge.ExpiresAt.After(time.Now().Add(6*time.Minute)) {
		return errors.New("Parallax returned an invalid or expired account challenge")
	}
	if challenge.Status != "waiting" && challenge.Status != "awaiting_approval" {
		return errors.New("connection request is no longer awaiting a cluster")
	}
	message := strings.Join([]string{"parallax-cluster-connect-v1", origin, challenge.ID, challenge.TeamID, strings.SplitN(code, ".", 2)[1], state.FabricID, challenge.Name, ""}, "\n")
	proof, err := fabric.SignAccount(home, []byte(message))
	if err != nil {
		return err
	}
	claim := map[string]string{"code": code, "fabric_id": state.FabricID, "ca_certificate": base64.StdEncoding.EncodeToString(state.CACertificate), "signature": base64.StdEncoding.EncodeToString(proof)}
	if err := accountPost(ctx, client, origin+"/api/cluster-enrollments/claim", claim, nil); err != nil {
		return err
	}
	fmt.Fprintf(output, "Cluster: %s\nFabric fingerprint: %s\nApprove this fingerprint in your signed-in Parallax account.\n", challenge.Name, state.FabricID)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			var next accountChallenge
			if err := accountPost(ctx, client, origin+"/api/cluster-enrollments/challenge", payload, &next); err != nil {
				return err
			}
			if next.ID != challenge.ID || next.Origin != origin || next.TeamID != challenge.TeamID {
				return errors.New("Parallax connection challenge changed")
			}
			if next.Status == "approved" && next.ClusterID != nil && enrollmentID.MatchString(*next.ClusterID) {
				binding := AccountBinding{Version: 1, Origin: origin, ClusterID: *next.ClusterID, FabricID: state.FabricID, TeamID: challenge.TeamID, Name: challenge.Name}
				if err := saveAccountBinding(home, &binding); err != nil {
					return err
				}
				fmt.Fprintln(output, "Connected. Run nucleus account report to publish the existing coordinator's inventory, or restart nucleus run to report automatically.")
				return nil
			}
		}
	}
}

func LoadAccountBinding(home string) (*AccountBinding, error) {
	var binding *AccountBinding
	err := withStateLock(home, func() error {
		fd, err := syscall.Open(filepath.Join(home, "parallax-account.json"), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if errors.Is(err, syscall.ENOENT) {
			return ErrAccountNotConnected
		}
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "parallax-account.json")
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("account binding must be a private regular file")
		}
		raw, err := io.ReadAll(io.LimitReader(file, 16385))
		if err != nil || len(raw) > 16384 {
			return errors.New("account binding exceeds its limit")
		}
		var b AccountBinding
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&b); err != nil {
			return err
		}
		if decoder.Decode(new(any)) != io.EOF {
			return errors.New("unexpected account binding content")
		}
		state, err := fabric.Load(home)
		if err != nil {
			return err
		}
		origin, err := accountOrigin(b.Origin)
		if err != nil || origin != b.Origin || b.Version != 1 || b.FabricID != state.FabricID || state.NodeID != state.OwnerID || !enrollmentID.MatchString(b.ClusterID) || !organizationID.MatchString(b.TeamID) {
			return errors.New("account binding does not match this fabric owner")
		}
		binding = &b
		return nil
	})
	return binding, err
}

func saveAccountBinding(home string, b *AccountBinding) error {
	return withStateLock(home, func() error {
		target := filepath.Join(home, "parallax-account.json")
		if _, err := os.Lstat(target); err == nil {
			return errors.New("account binding already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		raw, err := json.MarshalIndent(b, "", "  ")
		if err != nil {
			return err
		}
		temp, err := os.CreateTemp(home, ".parallax-account-")
		if err != nil {
			return err
		}
		defer os.Remove(temp.Name())
		if _, err = temp.Write(append(raw, '\n')); err != nil {
			temp.Close()
			return err
		}
		if err = temp.Sync(); err != nil {
			temp.Close()
			return err
		}
		if err = temp.Close(); err != nil {
			return err
		}
		// Link publishes once without replacing an existing or substituted path.
		return os.Link(temp.Name(), target)
	})
}

func DisconnectAccount(home string) error {
	return withStateLock(home, func() error { return os.Remove(filepath.Join(home, "parallax-account.json")) })
}

func ReportAccount(ctx context.Context, home string, view positronic.View) error {
	b, err := LoadAccountBinding(home)
	if err != nil {
		return err
	}
	if view.FabricID != b.FabricID || view.LocalNodeID == "" || len(view.Nodes) > 128 {
		return errors.New("inventory does not match the connected fabric")
	}
	nodes := make([]accountNode, 0, len(view.Nodes))
	for _, node := range view.Nodes {
		entry := accountNode{ID: node.NodeID, Name: node.Name, Status: node.Status, LastSeenMS: node.LastSeenMS}
		if entry.Status != "online" && entry.Status != "offline" && entry.Status != "awaiting" {
			entry.Status = "offline"
		}
		if node.Resources != nil {
			entry.LogicalCores = &node.Resources.CPU.LogicalCores
			entry.MemoryTotal = &node.Resources.Memory.TotalBytes
			entry.MemoryAvailable = &node.Resources.Memory.AvailableBytes
			entry.OS = node.Resources.Node.OperatingSystem
			entry.Architecture = node.Resources.CPU.Architecture
		}
		nodes = append(nodes, entry)
	}
	raw, err := json.Marshal(struct {
		FabricID string        `json:"fabric_id"`
		Nodes    []accountNode `json:"nodes"`
	}{b.FabricID, nodes})
	if err != nil {
		return err
	}
	if len(raw) > 262144 {
		return errors.New("account report exceeds its size limit")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	nonceText := hex.EncodeToString(nonce[:])
	digest := sha256.Sum256(raw)
	message := strings.Join([]string{"parallax-cluster-report-v1", b.Origin, b.ClusterID, timestamp, nonceText, hex.EncodeToString(digest[:]), ""}, "\n")
	signature, err := fabric.SignAccount(home, []byte(message))
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, b.Origin+"/api/clusters/"+b.ClusterID+"/reports", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("X-Cluster-Timestamp", timestamp)
	request.Header.Set("X-Cluster-Nonce", nonceText)
	request.Header.Set("X-Cluster-Signature", base64.StdEncoding.EncodeToString(signature))
	client := accountHTTP()
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("account inventory report rejected (HTTP %d)", response.StatusCode)
	}
	var result struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result); err != nil || result.Status != "accepted" {
		return errors.New("account did not acknowledge inventory")
	}
	return nil
}
