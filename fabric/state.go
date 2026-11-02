// Package fabric provides durable node identity, explicit fabric membership, and
// mutually authenticated TLS without depending on a UI, scheduler, or shell.
package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

const schemaVersion = 1
const maxDocument = 1 << 20
const maxMembers = 128
const maxInvitations = 128

// Member is an explicitly authorized node. NodeID is SHA-256 of its public SPKI.
type Member struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
}

// State contains public local metadata. Private keys never appear in this type.
type State struct {
	Name          string            `json:"name"`
	NodeID        string            `json:"node_id"`
	FabricID      string            `json:"fabric_id"`
	OwnerID       string            `json:"owner_id"`
	Endpoint      string            `json:"endpoint"`
	Members       map[string]Member `json:"members"`
	Certificate   []byte            `json:"certificate"`
	CACertificate []byte            `json:"ca_certificate"`
}

type invitationRecord struct {
	SecretHash          []byte    `json:"secret_hash"`
	ExpiresAt           time.Time `json:"expires_at"`
	AcceptedRequestHash string    `json:"accepted_request_hash,omitempty"`
	Grant               []byte    `json:"grant,omitempty"`
}
type pendingJoin struct {
	InvitationID     string    `json:"invitation_id"`
	RequestHash      string    `json:"request_hash"`
	CACertificate    []byte    `json:"ca_certificate"`
	OwnerCertificate []byte    `json:"owner_certificate"`
	FabricID         string    `json:"fabric_id"`
	OwnerID          string    `json:"owner_id"`
	Endpoint         string    `json:"endpoint"`
	ExpiresAt        time.Time `json:"expires_at"`
}
type diskState struct {
	Version              int                         `json:"version"`
	Public               State                       `json:"public"`
	IdentityKey          []byte                      `json:"identity_key_pkcs8"`
	CAKey                []byte                      `json:"ca_key_pkcs8,omitempty"`
	Invitations          map[string]invitationRecord `json:"invitations,omitempty"`
	Pending              *pendingJoin                `json:"pending,omitempty"`
	CompletedRequestHash string                      `json:"completed_request_hash,omitempty"`
	CompletedGrantHash   string                      `json:"completed_grant_hash,omitempty"`
}

// Init creates one Ed25519 identity. Repeated calls preserve the existing identity.
func Init(home, name string) (*State, error) {
	var public *State
	err := withLock(home, func(root string) error {
		if _, err := os.Lstat(filepath.Join(root, "state.json")); err == nil {
			state, err := loadDisk(root)
			if err != nil {
				return err
			}
			public = &state.Public
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if name == "" {
			name, _ = os.Hostname()
			if name == "" {
				name = "node"
			}
		}
		if err := validateName(name); err != nil {
			return err
		}
		key, err := generateKey()
		if err != nil {
			return err
		}
		encoded, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		id, err := publicID(key.Public())
		if err != nil {
			return err
		}
		state := &diskState{
			Version:     schemaVersion,
			Public:      State{Name: name, NodeID: id, Members: map[string]Member{}},
			IdentityKey: encoded, Invitations: map[string]invitationRecord{},
		}
		if err := saveDisk(root, state); err != nil {
			return err
		}
		public = &state.Public
		return nil
	})
	return public, err
}

// Load atomically reads and checks the current public state. It never creates an identity.
func Load(home string) (*State, error) {
	root, err := checkedHome(home, false)
	if err != nil {
		return nil, err
	}
	state, err := loadDisk(root)
	if err != nil {
		return nil, err
	}
	return &state.Public, nil
}

// ValidateEndpoint restricts this LAN alpha to literal private/loopback IPv4 HTTPS endpoints.
func ValidateEndpoint(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawPath != "" {
		return errors.New("endpoint must be https://PRIVATE_IPV4:PORT without credentials, path, query, or fragment")
	}
	host, port, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || port == "" || strings.Contains(port, "+") {
		return errors.New("endpoint requires a literal IPv4 address and explicit port")
	}
	var number int
	for _, c := range port {
		if c < '0' || c > '9' {
			return errors.New("invalid endpoint port")
		}
		number = number*10 + int(c-'0')
		if number > 65535 {
			return errors.New("endpoint port must be 1–65535")
		}
	}
	if number == 0 {
		return errors.New("endpoint port must be 1–65535")
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || strings.Contains(host, ":") {
		return errors.New("endpoint must use a literal IPv4 address")
	}
	v := ip.To4()
	private := v[0] == 10 || (v[0] == 172 && v[1] >= 16 && v[1] <= 31) ||
		(v[0] == 192 && v[1] == 168)
	if !(private || ip.IsLoopback()) || ip.IsUnspecified() {
		return errors.New("endpoint must use RFC1918 private IPv4 or loopback; public/wildcard addresses are disabled")
	}
	return nil
}

func withLock(home string, action func(string) error) error {
	root, err := checkedHome(home, true)
	if err != nil {
		return err
	}
	path := filepath.Join(root, "state.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("open state lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("state lock must be a regular file")
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return action(root)
}

func checkedHome(home string, create bool) (string, error) {
	if home == "" {
		return "", errors.New("fabric home must be specified")
	}
	root, err := filepath.Abs(home)
	if err != nil {
		return "", err
	}
	// Reject symlink components as well as the final managed directory.
	for path := root; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("refusing symlink: %s", path)
			}
			if !info.IsDir() {
				return "", fmt.Errorf("not a directory: %s", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	if create {
		if err := os.MkdirAll(root, 0700); err != nil {
			return "", err
		}
		if err := os.Chmod(root, 0700); err != nil {
			return "", err
		}
	} else if _, err := os.Stat(root); err != nil {
		return "", fmt.Errorf("fabric is not initialized: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0077 != 0 {
		return "", errors.New("fabric home must be a private directory (0700)")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return "", errors.New("fabric home must be owned by the current user")
	}
	return root, nil
}

func loadDisk(root string) (*diskState, error) {
	data, err := readPrivate(filepath.Join(root, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("read fabric state (run init first): %w", err)
	}
	var state diskState
	if err := decode(data, &state); err != nil {
		return nil, fmt.Errorf("invalid fabric state: %w", err)
	}
	if err := validateDisk(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

func readPrivate(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("fabric state must be a private regular file (0600)")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("fabric state must be owned by the current user")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxDocument+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDocument {
		return nil, errors.New("fabric state exceeds size limit")
	}
	return data, nil
}

func saveDisk(root string, state *diskState) error {
	if err := validateDisk(state); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxDocument {
		return errors.New("fabric state exceeds size limit")
	}
	path := filepath.Join(root, "state.json")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("refusing non-regular fabric state")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(root, ".state-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	dir, err := os.Open(root)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func validateDisk(state *diskState) error {
	if state.Version != schemaVersion {
		return errors.New("unsupported fabric state version")
	}
	if err := validateName(state.Public.Name); err != nil {
		return err
	}
	key, err := parseKey(state.IdentityKey)
	if err != nil {
		return err
	}
	id, err := publicID(key.Public())
	if err != nil || state.Public.NodeID != id {
		return errors.New("node identity does not match its private key")
	}
	if len(state.Public.Members) > maxMembers || len(state.Invitations) > maxInvitations {
		return errors.New("alpha membership or invitation limit exceeded")
	}
	for id, member := range state.Public.Members {
		if !validID(id) || member.NodeID != id {
			return errors.New("invalid member identifier")
		}
		if err := validateName(member.Name); err != nil {
			return err
		}
	}
	if state.Public.FabricID != "" {
		ca, err := parseCA(state.Public.CACertificate)
		if err != nil {
			return err
		}
		if hashHex(ca.Raw) != state.Public.FabricID || !validID(state.Public.OwnerID) {
			return errors.New("invalid fabric identity")
		}
		if err := ValidateEndpoint(state.Public.Endpoint); err != nil {
			return err
		}
		cert, err := verifyLeaf(state.Public.Certificate, ca, state.Public.NodeID)
		if err != nil {
			return fmt.Errorf("invalid local membership certificate: %w", err)
		}
		certID, err := publicID(cert.PublicKey)
		if err != nil || certID != id {
			return errors.New("local certificate does not match identity")
		}
		if _, ok := state.Public.Members[id]; !ok {
			return errors.New("local node is absent from membership")
		}
		if _, ok := state.Public.Members[state.Public.OwnerID]; !ok {
			return errors.New("owner is absent from membership")
		}
		if len(state.CAKey) > 0 {
			caKey, err := parseKey(state.CAKey)
			if err != nil || !bytes.Equal(caKey.Public().(ed25519.PublicKey), ca.PublicKey.(ed25519.PublicKey)) ||
				state.Public.OwnerID != id {
				return errors.New("CA signing key is not owned by this fabric owner")
			}
		}
	} else if len(state.Public.Certificate) > 0 || len(state.Public.CACertificate) > 0 || len(state.CAKey) > 0 ||
		state.Public.OwnerID != "" || state.Public.Endpoint != "" || len(state.Public.Members) > 0 {
		return errors.New("unjoined node contains inconsistent fabric state")
	}
	return nil
}

func decode(data []byte, value any) error {
	if len(data) == 0 || len(data) > maxDocument {
		return errors.New("document is empty or exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("document contains trailing data")
	}
	return nil
}
func validateName(name string) error {
	if name == "" || len(name) > 128 || !utf8.ValidString(name) {
		return errors.New("node name must be 1–128 valid UTF-8 bytes")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return errors.New("node name cannot contain control characters")
		}
	}
	return nil
}
func generateKey() (ed25519.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	return key, err
}
func parseKey(data []byte) (ed25519.PrivateKey, error) {
	value, err := x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("invalid identity key: %w", err)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("only Ed25519 identity keys are supported")
	}
	return key, nil
}
func publicID(key any) (string, error) {
	if _, ok := key.(ed25519.PublicKey); !ok {
		return "", errors.New("only Ed25519 public keys are supported")
	}
	data, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return hashHex(data), nil
}
func hashHex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validID(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}
func randomBytes(length int) ([]byte, error) {
	data := make([]byte, length)
	_, err := rand.Read(data)
	return data, err
}
