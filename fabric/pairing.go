package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var requestBindingOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

type invitation struct {
	Version          int       `json:"version"`
	InvitationID     string    `json:"invitation_id"`
	FabricID         string    `json:"fabric_id"`
	OwnerID          string    `json:"owner_id"`
	Endpoint         string    `json:"endpoint"`
	CACertificate    []byte    `json:"ca_certificate"`
	OwnerCertificate []byte    `json:"owner_certificate"`
	Secret           []byte    `json:"secret"`
	ExpiresAt        time.Time `json:"expires_at"`
	Signature        []byte    `json:"signature,omitempty"`
}
type joinRequest struct {
	Version      int    `json:"version"`
	InvitationID string `json:"invitation_id"`
	FabricID     string `json:"fabric_id"`
	OwnerID      string `json:"owner_id"`
	Endpoint     string `json:"endpoint"`
	Name         string `json:"name"`
	Secret       []byte `json:"secret"`
	CSR          []byte `json:"csr"`
}
type requestBinding struct {
	InvitationID string `json:"invitation_id"`
	FabricID     string `json:"fabric_id"`
	OwnerID      string `json:"owner_id"`
	Endpoint     string `json:"endpoint"`
	Name         string `json:"name"`
	SecretHash   []byte `json:"secret_hash"`
}
type grant struct {
	Version          int               `json:"version"`
	InvitationID     string            `json:"invitation_id"`
	FabricID         string            `json:"fabric_id"`
	OwnerID          string            `json:"owner_id"`
	Endpoint         string            `json:"endpoint"`
	NodeID           string            `json:"node_id"`
	RequestHash      string            `json:"request_hash"`
	CACertificate    []byte            `json:"ca_certificate"`
	OwnerCertificate []byte            `json:"owner_certificate"`
	Certificate      []byte            `json:"certificate"`
	Members          map[string]Member `json:"members"`
	Signature        []byte            `json:"signature,omitempty"`
}

// Invite exports an expiring one-use enrollment token over an explicit trusted
// out-of-band channel. The secret itself is never stored in the owner's state.
func Invite(home, endpoint string, ttl time.Duration) ([]byte, error) {
	if err := ValidateEndpoint(endpoint); err != nil {
		return nil, err
	}
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	if ttl <= 0 || ttl > 24*time.Hour {
		return nil, errors.New("invitation TTL must be positive and at most 24 hours")
	}
	var result []byte
	err := withLock(home, func(root string) error {
		state, err := loadDisk(root)
		if err != nil {
			return err
		}
		if state.Pending != nil {
			return errors.New("cannot create a fabric while a join request is pending")
		}
		key, err := parseKey(state.IdentityKey)
		if err != nil {
			return err
		}
		if state.Public.FabricID == "" {
			caKey, err := generateKey()
			if err != nil {
				return err
			}
			caDER, err := createCA(caKey)
			if err != nil {
				return err
			}
			ca, err := parseCA(caDER)
			if err != nil {
				return err
			}
			leaf, err := issueLeaf(ca, caKey, key.Public().(ed25519.PublicKey), state.Public.NodeID)
			if err != nil {
				return err
			}
			caKeyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
			if err != nil {
				return err
			}
			state.CAKey = caKeyDER
			state.Public.FabricID = hashHex(caDER)
			state.Public.OwnerID = state.Public.NodeID
			state.Public.Endpoint = endpoint
			state.Public.CACertificate = caDER
			state.Public.Certificate = leaf
			state.Public.Members = map[string]Member{state.Public.NodeID: {NodeID: state.Public.NodeID, Name: state.Public.Name}}
		}
		if state.Public.OwnerID != state.Public.NodeID || len(state.CAKey) == 0 {
			return errors.New("only the fabric owner can issue invitations")
		}
		if state.Public.Endpoint != endpoint {
			return errors.New("fabric endpoint is immutable in this alpha; use the existing endpoint")
		}
		if state.Invitations == nil {
			state.Invitations = map[string]invitationRecord{}
		}
		now := time.Now().UTC()
		// Expired unaccepted invitations carry no retry grant and may be pruned.
		for id, record := range state.Invitations {
			if record.AcceptedRequestHash == "" && !now.Before(record.ExpiresAt) {
				delete(state.Invitations, id)
			}
		}
		if len(state.Invitations) >= maxInvitations {
			return errors.New("alpha invitation limit reached")
		}
		idBytes, err := randomBytes(16)
		if err != nil {
			return err
		}
		secret, err := randomBytes(32)
		if err != nil {
			return err
		}
		id := hex.EncodeToString(idBytes)
		expires := now.Add(ttl)
		document := invitation{
			Version: schemaVersion, InvitationID: id, FabricID: state.Public.FabricID,
			OwnerID: state.Public.OwnerID, Endpoint: state.Public.Endpoint,
			CACertificate: state.Public.CACertificate, OwnerCertificate: state.Public.Certificate,
			Secret: secret, ExpiresAt: expires,
		}
		unsigned, err := json.Marshal(document)
		if err != nil {
			return err
		}
		document.Signature = ed25519.Sign(key, unsigned)
		result, err = json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		sum := sha256.Sum256(secret)
		state.Invitations[id] = invitationRecord{SecretHash: sum[:], ExpiresAt: expires}
		return saveDisk(root, state)
	})
	return result, err
}

// Join explicitly accepts an invitation and returns a proof-of-key-possession
// request. The node remains unjoined until the owner accepts and FinishJoin succeeds.
func Join(home string, data []byte) ([]byte, error) {
	invite, err := parseInvitation(data)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(invite.ExpiresAt) {
		return nil, errors.New("invitation has expired")
	}
	var result []byte
	err = withLock(home, func(root string) error {
		state, err := loadDisk(root)
		if err != nil {
			return err
		}
		if state.Public.FabricID != "" {
			return errors.New("node already belongs to a fabric")
		}
		if state.Public.NodeID == invite.OwnerID {
			return errors.New("refusing to join an invitation for this same node identity")
		}
		key, err := parseKey(state.IdentityKey)
		if err != nil {
			return err
		}
		request := joinRequest{
			Version: schemaVersion, InvitationID: invite.InvitationID, FabricID: invite.FabricID,
			OwnerID: invite.OwnerID, Endpoint: invite.Endpoint, Name: state.Public.Name, Secret: invite.Secret,
		}
		binding, err := bindingHash(request)
		if err != nil {
			return err
		}
		template := &x509.CertificateRequest{
			Subject:            pkix.Name{CommonName: state.Public.NodeID},
			DNSNames:           []string{state.Public.NodeID + ".nodes.nucleus"},
			ExtraExtensions:    []pkix.Extension{{Id: requestBindingOID, Value: binding}},
			SignatureAlgorithm: x509.PureEd25519,
		}
		request.CSR, err = x509.CreateCertificateRequest(rand.Reader, template, key)
		if err != nil {
			return err
		}
		canonical, err := json.Marshal(request)
		if err != nil {
			return err
		}
		requestHash := hashHex(canonical)
		if state.Pending != nil && state.Pending.RequestHash != requestHash {
			if time.Now().Before(state.Pending.ExpiresAt) {
				return errors.New("another invitation is already pending; finish that join or wait for it to expire before starting a different one")
			}
			// An explicit new Join can replace expired enrollment pins, but
			// never a live pending invitation or the durable identity key.
			state.Pending = nil
		}
		if state.Pending == nil {
			// Only a digest of the secret-bearing request is retained.
			state.Pending = &pendingJoin{
				InvitationID: invite.InvitationID, RequestHash: requestHash,
				CACertificate: invite.CACertificate, OwnerCertificate: invite.OwnerCertificate,
				FabricID: invite.FabricID, OwnerID: invite.OwnerID, Endpoint: invite.Endpoint,
				ExpiresAt: invite.ExpiresAt,
			}
			if err := saveDisk(root, state); err != nil {
				return err
			}
		}
		result, err = json.MarshalIndent(request, "", "  ")
		return err
	})
	return result, err
}

// InspectRequest verifies a signed request without authorizing it or exposing its
// bearer token. Compare the returned NodeID with the joining computer before Accept.
func InspectRequest(data []byte) (Member, error) {
	request, _, id, err := checkedRequest(data)
	if err != nil {
		return Member{}, err
	}
	return Member{NodeID: id, Name: request.Name}, nil
}

func checkedRequest(data []byte) (joinRequest, *x509.CertificateRequest, string, error) {
	var request joinRequest
	fail := func(err error) (joinRequest, *x509.CertificateRequest, string, error) {
		return joinRequest{}, nil, "", err
	}
	if err := decode(data, &request); err != nil {
		return fail(fmt.Errorf("invalid join request: %w", err))
	}
	if request.Version != schemaVersion || !validInvitationID(request.InvitationID) ||
		!validID(request.FabricID) || !validID(request.OwnerID) || len(request.Secret) != 32 {
		return fail(errors.New("invalid join request version, identity, or token"))
	}
	if err := ValidateEndpoint(request.Endpoint); err != nil {
		return fail(err)
	}
	if err := validateName(request.Name); err != nil {
		return fail(err)
	}
	csr, err := x509.ParseCertificateRequest(request.CSR)
	if err != nil {
		return fail(fmt.Errorf("invalid CSR: %w", err))
	}
	if csr.PublicKeyAlgorithm != x509.Ed25519 || csr.SignatureAlgorithm != x509.PureEd25519 {
		return fail(errors.New("only Ed25519 signed join requests are supported"))
	}
	if err := csr.CheckSignature(); err != nil {
		return fail(fmt.Errorf("invalid CSR signature: %w", err))
	}
	nodeID, err := publicID(csr.PublicKey)
	if err != nil {
		return fail(err)
	}
	binding, err := bindingHash(request)
	if err != nil {
		return fail(err)
	}
	found := 0
	for _, extension := range csr.Extensions {
		if extension.Id.Equal(requestBindingOID) {
			found++
			if !bytes.Equal(extension.Value, binding) {
				return fail(errors.New("CSR does not bind this invitation and request"))
			}
		}
	}
	if found != 1 {
		return fail(errors.New("CSR must bind exactly one invitation context"))
	}
	return request, csr, nodeID, nil
}

// Accept authorizes one signed join request. Exact retries return the persisted
// grant; a consumed invitation can never authorize a different request.
func Accept(home string, data []byte) ([]byte, error) {
	request, csr, nodeID, err := checkedRequest(data)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	requestHash := hashHex(canonical)
	var result []byte
	err = withLock(home, func(root string) error {
		state, err := loadDisk(root)
		if err != nil {
			return err
		}
		if state.Public.OwnerID != state.Public.NodeID || len(state.CAKey) == 0 {
			return errors.New("only the fabric owner can accept join requests")
		}
		if request.FabricID != state.Public.FabricID || request.OwnerID != state.Public.OwnerID || request.Endpoint != state.Public.Endpoint {
			return errors.New("request is bound to a different fabric, owner, or endpoint")
		}
		record, ok := state.Invitations[request.InvitationID]
		if !ok {
			return errors.New("unknown invitation")
		}
		sum := sha256.Sum256(request.Secret)
		if subtle.ConstantTimeCompare(record.SecretHash, sum[:]) != 1 {
			return errors.New("invalid invitation token")
		}
		if record.AcceptedRequestHash != "" {
			if record.AcceptedRequestHash == requestHash && len(record.Grant) > 0 {
				if _, stillMember := state.Public.Members[nodeID]; !stillMember {
					return errors.New("this membership has been revoked")
				}
				result = append([]byte(nil), record.Grant...)
				return nil
			}
			return errors.New("invitation has already been consumed by another request")
		}
		if !time.Now().Before(record.ExpiresAt) {
			return errors.New("invitation has expired")
		}
		if nodeID == state.Public.NodeID {
			return errors.New("cannot enroll the owner as a new node")
		}
		if _, exists := state.Public.Members[nodeID]; exists {
			return errors.New("node identity is already a member")
		}
		if len(state.Public.Members) >= maxMembers {
			return errors.New("alpha membership limit reached")
		}
		ca, err := parseCA(state.Public.CACertificate)
		if err != nil {
			return err
		}
		caKey, err := parseKey(state.CAKey)
		if err != nil {
			return err
		}
		// CSR subject/SANs/extensions/key usages are intentionally not copied.
		certificate, err := issueLeaf(ca, caKey, csr.PublicKey.(ed25519.PublicKey), nodeID)
		if err != nil {
			return err
		}
		state.Public.Members[nodeID] = Member{NodeID: nodeID, Name: request.Name}
		document := grant{
			Version: schemaVersion, InvitationID: request.InvitationID,
			FabricID: state.Public.FabricID, OwnerID: state.Public.OwnerID, Endpoint: state.Public.Endpoint,
			NodeID: nodeID, RequestHash: requestHash, CACertificate: state.Public.CACertificate,
			OwnerCertificate: state.Public.Certificate, Certificate: certificate, Members: state.Public.Members,
		}
		unsigned, err := json.Marshal(document)
		if err != nil {
			return err
		}
		identity, err := parseKey(state.IdentityKey)
		if err != nil {
			return err
		}
		document.Signature = ed25519.Sign(identity, unsigned)
		result, err = json.MarshalIndent(document, "", "  ")
		if err != nil {
			return err
		}
		record.AcceptedRequestHash = requestHash
		record.Grant = append([]byte(nil), result...)
		state.Invitations[request.InvitationID] = record
		return saveDisk(root, state)
	})
	return result, err
}

// FinishJoin verifies the owner's signed grant against the exact pending
// invitation and CSR, then atomically enables this node's membership.
func FinishJoin(home string, data []byte) error {
	var document grant
	if err := decode(data, &document); err != nil {
		return fmt.Errorf("invalid membership grant: %w", err)
	}
	if document.Version != schemaVersion {
		return errors.New("unsupported membership grant version")
	}
	return withLock(home, func(root string) error {
		state, err := loadDisk(root)
		if err != nil {
			return err
		}
		if state.Pending == nil {
			if state.Public.FabricID != "" && state.CompletedGrantHash == hashHex(data) {
				return nil
			}
			return errors.New("no matching pending join request")
		}
		pending := state.Pending
		if document.InvitationID != pending.InvitationID || document.RequestHash != pending.RequestHash ||
			document.FabricID != pending.FabricID || document.OwnerID != pending.OwnerID ||
			document.Endpoint != pending.Endpoint || document.NodeID != state.Public.NodeID ||
			!bytes.Equal(document.CACertificate, pending.CACertificate) ||
			!bytes.Equal(document.OwnerCertificate, pending.OwnerCertificate) {
			return errors.New("grant does not match the pending invitation, endpoint, and identity")
		}
		ca, err := parseCA(pending.CACertificate)
		if err != nil {
			return err
		}
		owner, err := verifyLeaf(pending.OwnerCertificate, ca, pending.OwnerID)
		if err != nil {
			return err
		}
		signature := document.Signature
		document.Signature = nil
		unsigned, err := json.Marshal(document)
		if err != nil {
			return err
		}
		if !ed25519.Verify(owner.PublicKey.(ed25519.PublicKey), unsigned, signature) {
			return errors.New("invalid fabric owner's grant signature")
		}
		if _, err := verifyLeaf(document.Certificate, ca, state.Public.NodeID); err != nil {
			return err
		}
		if len(document.Members) < 2 || len(document.Members) > maxMembers {
			return errors.New("invalid membership set")
		}
		if member, ok := document.Members[state.Public.NodeID]; !ok || member.Name != state.Public.Name || member.NodeID != state.Public.NodeID {
			return errors.New("grant omits or changes this node's membership")
		}
		if member, ok := document.Members[pending.OwnerID]; !ok || member.NodeID != pending.OwnerID {
			return errors.New("grant omits the fabric owner")
		}
		for id, member := range document.Members {
			if !validID(id) || member.NodeID != id {
				return errors.New("invalid grant member identity")
			}
			if err := validateName(member.Name); err != nil {
				return err
			}
		}
		state.Public.FabricID = pending.FabricID
		state.Public.OwnerID = pending.OwnerID
		state.Public.Endpoint = pending.Endpoint
		state.Public.CACertificate = append([]byte(nil), pending.CACertificate...)
		state.Public.Certificate = append([]byte(nil), document.Certificate...)
		state.Public.Members = document.Members
		state.CompletedRequestHash = pending.RequestHash
		state.CompletedGrantHash = hashHex(data)
		state.Pending = nil
		return saveDisk(root, state)
	})
}

// Revoke removes a node from the owner's current allowlist. Existing grants
// cannot reinstate it; a new invitation and explicit acceptance are required.
func Revoke(home, nodeID string) error {
	if !validID(nodeID) {
		return errors.New("invalid node identifier")
	}
	return withLock(home, func(root string) error {
		state, err := loadDisk(root)
		if err != nil {
			return err
		}
		if state.Public.OwnerID != state.Public.NodeID || len(state.CAKey) == 0 {
			return errors.New("only the owner can revoke fabric membership")
		}
		if nodeID == state.Public.OwnerID {
			return errors.New("cannot revoke the fabric owner")
		}
		if _, ok := state.Public.Members[nodeID]; !ok {
			return errors.New("unknown fabric member")
		}
		delete(state.Public.Members, nodeID)
		return saveDisk(root, state)
	})
}

func parseInvitation(data []byte) (*invitation, error) {
	var document invitation
	if err := decode(data, &document); err != nil {
		return nil, fmt.Errorf("invalid invitation: %w", err)
	}
	if document.Version != schemaVersion || !validInvitationID(document.InvitationID) ||
		!validID(document.FabricID) || !validID(document.OwnerID) || len(document.Secret) != 32 {
		return nil, errors.New("invalid invitation identity, version, or token")
	}
	if err := ValidateEndpoint(document.Endpoint); err != nil {
		return nil, err
	}
	ca, err := parseCA(document.CACertificate)
	if err != nil {
		return nil, err
	}
	if hashHex(ca.Raw) != document.FabricID {
		return nil, errors.New("invitation fabric fingerprint does not match CA")
	}
	if id, err := publicID(ca.PublicKey); err != nil || id == document.OwnerID {
		return nil, errors.New("owner identity and CA signing key must be distinct")
	}
	owner, err := verifyLeaf(document.OwnerCertificate, ca, document.OwnerID)
	if err != nil {
		return nil, err
	}
	signature := document.Signature
	document.Signature = nil
	unsigned, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(owner.PublicKey.(ed25519.PublicKey), unsigned, signature) {
		return nil, errors.New("invalid invitation owner's signature")
	}
	document.Signature = signature
	if document.ExpiresAt.IsZero() || document.ExpiresAt.After(time.Now().Add(24*time.Hour+time.Minute)) {
		return nil, errors.New("invalid invitation expiration")
	}
	return &document, nil
}
func bindingHash(request joinRequest) ([]byte, error) {
	secretHash := sha256.Sum256(request.Secret)
	binding := requestBinding{
		InvitationID: request.InvitationID, FabricID: request.FabricID, OwnerID: request.OwnerID,
		Endpoint: request.Endpoint, Name: request.Name, SecretHash: secretHash[:],
	}
	data, err := json.Marshal(binding)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return digest[:], nil
}
func validInvitationID(value string) bool {
	if len(value) != 32 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == 16
}
