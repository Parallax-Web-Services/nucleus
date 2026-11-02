package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

// ServerTLS returns a TLS-1.3-only configuration requiring a valid fabric client
// certificate and current allowlist membership on every new connection.
func ServerTLS(home string) (*tls.Config, error) {
	state, identity, ca, err := tlsMaterial(home)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{state.Certificate}, PrivateKey: identity}},
		ClientCAs:    roots, ClientAuth: tls.RequireAndVerifyClientCert,
		SessionTicketsDisabled: true,
	}
	config.VerifyConnection = membershipVerifier(home, state.FabricID, state.CACertificate, "")
	return config, nil
}

// ClientTLS verifies the pinned fabric CA and owner's logical node DNS identity;
// the private IPv4 endpoint is deliberately separate from certificate identity.
func ClientTLS(home string) (*tls.Config, error) {
	state, identity, ca, err := tlsMaterial(home)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{state.Certificate}, PrivateKey: identity}},
		RootCAs:      roots, ServerName: state.OwnerID + ".nodes.nucleus",
		SessionTicketsDisabled: true, ClientSessionCache: nil,
	}
	config.VerifyConnection = membershipVerifier(home, state.FabricID, state.CACertificate, state.OwnerID)
	return config, nil
}

func tlsMaterial(home string) (*State, ed25519.PrivateKey, *x509.Certificate, error) {
	root, err := checkedHome(home, false)
	if err != nil {
		return nil, nil, nil, err
	}
	disk, err := loadDisk(root)
	if err != nil {
		return nil, nil, nil, err
	}
	if disk.Public.FabricID == "" {
		return nil, nil, nil, errors.New("node has no accepted fabric membership")
	}
	identity, err := parseKey(disk.IdentityKey)
	if err != nil {
		return nil, nil, nil, err
	}
	ca, err := parseCA(disk.Public.CACertificate)
	if err != nil {
		return nil, nil, nil, err
	}
	return &disk.Public, identity, ca, nil
}

func membershipVerifier(home, fabricID string, caDER []byte, expectedNode string) func(tls.ConnectionState) error {
	return func(connection tls.ConnectionState) error {
		if connection.Version != tls.VersionTLS13 || len(connection.PeerCertificates) == 0 || len(connection.VerifiedChains) == 0 {
			return errors.New("verified TLS 1.3 peer certificate is required")
		}
		peer := connection.PeerCertificates[0]
		id, err := publicID(peer.PublicKey)
		if err != nil {
			return err
		}
		if expectedNode != "" && id != expectedNode {
			return errors.New("TLS server is not the fabric owner")
		}
		current, err := Load(home)
		if err != nil {
			return fmt.Errorf("load current membership: %w", err)
		}
		if current.FabricID != fabricID || !bytes.Equal(current.CACertificate, caDER) {
			return errors.New("fabric trust changed; restart this listener/client")
		}
		if member, ok := current.Members[id]; !ok || member.NodeID != id {
			return errors.New("TLS peer is not an active fabric member")
		}
		ca, err := parseCA(caDER)
		if err != nil {
			return err
		}
		_, err = verifyLeaf(peer.Raw, ca, id)
		return err
	}
}
