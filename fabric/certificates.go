package fabric

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"
)

func parseCA(data []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("invalid fabric CA: %w", err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok ||
		!cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!cert.MaxPathLenZero || cert.CheckSignatureFrom(cert) != nil {
		return nil, errors.New("fabric CA must be a self-signed, Ed25519, path-length-zero authority")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
		return nil, errors.New("fabric CA has expired or is not yet valid")
	}
	return cert, nil
}

func verifyLeaf(data []byte, ca *x509.Certificate, nodeID string) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}
	id, err := publicID(cert.PublicKey)
	if err != nil || id != nodeID {
		return nil, errors.New("certificate key does not match node identity")
	}
	if cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(cert.DNSNames) != 1 || cert.DNSNames[0] != nodeID+".nodes.nucleus" ||
		len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 ||
		len(cert.ExtKeyUsage) != 2 || len(cert.UnknownExtKeyUsage) > 0 {
		return nil, errors.New("membership certificate has unexpected constraints")
	}
	client, server := false, false
	for _, usage := range cert.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			client = true
		}
		if usage == x509.ExtKeyUsageServerAuth {
			server = true
		}
	}
	if !client || !server {
		return nil, errors.New("membership certificate requires client and server authentication")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: nodeID + ".nodes.nucleus", KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return nil, fmt.Errorf("invalid membership certificate: %w", err)
		}
	}
	return cert, nil
}

func createCA(key ed25519.PrivateKey) ([]byte, error) {
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Nucleus private fabric authority"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	return x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
}

func issueLeaf(ca *x509.Certificate, caKey ed25519.PrivateKey, public ed25519.PublicKey, nodeID string) ([]byte, error) {
	derived, err := publicID(public)
	if err != nil || derived != nodeID {
		return nil, errors.New("node identity mismatch")
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: nodeID},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		BasicConstraintsValid: true, IsCA: false,
		DNSNames:    []string{nodeID + ".nodes.nucleus"},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	return x509.CreateCertificate(rand.Reader, template, ca, public, caKey)
}
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}
func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }
