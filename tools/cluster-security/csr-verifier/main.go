// Command nebula-csr-verifier evaluates a projected CSR against independent node
// enrollment and fresh authenticated API observations. It cannot approve a CSR.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

const (
	maxInputBytes   = 256 << 10
	maxPEMBytes     = 64 << 10
	maxDERBytes     = 48 << 10
	credentialIDKey = "authentication.kubernetes.io/credential-id"
)

type Input struct {
	SchemaVersion int        `json:"schema_version"`
	PolicyKind    string     `json:"policy_kind"`
	CSR           CSR        `json:"csr"`
	Enrollment    Enrollment `json:"enrollment"`
	CurrentNode   Node       `json:"current_node"`
}
type CSR struct {
	Metadata Metadata `json:"metadata"`
	Spec     Spec     `json:"spec"`
}
type Metadata struct {
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
}
type Spec struct {
	RequestBase64     string              `json:"request_base64"`
	SignerName        string              `json:"signer_name"`
	Usages            []string            `json:"usages"`
	Username          string              `json:"username"`
	UID               string              `json:"uid"`
	Groups            []string            `json:"groups"`
	Extra             map[string][]string `json:"extra"`
	ExpirationSeconds *int64              `json:"expiration_seconds,omitempty"`
}
type Enrollment struct {
	NodeName           string              `json:"node_name"`
	NodeUID            string              `json:"node_uid"`
	AllowedDNSNames    []string            `json:"allowed_dns_names"`
	AllowedIPAddresses []string            `json:"allowed_ip_addresses"`
	AllowedAuthUID     string              `json:"allowed_auth_uid"`
	AllowedAuthExtra   map[string][]string `json:"allowed_auth_extra"`
}
type Node struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}
type Decision struct {
	SchemaVersion int      `json:"schema_version"`
	Decision      string   `json:"decision"`
	Code          string   `json:"code"`
	Binding       *Binding `json:"binding,omitempty"`
}
type Binding struct {
	PolicyKind       string `json:"policy_kind"`
	CSRName          string `json:"csr_name"`
	CSRUID           string `json:"csr_uid"`
	ResourceVersion  string `json:"resource_version"`
	NodeName         string `json:"node_name"`
	NodeUID          string `json:"node_uid"`
	RequestDERSHA256 string `json:"request_der_sha256"`
	RequestPEMSHA256 string `json:"request_pem_sha256"`
	SPKISHA256       string `json:"spki_sha256"`
	InputSHA256      string `json:"input_sha256"`
}

func reject(code string) Decision { return Decision{SchemaVersion: 1, Decision: "reject", Code: code} }
func digest(b []byte) string      { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Reject duplicate keys, explicit nulls and ambiguous trailing JSON before typed
// decoding. This is a local protocol, not a permissive Kubernetes object parser.
func checkJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return errors.New("json_depth")
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		if tok == nil {
			return errors.New("json_null")
		}
		delimiter, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				t, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := t.(string)
				if !ok || seen[key] {
					return errors.New("json_duplicate")
				}
				seen[key] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("json_object")
			}
		case '[':
			for d.More() {
				if e := walk(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("json_array")
			}
		default:
			return errors.New("json_delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("json_trailing")
	}
	return nil
}
func shape(raw json.RawMessage, required []string, optional []string) (map[string]json.RawMessage, error) {
	var v map[string]json.RawMessage
	if err := json.Unmarshal(raw, &v); err != nil || v == nil {
		return nil, errors.New("shape_object")
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := v[k]; !ok {
			return nil, errors.New("shape_missing")
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range v {
		if !allowed[k] {
			return nil, errors.New("shape_unknown")
		}
	}
	return v, nil
}
func DecodeInput(raw []byte) (Input, error) {
	var in Input
	if len(raw) == 0 || len(raw) > maxInputBytes {
		return in, errors.New("input_size")
	}
	if err := checkJSON(raw); err != nil {
		return in, err
	}
	root, err := shape(raw, []string{"schema_version", "policy_kind", "csr", "enrollment", "current_node"}, nil)
	if err != nil {
		return in, err
	}
	csr, err := shape(root["csr"], []string{"metadata", "spec"}, nil)
	if err != nil {
		return in, err
	}
	if _, err = shape(csr["metadata"], []string{"name", "uid", "resource_version"}, nil); err != nil {
		return in, err
	}
	if _, err = shape(csr["spec"], []string{"request_base64", "signer_name", "usages", "username", "uid", "groups", "extra"}, []string{"expiration_seconds"}); err != nil {
		return in, err
	}
	if _, err = shape(root["enrollment"], []string{"node_name", "node_uid", "allowed_dns_names", "allowed_ip_addresses", "allowed_auth_uid", "allowed_auth_extra"}, nil); err != nil {
		return in, err
	}
	if _, err = shape(root["current_node"], []string{"name", "uid"}, nil); err != nil {
		return in, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	err = d.Decode(&in)
	return in, err
}

var (
	uuidPattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	labelPattern      = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	credentialPattern = regexp.MustCompile(`^X509SHA256=[0-9a-f]{64}$`)
)

func dnsName(s string) bool {
	if len(s) == 0 || len(s) > 253 || strings.HasSuffix(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) > 63 || !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}
func uuidValue(s string) bool {
	return uuidPattern.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}
func opaque(s string, max int, empty bool) bool {
	if len(s) > max || (!empty && s == "") {
		return false
	}
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
func uniqueSet(values []string, max int) ([]string, bool) {
	if values == nil || len(values) > max {
		return nil, false
	}
	out := append([]string{}, values...)
	sort.Strings(out)
	for i, v := range out {
		if v == "" || (i > 0 && out[i-1] == v) {
			return nil, false
		}
	}
	return out, true
}
func equalSet(a, b []string, max int) bool {
	x, ok := uniqueSet(a, max)
	if !ok {
		return false
	}
	y, ok := uniqueSet(b, max)
	return ok && reflect.DeepEqual(x, y)
}
func canonicalIPs(values []string) ([]string, bool) {
	if values == nil || len(values) > 16 {
		return nil, false
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		a, err := netip.ParseAddr(v)
		if err != nil || a.Zone() != "" || a.Is4In6() || a.String() != v || !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			return nil, false
		}
		out = append(out, a.String())
	}
	return uniqueSet(out, 16)
}
func canonicalDNS(values []string) ([]string, bool) {
	if values == nil || len(values) > 32 {
		return nil, false
	}
	for _, v := range values {
		if !dnsName(v) {
			return nil, false
		}
	}
	return uniqueSet(values, 32)
}
func exactExtra(actual, expected map[string][]string) bool {
	if len(actual) != 1 || len(expected) != 1 {
		return false
	}
	a, aok := actual[credentialIDKey]
	e, eok := expected[credentialIDKey]
	return aok && eok && len(a) == 1 && len(e) == 1 && credentialPattern.MatchString(e[0]) && a[0] == e[0]
}

func oneDER(raw []byte, class, tag int, compound bool) (asn1.RawValue, error) {
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &v)
	if err != nil || len(rest) != 0 || v.Class != class || v.Tag != tag || v.IsCompound != compound {
		return v, errors.New("der_type")
	}
	return v, nil
}
func children(v asn1.RawValue, max int) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	rest := v.Bytes
	for len(rest) > 0 {
		if len(out) >= max {
			return nil, errors.New("der_children")
		}
		var child asn1.RawValue
		next, err := asn1.Unmarshal(rest, &child)
		if err != nil || len(next) >= len(rest) {
			return nil, errors.New("der_child")
		}
		out = append(out, child)
		rest = next
	}
	return out, nil
}
func isType(v asn1.RawValue, class, tag int, compound bool) bool {
	return v.Class == class && v.Tag == tag && v.IsCompound == compound
}
func oidValue(v asn1.RawValue) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	if !isType(v, 0, 6, false) {
		return nil, errors.New("oid_type")
	}
	rest, err := asn1.Unmarshal(v.FullBytes, &oid)
	if err != nil || len(rest) > 0 {
		return nil, errors.New("oid")
	}
	return oid, nil
}

var (
	oidCN               = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidO                = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidSAN              = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
)

func rawSubject(v asn1.RawValue, expectedCN string) bool {
	if !isType(v, 0, 16, true) {
		return false
	}
	rdns, err := children(v, 3)
	if err != nil || len(rdns) != 2 {
		return false
	}
	seen := map[string]bool{}
	for _, rdn := range rdns {
		if !isType(rdn, 0, 17, true) {
			return false
		}
		attrs, err := children(rdn, 2)
		if err != nil || len(attrs) != 1 || !isType(attrs[0], 0, 16, true) {
			return false
		}
		fields, err := children(attrs[0], 3)
		if err != nil || len(fields) != 2 {
			return false
		}
		oid, err := oidValue(fields[0])
		if err != nil {
			return false
		}
		key := oid.String()
		if seen[key] {
			return false
		}
		seen[key] = true
		value := fields[1]
		if value.Class != 0 || value.IsCompound || (value.Tag != 12 && value.Tag != 19) {
			return false
		}
		want := ""
		switch {
		case oid.Equal(oidCN):
			want = expectedCN
		case oid.Equal(oidO):
			want = "system:nodes"
		default:
			return false
		}
		if string(value.Bytes) != want {
			return false
		}
	}
	return seen[oidCN.String()] && seen[oidO.String()]
}
func rawSAN(raw []byte) ([]string, []string, error) {
	seq, err := oneDER(raw, 0, 16, true)
	if err != nil {
		return nil, nil, err
	}
	names, err := children(seq, 48)
	if err != nil || len(names) == 0 {
		return nil, nil, errors.New("san_count")
	}
	dns := []string{}
	ips := []string{}
	for _, name := range names {
		if name.Class != 2 || name.IsCompound {
			return nil, nil, errors.New("san_type")
		}
		switch name.Tag {
		case 2:
			v := string(name.Bytes)
			if !dnsName(v) {
				return nil, nil, errors.New("san_dns")
			}
			dns = append(dns, v)
		case 7:
			if len(name.Bytes) != 4 && len(name.Bytes) != 16 {
				return nil, nil, errors.New("san_ip")
			}
			addr, ok := netip.AddrFromSlice(name.Bytes)
			if !ok || addr.Is4In6() {
				return nil, nil, errors.New("san_ip")
			}
			ips = append(ips, addr.String())
		default:
			return nil, nil, errors.New("san_forbidden_general_name")
		}
	}
	if _, ok := canonicalDNS(dns); !ok {
		return nil, nil, errors.New("san_dns")
	}
	if _, ok := canonicalIPs(ips); !ok {
		return nil, nil, errors.New("san_ip")
	}
	return dns, ips, nil
}
func rawAttributes(v asn1.RawValue, serving bool) ([]string, []string, error) {
	if !isType(v, 2, 0, true) {
		return nil, nil, errors.New("attributes_type")
	}
	attrs, err := children(v, 2)
	if err != nil {
		return nil, nil, err
	}
	if !serving {
		if len(attrs) != 0 {
			return nil, nil, errors.New("client_extensions_forbidden")
		}
		return []string{}, []string{}, nil
	}
	if len(attrs) != 1 || !isType(attrs[0], 0, 16, true) {
		return nil, nil, errors.New("extension_attribute_required")
	}
	fields, err := children(attrs[0], 3)
	if err != nil || len(fields) != 2 {
		return nil, nil, errors.New("attribute_fields")
	}
	oid, err := oidValue(fields[0])
	if err != nil || !oid.Equal(oidExtensionRequest) || !isType(fields[1], 0, 17, true) {
		return nil, nil, errors.New("attribute_oid")
	}
	values, err := children(fields[1], 2)
	if err != nil || len(values) != 1 || !isType(values[0], 0, 16, true) {
		return nil, nil, errors.New("attribute_values")
	}
	extensions, err := children(values[0], 2)
	if err != nil || len(extensions) != 1 || !isType(extensions[0], 0, 16, true) {
		return nil, nil, errors.New("extension_count")
	}
	extension, err := children(extensions[0], 4)
	if err != nil || len(extension) != 2 {
		return nil, nil, errors.New("extension_fields")
	}
	oid, err = oidValue(extension[0])
	if err != nil || !oid.Equal(oidSAN) || !isType(extension[1], 0, 4, false) {
		return nil, nil, errors.New("only_noncritical_san_allowed")
	}
	return rawSAN(extension[1].Bytes)
}
func rawRequest(der []byte) ([]asn1.RawValue, asn1.RawValue, error) {
	outer, err := oneDER(der, 0, 16, true)
	if err != nil {
		return nil, asn1.RawValue{}, err
	}
	parts, err := children(outer, 4)
	if err != nil || len(parts) != 3 || !isType(parts[0], 0, 16, true) || !isType(parts[1], 0, 16, true) || !isType(parts[2], 0, 3, false) {
		return nil, asn1.RawValue{}, errors.New("request_structure")
	}
	tbs, err := children(parts[0], 5)
	if err != nil || len(tbs) != 4 || !bytes.Equal(tbs[0].FullBytes, []byte{2, 1, 0}) || !isType(tbs[1], 0, 16, true) || !isType(tbs[2], 0, 16, true) || !isType(tbs[3], 2, 0, true) {
		return nil, asn1.RawValue{}, errors.New("request_info_structure")
	}
	var signature asn1.BitString
	rest, err := asn1.Unmarshal(parts[2].FullBytes, &signature)
	if err != nil || len(rest) != 0 || signature.BitLength != len(signature.Bytes)*8 || len(signature.Bytes) == 0 {
		return nil, asn1.RawValue{}, errors.New("signature_bitstring")
	}
	return tbs, parts[1], nil
}
func keyProfile(csr *x509.CertificateRequest, spki asn1.RawValue) (string, bool) {
	kind := ""
	switch key := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) != 1 || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E != 65537 {
			return "", false
		}
		kind = "rsa"
	case *ecdsa.PublicKey:
		if key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521() {
			return "", false
		}
		if key.X == nil || key.Y == nil || !key.Curve.IsOnCurve(key.X, key.Y) {
			return "", false
		}
		kind = "ecdsa"
	default:
		return "", false
	}
	canonical, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	return kind, err == nil && bytes.Equal(canonical, spki.FullBytes)
}

type pssParameters struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength   int                      `asn1:"explicit,tag:2"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

func signatureAlgorithm(csr *x509.CertificateRequest, algorithm asn1.RawValue, keyKind string) bool {
	ai := pkix.AlgorithmIdentifier{}
	var hashOID asn1.ObjectIdentifier
	hashSize := 0
	switch csr.SignatureAlgorithm {
	case x509.SHA256WithRSA:
		if keyKind != "rsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
		ai.Parameters = asn1.NullRawValue
	case x509.SHA384WithRSA:
		if keyKind != "rsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
		ai.Parameters = asn1.NullRawValue
	case x509.SHA512WithRSA:
		if keyKind != "rsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
		ai.Parameters = asn1.NullRawValue
	case x509.ECDSAWithSHA256:
		if keyKind != "ecdsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	case x509.ECDSAWithSHA384:
		if keyKind != "ecdsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	case x509.ECDSAWithSHA512:
		if keyKind != "ecdsa" {
			return false
		}
		ai.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	case x509.SHA256WithRSAPSS:
		if keyKind != "rsa" {
			return false
		}
		hashOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
		hashSize = 32
	case x509.SHA384WithRSAPSS:
		if keyKind != "rsa" {
			return false
		}
		hashOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
		hashSize = 48
	case x509.SHA512WithRSAPSS:
		if keyKind != "rsa" {
			return false
		}
		hashOID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
		hashSize = 64
	default:
		return false
	}
	if hashSize != 0 {
		hashAI := pkix.AlgorithmIdentifier{Algorithm: hashOID, Parameters: asn1.NullRawValue}
		hashDER, err := asn1.Marshal(hashAI)
		if err != nil {
			return false
		}
		params := pssParameters{Hash: hashAI, MGF: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: hashDER}}, SaltLength: hashSize, TrailerField: 1}
		der, err := asn1.Marshal(params)
		if err != nil {
			return false
		}
		ai = pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Parameters: asn1.RawValue{FullBytes: der}}
	}
	der, err := asn1.Marshal(ai)
	return err == nil && bytes.Equal(der, algorithm.FullBytes)
}
func parsePEM(encoded string) ([]byte, []byte, bool) {
	if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(maxPEMBytes) {
		return nil, nil, false
	}
	pemBytes, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(pemBytes) != encoded || len(pemBytes) > maxPEMBytes {
		return nil, nil, false
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(rest) != 0 || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > maxDERBytes {
		return nil, nil, false
	}
	if !bytes.Equal(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: block.Bytes}), pemBytes) {
		return nil, nil, false
	}
	return pemBytes, block.Bytes, true
}

func Evaluate(raw []byte) Decision {
	in, err := DecodeInput(raw)
	if err != nil {
		return reject("input_invalid")
	}
	return Verify(in, digest(raw))
}
func Verify(in Input, inputHash string) Decision {
	if in.SchemaVersion != 1 {
		return reject("schema_unsupported")
	}
	serving := in.PolicyKind == "serving"
	if !serving && in.PolicyKind != "selfnodeclient-renewal" {
		return reject("policy_unsupported")
	}
	m := in.CSR.Metadata
	e := in.Enrollment
	s := in.CSR.Spec
	if !dnsName(m.Name) || !uuidValue(m.UID) || !opaque(m.ResourceVersion, 128, false) {
		return reject("metadata_invalid")
	}
	if !dnsName(e.NodeName) || !uuidValue(e.NodeUID) || !opaque(e.AllowedAuthUID, 128, true) || in.CurrentNode.Name != e.NodeName || in.CurrentNode.UID != e.NodeUID {
		return reject("enrollment_binding_invalid")
	}
	dns, ok := canonicalDNS(e.AllowedDNSNames)
	if !ok {
		return reject("enrollment_names_invalid")
	}
	ips, ok := canonicalIPs(e.AllowedIPAddresses)
	if !ok {
		return reject("enrollment_names_invalid")
	}
	if serving && len(dns)+len(ips) == 0 {
		return reject("enrollment_names_invalid")
	}
	expectedCN := "system:node:" + e.NodeName
	if s.Username != expectedCN || s.UID != e.AllowedAuthUID {
		return reject("authenticated_identity_mismatch")
	}
	if !equalSet(s.Groups, []string{"system:nodes", "system:authenticated"}, 2) {
		return reject("authenticated_groups_invalid")
	}
	if !exactExtra(s.Extra, e.AllowedAuthExtra) {
		return reject("authenticated_extra_mismatch")
	}
	signer := "kubernetes.io/kube-apiserver-client-kubelet"
	usage := "client auth"
	if serving {
		signer = "kubernetes.io/kubelet-serving"
		usage = "server auth"
	}
	if s.SignerName != signer {
		return reject("signer_mismatch")
	}
	if s.ExpirationSeconds != nil && (*s.ExpirationSeconds < 600 || *s.ExpirationSeconds > 31536000) {
		return reject("expiration_invalid")
	}
	pemBytes, der, ok := parsePEM(s.RequestBase64)
	if !ok {
		return reject("request_encoding_invalid")
	}
	tbs, algorithm, err := rawRequest(der)
	if err != nil {
		return reject("request_asn1_invalid")
	}
	if !rawSubject(tbs[1], expectedCN) {
		return reject("request_subject_invalid")
	}
	rawDNS, rawIPs, err := rawAttributes(tbs[3], serving)
	if err != nil {
		return reject("request_extensions_invalid")
	}
	if serving && (!equalSet(rawDNS, dns, 32) || !equalSet(rawIPs, ips, 16)) {
		return reject("request_names_mismatch")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return reject("request_parse_invalid")
	}
	kind, ok := keyProfile(csr, tbs[2])
	if !ok {
		return reject("request_key_profile_invalid")
	}
	usages := []string{"digital signature", usage}
	withEnc := append(append([]string{}, usages...), "key encipherment")
	if !equalSet(s.Usages, usages, 3) && !(kind == "rsa" && equalSet(s.Usages, withEnc, 3)) {
		return reject("request_usages_invalid")
	}
	if !signatureAlgorithm(csr, algorithm, kind) {
		return reject("request_signature_algorithm_invalid")
	}
	if err := csr.CheckSignature(); err != nil {
		return reject("request_signature_invalid")
	}
	parsedIPs := []string{}
	for _, ip := range csr.IPAddresses {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			return reject("request_parser_disagreement")
		}
		parsedIPs = append(parsedIPs, a.Unmap().String())
	}
	if !equalSet(append([]string{}, csr.DNSNames...), rawDNS, 32) || !equalSet(parsedIPs, rawIPs, 16) || len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		return reject("request_parser_disagreement")
	}
	if !serving && (len(csr.Extensions) != 0 || len(csr.DNSNames) != 0 || len(csr.IPAddresses) != 0) {
		return reject("request_extensions_invalid")
	}
	b := &Binding{PolicyKind: in.PolicyKind, CSRName: m.Name, CSRUID: m.UID, ResourceVersion: m.ResourceVersion, NodeName: e.NodeName, NodeUID: e.NodeUID, RequestDERSHA256: digest(der), RequestPEMSHA256: digest(pemBytes), SPKISHA256: digest(csr.RawSubjectPublicKeyInfo), InputSHA256: inputHash}
	return Decision{SchemaVersion: 1, Decision: "valid", Code: "csr_policy_valid", Binding: b}
}
func run(r io.Reader, w io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	decision := reject("input_read_failed")
	if err == nil {
		if len(raw) > maxInputBytes {
			decision = reject("input_too_large")
		} else {
			decision = Evaluate(raw)
		}
	}
	if err := json.NewEncoder(w).Encode(decision); err != nil {
		return 2
	}
	if decision.Decision != "valid" {
		return 2
	}
	return 0
}
func main() { os.Exit(run(os.Stdin, os.Stdout)) }
