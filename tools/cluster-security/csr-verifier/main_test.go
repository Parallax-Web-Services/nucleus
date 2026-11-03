package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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
	"math/big"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
)

var testRSA *rsa.PrivateKey
var testEC *ecdsa.PrivateKey

func TestMain(m *testing.M) {
	var err error
	testRSA, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("synthetic RSA fixture setup")
	}
	testEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("synthetic ECDSA fixture setup")
	}
	os.Exit(m.Run())
}
func encodeCSR(der []byte) string {
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
func fixture(t testing.TB, key crypto.Signer, kind string, change func(*x509.CertificateRequest)) Input {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "system:node:node-a", Organization: []string{"system:nodes"}}}
	if kind == "serving" {
		template.DNSNames = []string{"node-a"}
		template.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")}
	}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("synthetic CSR setup: %v", err)
	}
	usage := "client auth"
	signer := "kubernetes.io/kube-apiserver-client-kubelet"
	if kind == "serving" {
		usage = "server auth"
		signer = "kubernetes.io/kubelet-serving"
	}
	usages := []string{"digital signature", usage}
	if _, ok := key.(*rsa.PrivateKey); ok {
		usages = append(usages, "key encipherment")
	}
	extra := map[string][]string{credentialIDKey: {"X509SHA256=" + strings.Repeat("a", 64)}}
	return Input{SchemaVersion: 1, PolicyKind: kind, CSR: CSR{Metadata: Metadata{Name: "csr-synthetic-1", UID: "11111111-1111-4111-8111-111111111111", ResourceVersion: "opaque-rv:42"}, Spec: Spec{RequestBase64: encodeCSR(der), SignerName: signer, Usages: usages, Username: "system:node:node-a", UID: "", Groups: []string{"system:nodes", "system:authenticated"}, Extra: extra}}, Enrollment: Enrollment{NodeName: "node-a", NodeUID: "22222222-2222-4222-8222-222222222222", AllowedDNSNames: []string{"node-a"}, AllowedIPAddresses: []string{"192.0.2.10"}, AllowedAuthUID: "", AllowedAuthExtra: map[string][]string{credentialIDKey: {extra[credentialIDKey][0]}}}, CurrentNode: Node{Name: "node-a", UID: "22222222-2222-4222-8222-222222222222"}}
}
func inputBytes(t testing.TB, in Input) []byte {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func copyInput(t testing.TB, in Input) Input {
	t.Helper()
	var out Input
	if err := json.Unmarshal(inputBytes(t, in), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func valid(t testing.TB, in Input) Decision {
	t.Helper()
	d := Evaluate(inputBytes(t, in))
	if d.Decision != "valid" || d.Code != "csr_policy_valid" || d.Binding == nil {
		t.Fatalf("expected valid, got %+v", d)
	}
	return d
}
func invalid(t testing.TB, in Input) Decision {
	t.Helper()
	d := Evaluate(inputBytes(t, in))
	if d.Decision != "reject" || d.Binding != nil {
		t.Fatalf("expected rejection, got %+v", d)
	}
	return d
}
func derOf(t testing.TB, in Input) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(in.CSR.Spec.RequestBase64)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode(b)
	return p.Bytes
}
func wrap(tag byte, body []byte) []byte {
	out := []byte{tag}
	n := len(body)
	if n < 128 {
		out = append(out, byte(n))
	} else {
		var length []byte
		for v := n; v > 0; v >>= 8 {
			length = append([]byte{byte(v)}, length...)
		}
		out = append(out, 0x80|byte(len(length)))
		out = append(out, length...)
	}
	return append(out, body...)
}
func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func testChildren(t testing.TB, raw []byte) []asn1.RawValue {
	t.Helper()
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(raw, &outer)
	if err != nil || len(rest) != 0 {
		t.Fatal("test DER outer")
	}
	var out []asn1.RawValue
	rest = outer.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			t.Fatal("test DER child")
		}
		out = append(out, v)
	}
	return out
}
func asn(t testing.TB, v any) []byte {
	t.Helper()
	b, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func resign(t testing.TB, in Input, change func([]asn1.RawValue) []asn1.RawValue) Input {
	t.Helper()
	outer := testChildren(t, derOf(t, in))
	parts := change(testChildren(t, outer[0].FullBytes))
	var body []byte
	for _, p := range parts {
		body = append(body, p.FullBytes...)
	}
	tbs := wrap(0x30, body)
	h := sha256.Sum256(tbs)
	sig, err := testEC.Sign(rand.Reader, h[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	in.CSR.Spec.RequestBase64 = encodeCSR(wrap(0x30, join(tbs, outer[1].FullBytes, asn(t, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}))))
	return in
}
func rawValue(t testing.TB, b []byte) asn1.RawValue {
	t.Helper()
	var v asn1.RawValue
	rest, err := asn1.Unmarshal(b, &v)
	if err != nil || len(rest) > 0 {
		t.Fatal("synthetic raw TLV")
	}
	return v
}
func sanExtension(t testing.TB, raw []byte) pkix.Extension {
	return pkix.Extension{Id: oidSAN, Value: raw}
}

func TestAcceptedServingAlgorithmsAndBindings(t *testing.T) {
	cases := []struct {
		name      string
		key       crypto.Signer
		algorithm x509.SignatureAlgorithm
	}{{"rsa256", testRSA, x509.SHA256WithRSA}, {"rsa384", testRSA, x509.SHA384WithRSA}, {"rsa512", testRSA, x509.SHA512WithRSA}, {"pss256", testRSA, x509.SHA256WithRSAPSS}, {"pss384", testRSA, x509.SHA384WithRSAPSS}, {"pss512", testRSA, x509.SHA512WithRSAPSS}, {"p256", testEC, x509.ECDSAWithSHA256}}
	for _, curve := range []elliptic.Curve{elliptic.P384(), elliptic.P521()} {
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct {
			name      string
			key       crypto.Signer
			algorithm x509.SignatureAlgorithm
		}{curve.Params().Name, key, 0})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture(t, tc.key, "serving", func(c *x509.CertificateRequest) { c.SignatureAlgorithm = tc.algorithm })
			d := valid(t, in)
			raw := inputBytes(t, in)
			der := derOf(t, in)
			csr, err := x509.ParseCertificateRequest(der)
			if err != nil {
				t.Fatal(err)
			}
			pemBytes, _ := base64.StdEncoding.DecodeString(in.CSR.Spec.RequestBase64)
			hash := func(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
			if d.Binding.RequestDERSHA256 != hash(der) || d.Binding.SPKISHA256 != hash(csr.RawSubjectPublicKeyInfo) || d.Binding.RequestPEMSHA256 != hash(pemBytes) || d.Binding.InputSHA256 != hash(raw) {
				t.Fatal("public binding differs")
			}
			if d.Binding.CSRUID != in.CSR.Metadata.UID || d.Binding.ResourceVersion != in.CSR.Metadata.ResourceVersion || d.Binding.NodeUID != in.CurrentNode.UID {
				t.Fatal("CAS binding differs")
			}
		})
	}
}
func TestAcceptedExactSelfNodeRenewal(t *testing.T) {
	for _, key := range []crypto.Signer{testRSA, testEC} {
		in := fixture(t, key, "selfnodeclient-renewal", nil)
		valid(t, in)
	}
}
func TestAcceptedUsageWithoutRSAEncipherment(t *testing.T) {
	in := fixture(t, testRSA, "serving", nil)
	in.CSR.Spec.Usages = []string{"server auth", "digital signature"}
	valid(t, in)
}
func TestExactIndependentEnrollmentAndIdentity(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	changes := map[string]func(*Input){"currentuid": func(i *Input) { i.CurrentNode.UID = "33333333-3333-4333-8333-333333333333" }, "currentname": func(i *Input) { i.CurrentNode.Name = "node-b" }, "username": func(i *Input) { i.CSR.Spec.Username = "system:node:node-b" }, "bootstrap": func(i *Input) {
		i.CSR.Spec.Username = "system:bootstrap:abcdef"
		i.CSR.Spec.Groups = []string{"system:bootstrappers", "system:authenticated"}
	}, "authuid": func(i *Input) { i.CSR.Spec.UID = "unexpected-user-uid" }, "masters": func(i *Input) { i.CSR.Spec.Groups = append(i.CSR.Spec.Groups, "system:masters") }, "duplicategroups": func(i *Input) { i.CSR.Spec.Groups = []string{"system:nodes", "system:nodes"} }, "nilgroups": func(i *Input) { i.CSR.Spec.Groups = []string{} }, "enrolleddns": func(i *Input) { i.Enrollment.AllowedDNSNames = []string{"node-b"} }, "enrolledip": func(i *Input) { i.Enrollment.AllowedIPAddresses = []string{"192.0.2.11"} }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) { in := copyInput(t, base); change(&in); invalid(t, in) })
	}
}
func TestAuthExtraIsCurrentCertificateBoundNotArbitrary(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	changes := map[string]func(*Input){"missing": func(i *Input) { i.CSR.Spec.Extra = map[string][]string{} }, "unboundempty": func(i *Input) {
		i.CSR.Spec.Extra = map[string][]string{}
		i.Enrollment.AllowedAuthExtra = map[string][]string{}
	}, "oldcredential": func(i *Input) { i.CSR.Spec.Extra[credentialIDKey] = []string{"X509SHA256=" + strings.Repeat("b", 64)} }, "arbitrary": func(i *Input) {
		i.CSR.Spec.Extra["custom/role"] = []string{"admin"}
		i.Enrollment.AllowedAuthExtra["custom/role"] = []string{"admin"}
	}, "multiple": func(i *Input) {
		i.CSR.Spec.Extra[credentialIDKey] = append(i.CSR.Spec.Extra[credentialIDKey], i.CSR.Spec.Extra[credentialIDKey][0])
	}, "uppercase": func(i *Input) {
		v := "X509SHA256=" + strings.Repeat("A", 64)
		i.CSR.Spec.Extra[credentialIDKey] = []string{v}
		i.Enrollment.AllowedAuthExtra[credentialIDKey] = []string{v}
	}}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) { in := copyInput(t, base); change(&in); invalid(t, in) })
	}
}
func TestRefreshOfValidatedCredentialAllowsLegitimateRotation(t *testing.T) {
	in := fixture(t, testEC, "serving", nil)
	v := "X509SHA256=" + strings.Repeat("b", 64)
	in.CSR.Spec.Extra[credentialIDKey] = []string{v}
	in.Enrollment.AllowedAuthExtra[credentialIDKey] = []string{v}
	valid(t, in)
}
func TestSignerAndUsagesAreSeparatePolicies(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	for _, change := range []func(*Input){func(i *Input) { i.CSR.Spec.SignerName = "kubernetes.io/kube-apiserver-client" }, func(i *Input) { i.CSR.Spec.Usages = append(i.CSR.Spec.Usages, "client auth") }, func(i *Input) { i.CSR.Spec.Usages = append(i.CSR.Spec.Usages, "cert sign") }, func(i *Input) { i.CSR.Spec.Usages = append(i.CSR.Spec.Usages, "key encipherment") }, func(i *Input) { i.CSR.Spec.Usages = []string{"server auth", "server auth"} }, func(i *Input) { i.PolicyKind = "selfnodeclient-renewal" }} {
		in := copyInput(t, base)
		change(&in)
		invalid(t, in)
	}
}
func TestExpirationBounds(t *testing.T) {
	for _, v := range []int64{0, 599, 31536001, -1} {
		in := fixture(t, testEC, "serving", nil)
		in.CSR.Spec.ExpirationSeconds = &v
		invalid(t, in)
	}
	for _, v := range []int64{600, 31536000} {
		in := fixture(t, testEC, "serving", nil)
		in.CSR.Spec.ExpirationSeconds = &v
		valid(t, in)
	}
}
func TestSubjectHasOnlyOneExactCNAndOrganization(t *testing.T) {
	variants := []pkix.Name{{CommonName: "system:node:other", Organization: []string{"system:nodes"}}, {CommonName: "system:node:node-a", Organization: []string{"system:nodes", "system:masters"}}, {CommonName: "system:node:node-a", Organization: []string{"system:nodes"}, OrganizationalUnit: []string{"admin"}}, {CommonName: "system:node:node-a", Organization: []string{"system:nodes"}, Country: []string{"US"}}, {CommonName: "system:node:node-a", Organization: []string{"system:nodes"}, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: "extra"}}}}
	for _, name := range variants {
		in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) { c.Subject = name })
		invalid(t, in)
	}
}
func TestRawSubjectRejectsCollapsedDuplicateOrMultivaluedRDN(t *testing.T) {
	cn := pkix.AttributeTypeAndValue{Type: oidCN, Value: "system:node:node-a"}
	org := pkix.AttributeTypeAndValue{Type: oidO, Value: "system:nodes"}
	cases := []pkix.RDNSequence{{{org}, {cn}, {cn}}, {{org, cn}}, {{org}, {cn}, {{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: ""}}}}
	for _, rdn := range cases {
		in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) { c.RawSubject = asn(t, rdn) })
		invalid(t, in)
	}
}
func TestServingNamesMustMatchIndependentExactSet(t *testing.T) {
	for _, change := range []func(*x509.CertificateRequest){func(c *x509.CertificateRequest) { c.DNSNames = []string{"node-b"} }, func(c *x509.CertificateRequest) { c.DNSNames = append(c.DNSNames, "another.example.test") }, func(c *x509.CertificateRequest) { c.DNSNames = []string{"*.example.test"} }, func(c *x509.CertificateRequest) { c.DNSNames = []string{"NODE-A"} }, func(c *x509.CertificateRequest) { c.DNSNames = []string{"node-a."} }, func(c *x509.CertificateRequest) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.11")} }, func(c *x509.CertificateRequest) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }, func(c *x509.CertificateRequest) { c.DNSNames = nil; c.IPAddresses = nil }} {
		in := fixture(t, testEC, "serving", change)
		invalid(t, in)
	}
}
func TestExactIPOnlyAndDNSOnlyServingAreSupported(t *testing.T) {
	in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) { c.DNSNames = nil })
	in.Enrollment.AllowedDNSNames = []string{}
	valid(t, in)
	in = fixture(t, testEC, "serving", func(c *x509.CertificateRequest) { c.IPAddresses = nil })
	in.Enrollment.AllowedIPAddresses = []string{}
	valid(t, in)
}
func TestClientRenewalForbidsAnySAN(t *testing.T) {
	in := fixture(t, testEC, "selfnodeclient-renewal", func(c *x509.CertificateRequest) { c.DNSNames = []string{"node-a"} })
	invalid(t, in)
}
func TestAllOtherGeneralNameKindsAreRejected(t *testing.T) {
	for _, tag := range []byte{0xa0, 0x81, 0xa3, 0xa4, 0xa5, 0x86, 0x88, 0xa2} {
		t.Run(hex.EncodeToString([]byte{tag}), func(t *testing.T) {
			body := join(wrap(0x82, []byte("node-a")), wrap(0x87, []byte{192, 0, 2, 10}), wrap(tag, []byte("surprise")))
			in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) {
				c.ExtraExtensions = []pkix.Extension{sanExtension(t, wrap(0x30, body))}
			})
			invalid(t, in)
		})
	}
}
func TestSANRejectsDuplicatesAndMappedIP(t *testing.T) {
	for _, body := range [][]byte{join(wrap(0x82, []byte("node-a")), wrap(0x82, []byte("node-a")), wrap(0x87, []byte{192, 0, 2, 10})), join(wrap(0x82, []byte("node-a")), wrap(0x87, net.ParseIP("::ffff:192.0.2.10").To16()))} {
		in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{sanExtension(t, wrap(0x30, body))}
		})
		invalid(t, in)
	}
}
func TestCAAndExtraExtensionsAreRejected(t *testing.T) {
	for _, extension := range []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: asn(t, struct{ CA bool }{true})}, {Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}, {Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: asn(t, asn1.BitString{Bytes: []byte{0x80}, BitLength: 1})}} {
		in := fixture(t, testEC, "serving", func(c *x509.CertificateRequest) { c.ExtraExtensions = []pkix.Extension{extension} })
		invalid(t, in)
	}
}
func TestRawAttributeExtraValuesAndFieldsAreRejected(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	for _, kind := range []string{"unknown", "duplicate", "multiple-values", "attribute-extra-field", "extension-extra-field"} {
		t.Run(kind, func(t *testing.T) {
			in := resign(t, base, func(parts []asn1.RawValue) []asn1.RawValue {
				attrs := testChildren(t, parts[3].FullBytes)
				fields := testChildren(t, attrs[0].FullBytes)
				switch kind {
				case "unknown":
					fields[0] = rawValue(t, asn(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}))
				case "duplicate":
					parts[3] = rawValue(t, wrap(0xa0, join(attrs[0].FullBytes, attrs[0].FullBytes)))
					return parts
				case "multiple-values":
					values := testChildren(t, fields[1].FullBytes)
					fields[1] = rawValue(t, wrap(0x31, join(values[0].FullBytes, values[0].FullBytes)))
				case "attribute-extra-field":
					fields = append(fields, rawValue(t, []byte{5, 0}))
				case "extension-extra-field":
					values := testChildren(t, fields[1].FullBytes)
					exts := testChildren(t, values[0].FullBytes)
					extFields := testChildren(t, exts[0].FullBytes)
					var b []byte
					for _, v := range extFields {
						b = append(b, v.FullBytes...)
					}
					exts[0] = rawValue(t, wrap(0x30, append(b, 5, 0)))
					fields[1] = rawValue(t, wrap(0x31, wrap(0x30, exts[0].FullBytes)))
				}
				var body []byte
				for _, v := range fields {
					body = append(body, v.FullBytes...)
				}
				parts[3] = rawValue(t, wrap(0xa0, wrap(0x30, body)))
				return parts
			})
			invalid(t, in)
		})
	}
}
func TestOuterAndRequestInfoExtraSequenceChildrenRejected(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	in := resign(t, base, func(parts []asn1.RawValue) []asn1.RawValue { return append(parts, rawValue(t, []byte{5, 0})) })
	invalid(t, in)
	outer := testChildren(t, derOf(t, base))
	var body []byte
	for _, v := range outer {
		body = append(body, v.FullBytes...)
	}
	base.CSR.Spec.RequestBase64 = encodeCSR(wrap(0x30, append(body, 5, 0)))
	invalid(t, base)
}
func TestInvalidProofOfPossessionIsRejected(t *testing.T) {
	in := fixture(t, testRSA, "serving", nil)
	der := derOf(t, in)
	der[len(der)-1] ^= 1
	in.CSR.Spec.RequestBase64 = encodeCSR(der)
	d := invalid(t, in)
	if d.Code != "request_signature_invalid" {
		t.Fatalf("wrong failure %s", d.Code)
	}
}
func TestWeakRSAAndEd25519ProfilesAreRejected(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []crypto.Signer{weak, ed} {
		in := fixture(t, key, "serving", nil)
		d := invalid(t, in)
		if d.Code != "request_key_profile_invalid" {
			t.Fatalf("wrong key rejection %s", d.Code)
		}
	}
}
func TestRSAExponentAndSizeBoundsBeforeSignatureVerification(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	for _, key := range []*rsa.PublicKey{{N: testRSA.N, E: 3}, {N: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 8192), big.NewInt(1)), E: 65537}} {
		spki, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			t.Fatal(err)
		}
		in := resign(t, base, func(parts []asn1.RawValue) []asn1.RawValue { parts[2] = rawValue(t, spki); return parts })
		d := invalid(t, in)
		if d.Code != "request_key_profile_invalid" {
			t.Fatalf("wrong key rejection %s", d.Code)
		}
	}
}
func TestSHA1CSRIsRejectedEvenIfStandardSignatureCheckSucceeds(t *testing.T) {
	in := fixture(t, testRSA, "serving", func(c *x509.CertificateRequest) { c.SignatureAlgorithm = x509.SHA1WithRSA })
	csr, err := x509.ParseCertificateRequest(derOf(t, in))
	if err != nil {
		t.Fatal(err)
	}
	if err = csr.CheckSignature(); err != nil {
		t.Fatalf("test expects real valid SHA1 proof: %v", err)
	}
	d := invalid(t, in)
	if d.Code != "request_signature_algorithm_invalid" {
		t.Fatalf("wrong failure %s", d.Code)
	}
}
func TestEquivalentAlgorithmWithExtraParameterRejected(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	outer := testChildren(t, derOf(t, base))
	fields := testChildren(t, outer[1].FullBytes)
	algorithm := wrap(0x30, join(fields[0].FullBytes, []byte{5, 0}))
	base.CSR.Spec.RequestBase64 = encodeCSR(wrap(0x30, join(outer[0].FullBytes, algorithm, outer[2].FullBytes)))
	invalid(t, base)
}
func TestPEMAndBase64HaveOneCanonicalCSRBlock(t *testing.T) {
	base := fixture(t, testEC, "serving", nil)
	pemBytes, _ := base64.StdEncoding.DecodeString(base.CSR.Spec.RequestBase64)
	for _, blob := range [][]byte{append([]byte("prefix\n"), pemBytes...), append(append([]byte{}, pemBytes...), byte('\n')), append(append([]byte{}, pemBytes...), pemBytes...), bytes.Replace(pemBytes, []byte("CERTIFICATE REQUEST"), []byte("NEW CERTIFICATE REQUEST"), -1), bytes.ReplaceAll(pemBytes, []byte("\n"), []byte("\r\n")), bytes.Replace(pemBytes, []byte("-----BEGIN CERTIFICATE REQUEST-----\n"), []byte("-----BEGIN CERTIFICATE REQUEST-----\nHeader: surprise\n\n"), 1)} {
		in := copyInput(t, base)
		in.CSR.Spec.RequestBase64 = base64.StdEncoding.EncodeToString(blob)
		invalid(t, in)
	}
	in := copyInput(t, base)
	in.CSR.Spec.RequestBase64 = base.CSR.Spec.RequestBase64 + "\n"
	invalid(t, in)
	in = copyInput(t, base)
	in.CSR.Spec.RequestBase64 = encodeCSR(append(derOf(t, base), 5, 0))
	invalid(t, in)
}
func TestInputProtocolRejectsDuplicateUnknownNullAndTrailingFields(t *testing.T) {
	raw := inputBytes(t, fixture(t, testEC, "serving", nil))
	variants := [][]byte{append(append([]byte{}, raw...), []byte(" {}")...), bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1), bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":true`), 1), bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unexpected":0`), 1), bytes.Replace(raw, []byte(`"uid":""`), []byte(`"uid":null`), 1), bytes.Replace(raw, []byte(`"expiration_seconds"`), []byte(`"surprise"`), 1)}
	variants = variants[:len(variants)-1]
	for _, v := range variants {
		d := Evaluate(v)
		if d.Decision != "reject" || d.Code != "input_invalid" {
			t.Fatalf("accepted ambiguous protocol: %+v", d)
		}
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj["enrollment"].(map[string]any), "allowed_auth_uid")
	missing, _ := json.Marshal(obj)
	if Evaluate(missing).Decision != "reject" {
		t.Fatal("missing required explicit auth UID")
	}
}
func TestMalformedInputNeverEchoesCanaryOrRequest(t *testing.T) {
	var out bytes.Buffer
	raw := []byte(`{"private-canary":"never-echo-this-value"}`)
	if code := run(bytes.NewReader(raw), &out); code != 2 {
		t.Fatal(code)
	}
	if bytes.Contains(out.Bytes(), []byte("never-echo")) || bytes.Contains(out.Bytes(), []byte("private-canary")) {
		t.Fatal("input leaked")
	}
	var d Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Binding != nil || d.Decision != "reject" {
		t.Fatal("not typed rejection")
	}
}
func TestReaderAndSizeErrorsAreTyped(t *testing.T) {
	var out bytes.Buffer
	if code := run(errorReader{}, &out); code != 2 || !bytes.Contains(out.Bytes(), []byte("input_read_failed")) {
		t.Fatal("reader error")
	}
	out.Reset()
	if code := run(io.LimitReader(zeroReader{}, maxInputBytes+1), &out); code != 2 || !bytes.Contains(out.Bytes(), []byte("input_too_large")) {
		t.Fatal("size bound")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic private error must not be printed")
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
func TestValidDecisionIsOnlyPublicBindings(t *testing.T) {
	in := fixture(t, testEC, "serving", nil)
	var out bytes.Buffer
	if code := run(bytes.NewReader(inputBytes(t, in)), &out); code != 0 {
		t.Fatal(code)
	}
	for _, needle := range []string{"BEGIN", in.CSR.Spec.RequestBase64, in.CSR.Spec.Extra[credentialIDKey][0], "192.0.2.10"} {
		if strings.Contains(out.String(), needle) {
			t.Fatalf("unnecessary data emitted: %s", needle)
		}
	}
	var d Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil || d.Binding == nil {
		t.Fatal("invalid decision")
	}
}
func TestNoMutationOfInputBindings(t *testing.T) {
	in := fixture(t, testEC, "serving", nil)
	before := inputBytes(t, in)
	Verify(in, digest(before))
	if !reflect.DeepEqual(before, inputBytes(t, in)) {
		t.Fatal("mutated caller data")
	}
}
func FuzzEvaluate(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schema_version":1,"schema_version":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxInputBytes+1 {
			t.Skip()
		}
		d := Evaluate(raw)
		if d.SchemaVersion != 1 || (d.Decision != "valid" && d.Decision != "reject") {
			t.Fatal("untyped decision")
		}
		if d.Decision == "reject" && d.Binding != nil {
			t.Fatal("rejected request bound")
		}
	})
}
