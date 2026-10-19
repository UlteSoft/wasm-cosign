// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var rsaTestOnce sync.Once
var rsaTestKey *rsa.PrivateKey
var rsaTestErr error

func testRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	rsaTestOnce.Do(func() { rsaTestKey, rsaTestErr = rsa.GenerateKey(rand.Reader, 3072) })
	if rsaTestErr != nil {
		t.Fatal(rsaTestErr)
	}
	return rsaTestKey
}
func testKey(t *testing.T, name Algorithm) any {
	t.Helper()
	p, ok := profile(name)
	if !ok {
		t.Fatal(name)
	}
	switch p.kind {
	case 'e':
		k, e := ecdsa.GenerateKey(p.curve, rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	case 'd':
		_, k, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		return k
	default:
		return testRSA(t)
	}
}
func testPublic(key any) any {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *rsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	}
	return nil
}
func encodeBundle(p algorithmInfo, payload, signature []byte) []byte {
	b := appendBytes([]byte{0xd2, 0x84}, p.protected())
	b = append(b, 0xa0)
	b = appendBytes(b, payload)
	return appendBytes(b, signature)
}
func replacePublisher(t *testing.T, f *fixture, key any, name Algorithm) {
	t.Helper()
	template := *f.leaf
	der, e := x509.CreateCertificate(rand.Reader, &template, f.ca, testPublic(key), f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Certificates = certificatePEM(der)
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	r := f.p.Modules[f.m.ModuleID]
	r.SPKI = SPKIDigest(cert.RawSubjectPublicKeyInfo)
	r.Algorithms = []Algorithm{name}
	f.p.Modules[f.m.ModuleID] = r
	f.m.Algorithm = name
	f.ev.Signature, e = Sign(f.module, f.m, key)
	if e != nil {
		t.Fatal(e)
	}
}

func TestAll13AlgorithmProfiles(t *testing.T) {
	seen := map[int64]bool{}
	for _, p := range algorithmProfiles {
		t.Run(string(p.name), func(t *testing.T) {
			if seen[p.id] {
				t.Fatal("duplicate COSE identifier")
			}
			seen[p.id] = true
			f := newFixture(t)
			key := testKey(t, p.name)
			replacePublisher(t, &f, key, p.name)
			m, payload, sig, e := Parse(f.ev.Signature)
			if e != nil {
				t.Fatal(e)
			}
			if m.Algorithm != p.name {
				t.Fatalf("algorithm metadata %q", m.Algorithm)
			}
			if e = verifyAlgorithmSignature(m.Algorithm, payload, sig, testPublic(key)); e != nil {
				t.Fatal(e)
			}
			if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e != nil {
				t.Fatal(e)
			}
			broken := bytes.Clone(sig)
			broken[len(broken)-1] ^= 1
			if e = verifyAlgorithmSignature(p.name, payload, broken, testPublic(key)); e == nil {
				t.Fatal("accepted modified signature")
			}
			for _, n := range []int{0, len(sig) - 1, len(sig) + 1} {
				b := make([]byte, n)
				copy(b, sig)
				if e = verifyAlgorithmSignature(p.name, payload, b, testPublic(key)); e == nil {
					t.Fatalf("accepted signature length %d", n)
				}
			}
		})
	}
	if len(seen) != 13 {
		t.Fatalf("got %d profiles", len(seen))
	}
}

func TestExactAlgorithmWireIdentifiers(t *testing.T) {
	// This independent table checks the wire constants, rather than deriving
	// the expected identifier from the same profile used by the signer.
	wire := map[Algorithm]string{
		AlgorithmES256: "a10126", AlgorithmESP256: "a10128",
		AlgorithmES384: "a1013822", AlgorithmESP384: "a1013832",
		AlgorithmES512: "a1013823", AlgorithmESP512: "a1013833",
		AlgorithmEd25519: "a10132",
		AlgorithmPS256:   "a1013824", AlgorithmPS384: "a1013825", AlgorithmPS512: "a1013826",
		AlgorithmRS256: "a101390100", AlgorithmRS384: "a101390101", AlgorithmRS512: "a101390102",
	}
	f := newFixture(t)
	for name, expected := range wire {
		p, ok := profile(name)
		if !ok || hex.EncodeToString(p.protected()) != expected {
			t.Fatalf("%s: got %x, expected %s", name, p.protected(), expected)
		}
	}
	for _, id := range []int64{-8, -1, -20, -260, -65536} {
		p := algorithmInfo{id: id}
		if _, _, _, e := Parse(encodeBundle(p, f.m.payload(), make([]byte, 64))); e == nil || !strings.Contains(e.Error(), "SIG_005") {
			t.Fatalf("accepted unknown/ambiguous COSE algorithm %d: %v", id, e)
		}
	}
}

func TestProtectedAlgorithmSubstitutionAndPolicy(t *testing.T) {
	f := newFixture(t)
	for _, pair := range [][2]Algorithm{{AlgorithmES256, AlgorithmESP256}, {AlgorithmES384, AlgorithmESP384}, {AlgorithmES512, AlgorithmESP512}} {
		key := testKey(t, pair[0])
		f.m.Algorithm = pair[0]
		bundle, e := Sign(f.module, f.m, key)
		if e != nil {
			t.Fatal(e)
		}
		_, payload, sig, e := Parse(bundle)
		if e != nil {
			t.Fatal(e)
		}
		to, _ := profile(pair[1])
		m, p, s, e := Parse(encodeBundle(to, payload, sig))
		if e != nil {
			t.Fatal(e)
		}
		if e = verifyAlgorithmSignature(m.Algorithm, p, s, testPublic(key)); e == nil {
			t.Fatal("changing signed protected algorithm preserved authorization")
		}
	}
	f = newFixture(t)
	f.m.Algorithm = AlgorithmESP256
	var e error
	f.ev.Signature, e = Sign(f.module, f.m, f.key)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Certificates = []byte("invalid certificate should never be authorized")
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil || !strings.Contains(e.Error(), "SIG_005") {
		t.Fatalf("legacy policy silently broadened or checked certificate before algorithm policy: %v", e)
	}
	if _, e = Sign(f.module, Manifest{Algorithm: "EdDSA"}, f.key); e == nil || !strings.Contains(e.Error(), "SIG_005") {
		t.Fatal("accepted alias", e)
	}
	for _, p := range algorithmProfiles {
		wrong := any(f.key)
		if p.kind == 'e' && p.curve == elliptic.P256() {
			wrong = testRSA(t)
		}
		f.m.Algorithm = p.name
		if _, e = Sign(f.module, f.m, wrong); e == nil {
			t.Fatalf("accepted mismatched %s key", p.name)
		}
	}
}

func TestAlgorithmPolicyCompatibilityAndCanonicalSets(t *testing.T) {
	f := newFixture(t)
	original, e := f.p.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	p, e := ParsePolicy(original)
	if e != nil {
		t.Fatal(e)
	}
	rule := p.Modules[f.m.ModuleID]
	if !rule.AllowsAlgorithm(AlgorithmES256) || rule.AllowsAlgorithm(AlgorithmESP256) || rule.AllowsAlgorithm(AlgorithmEd25519) {
		t.Fatal("six-field policy broadened")
	}
	for _, value := range []string{"", "ES256,", "ES256,ES256", "ES256, ES384", "es256", "EdDSA", "-7", "ES256\t", "PS256,,RS256", "Ed25519ph"} {
		if _, e = ParseAlgorithms(value); e == nil {
			t.Fatalf("accepted algorithm policy %q", value)
		}
	}
	names, e := ParseAlgorithms("RS512,Ed25519,ESP256,PS256")
	if e != nil {
		t.Fatal(e)
	}
	rule.Algorithms = names
	p.Modules[f.m.ModuleID] = rule
	encoded, e := p.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(encoded, []byte("|ESP256,Ed25519,PS256,RS512\n")) {
		t.Fatalf("noncanonical policy set %s", encoded)
	}
	altered := bytes.Replace(encoded, []byte("ESP256,Ed25519,PS256,RS512"), []byte("RS512,PS256,ESP256,Ed25519"), 1)
	p2, e := ParsePolicy(altered)
	if e != nil {
		t.Fatal(e)
	}
	canon, e := p2.Marshal()
	if e != nil || !bytes.Equal(encoded, canon) {
		t.Fatal("semantic policy set changed with input order", e)
	}
	bad := bytes.Replace(original, []byte("|63\n"), []byte("|63|\n"), 1)
	if _, e = ParsePolicy(bad); e == nil {
		t.Fatal("accepted empty seventh field")
	}
}

func TestECDSALowSAcrossCurves(t *testing.T) {
	for _, name := range []Algorithm{AlgorithmES256, AlgorithmES384, AlgorithmES512} {
		f := newFixture(t)
		key := testKey(t, name).(*ecdsa.PrivateKey)
		f.m.Algorithm = name
		b, e := Sign(f.module, f.m, key)
		if e != nil {
			t.Fatal(e)
		}
		_, payload, sig, e := Parse(b)
		if e != nil {
			t.Fatal(e)
		}
		p, _ := profile(name)
		s := new(big.Int).SetBytes(sig[p.width:])
		s.Sub(key.Params().N, s).FillBytes(sig[p.width:])
		if e = verifyAlgorithmSignature(name, payload, sig, &key.PublicKey); e == nil {
			t.Fatalf("accepted high S for %s", name)
		}
	}
}

func TestPSSSaltAndEd25519DomainSeparation(t *testing.T) {
	f := newFixture(t)
	for _, name := range []Algorithm{AlgorithmPS256, AlgorithmPS384, AlgorithmPS512} {
		p, _ := profile(name)
		digest := hashMessage(p.hash, signingBytesFor(f.m.payload(), p))
		sig, e := rsa.SignPSS(rand.Reader, testRSA(t), p.hash, digest, &rsa.PSSOptions{SaltLength: p.hash.Size() + 1, Hash: p.hash})
		if e != nil {
			t.Fatal(e)
		}
		if e = verifyAlgorithmSignature(name, f.m.payload(), sig, &testRSA(t).PublicKey); e == nil {
			t.Fatalf("accepted wrong PSS salt for %s", name)
		}
	}
	key := testKey(t, AlgorithmEd25519).(ed25519.PrivateKey)
	p, _ := profile(AlgorithmEd25519)
	input := signingBytesFor(f.m.payload(), p)
	digest := sha512.Sum512(input)
	for _, opts := range []*ed25519.Options{{Hash: crypto.SHA512}, {Context: "wsea-forbidden-context"}} {
		message := input
		if opts.Hash != 0 {
			message = digest[:]
		}
		sig, e := key.Sign(rand.Reader, message, opts)
		if e != nil {
			t.Fatal(e)
		}
		if e = verifyAlgorithmSignature(AlgorithmEd25519, f.m.payload(), sig, key.Public()); e == nil {
			t.Fatal("accepted prehash or context Ed25519 signature")
		}
	}
}

func TestStrictEd25519PublicAndSignatureEncodings(t *testing.T) {
	f := newFixture(t)
	identity := ed25519.PublicKey(make([]byte, 32))
	identity[0] = 1
	forgery := make([]byte, 64)
	forgery[0] = 1
	t.Logf("raw standard-library identity-key forgery accepted=%v (strict profile must reject either result)", ed25519.Verify(identity, []byte("arbitrary module"), forgery))
	if e := verifyAlgorithmSignature(AlgorithmEd25519, f.m.payload(), forgery, identity); e == nil {
		t.Fatal("accepted identity-key forgery")
	}
	values := []string{strings.Repeat("00", 32), "01" + strings.Repeat("00", 31), "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "ec" + strings.Repeat("ff", 30) + "7f", "ed" + strings.Repeat("ff", 30) + "7f", "ee" + strings.Repeat("ff", 30) + "7f"}
	for _, value := range values {
		b, e := hex.DecodeString(value)
		if e != nil {
			t.Fatal(e)
		}
		for _, sign := range []byte{0, 0x80} {
			k := bytes.Clone(b)
			k[31] = k[31]&0x7f | sign
			if strongEd25519Encoding(k) || allowedPublicKey(ed25519.PublicKey(k)) {
				t.Fatalf("accepted forbidden Ed25519 point %x", k)
			}
		}
	}
	key := testKey(t, AlgorithmEd25519).(ed25519.PrivateKey)
	f.m.Algorithm = AlgorithmEd25519
	bundle, e := Sign(f.module, f.m, key)
	if e != nil {
		t.Fatal(e)
	}
	_, payload, sig, e := Parse(bundle)
	if e != nil {
		t.Fatal(e)
	}
	copyBad := bytes.Clone(sig)
	copy(copyBad[:32], identity)
	if e = verifyAlgorithmSignature(AlgorithmEd25519, payload, copyBad, key.Public()); e == nil {
		t.Fatal("accepted small-order R")
	}
	order := []byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	copyBad = bytes.Clone(sig)
	carry := uint16(0)
	for i := range order {
		v := uint16(copyBad[32+i]) + uint16(order[i]) + carry
		copyBad[32+i] = byte(v)
		carry = v >> 8
	}
	if e = verifyAlgorithmSignature(AlgorithmEd25519, payload, copyBad, key.Public()); e == nil {
		t.Fatal("accepted S+L")
	}
}

func TestRSAKeyBoundsAndStrictPrivatePEM(t *testing.T) {
	valid := &testRSA(t).PublicKey
	if !strongRSA(valid) {
		t.Fatal("rejected valid RSA3072")
	}
	for _, bits := range []uint{3072, 8192} {
		n := new(big.Int).Lsh(big.NewInt(1), bits-1)
		n.Add(n, big.NewInt(1))
		if !strongRSA(&rsa.PublicKey{N: n, E: 65537}) {
			t.Fatalf("RSA profile excludes its declared boundary %d", bits)
		}
	}
	for _, test := range []struct{ bits, e int }{{2048, 65537}, {3071, 65537}, {8193, 65537}, {3072, 3}, {3072, 17}} {
		n := new(big.Int).Lsh(big.NewInt(1), uint(test.bits-1))
		n.Add(n, big.NewInt(1))
		if strongRSA(&rsa.PublicKey{N: n, E: test.e}) {
			t.Fatalf("accepted RSA bits=%d exponent=%d", test.bits, test.e)
		}
	}
	ec := testKey(t, AlgorithmES512).(*ecdsa.PrivateKey)
	sec1, e := x509.MarshalECPrivateKey(ec)
	if e != nil {
		t.Fatal(e)
	}
	for _, block := range []*pem.Block{{Type: "EC PRIVATE KEY", Bytes: sec1}, {Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testRSA(t))}} {
		if _, e = ParsePrivateKey(pem.EncodeToMemory(block)); e != nil {
			t.Fatal(e)
		}
	}
	for _, key := range []any{testKey(t, AlgorithmES384), testKey(t, AlgorithmEd25519), testRSA(t)} {
		der, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			t.Fatal(e)
		}
		encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if _, e = ParsePrivateKey(encoded); e != nil {
			t.Fatal(e)
		}
		for _, b := range [][]byte{append([]byte("padding"), encoded...), append(bytes.Clone(encoded), encoded...), append([]byte("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----\n"), encoded...)} {
			if _, e = ParsePrivateKey(b); e == nil {
				t.Fatal("accepted unsigned key PEM padding/duplicate/malformed leading block")
			}
		}
		for _, tail := range [][]byte{{0}, der} {
			b := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: append(bytes.Clone(der), tail...)})
			if _, e = ParsePrivateKey(b); e == nil {
				t.Fatal("accepted trailing DER inside a private-key PEM block")
			}
		}
	}
}

func TestPEMDERExactConsumption(t *testing.T) {
	f := newFixture(t)
	pristine := f.ev
	cert, _ := pem.Decode(f.ev.Certificates)
	crl, _ := pem.Decode(f.ev.CRLs)
	root, _ := pem.Decode(f.root)
	for _, tail := range [][]byte{{0}, root.Bytes} {
		encoded := certificatePEM(append(bytes.Clone(root.Bytes), tail...))
		if _, e := Verify(f.module, pristine, f.p, encoded, f.now); e == nil || !strings.HasPrefix(e.Error(), "CERT_001:") {
			t.Fatalf("malformed trust-root DER was not classified as CERT_001: %v", e)
		}
	}
	for _, tc := range []struct {
		name, kind string
		der        []byte
	}{{"certificate", "CERTIFICATE", cert.Bytes}, {"CRL", "X509 CRL", crl.Bytes}} {
		for i, tail := range [][]byte{{0}, {0, 1, 2, 3}, tc.der} {
			t.Run(tc.name+"-tail-"+string(rune('0'+i)), func(t *testing.T) {
				encoded := pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: append(bytes.Clone(tc.der), tail...)})
				if tc.kind == "CERTIFICATE" {
					if _, e := Certificates(encoded); e == nil {
						t.Fatal("accepted DER padding or a second object inside certificate PEM")
					}
					f.ev.Certificates = encoded
				} else {
					if _, e := parseCRLs(encoded); e == nil {
						t.Fatal("accepted DER padding or a second object inside CRL PEM")
					}
					f.ev.Certificates = certificatePEM(cert.Bytes)
					f.ev.CRLs = encoded
				}
				if _, e := Verify(f.module, f.ev, f.p, f.root, f.now); e == nil {
					t.Fatal("deployment verifier accepted evidence with hidden DER padding")
				}
			})
		}
	}
}

func TestPEMRejectsUnterminatedBlockBeforeNestedValidBlock(t *testing.T) {
	f := newFixture(t)
	keyDER, e := x509.MarshalPKCS8PrivateKey(f.key)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		kind    string
		encoded []byte
	}{{"CERTIFICATE", f.ev.Certificates}, {"X509 CRL", f.ev.CRLs}, {"PRIVATE KEY", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}} {
		t.Run(tc.kind, func(t *testing.T) {
			malformed := append([]byte("-----BEGIN "+tc.kind+"-----\n!!!!\n"), tc.encoded...)
			if block, _ := strictPEM(malformed, tc.kind); block != nil {
				t.Fatal("substituted nested PEM for an unterminated malformed leading block")
			}
			switch tc.kind {
			case "CERTIFICATE":
				if _, e = Certificates(malformed); e == nil {
					t.Fatal("accepted nested certificate block")
				}
			case "X509 CRL":
				if _, e = parseCRLs(malformed); e == nil {
					t.Fatal("accepted nested CRL block")
				}
			case "PRIVATE KEY":
				if _, e = ParsePrivateKey(malformed); e == nil {
					t.Fatal("accepted nested private key block")
				}
			}
		})
	}
}

func TestPKIAllAllowedSigningAlgorithms(t *testing.T) {
	cases := []struct {
		algorithm x509.SignatureAlgorithm
		key       Algorithm
	}{{x509.ECDSAWithSHA256, AlgorithmES256}, {x509.ECDSAWithSHA384, AlgorithmES384}, {x509.ECDSAWithSHA512, AlgorithmES512}, {x509.PureEd25519, AlgorithmEd25519}, {x509.SHA256WithRSA, AlgorithmRS256}, {x509.SHA384WithRSA, AlgorithmRS384}, {x509.SHA512WithRSA, AlgorithmRS512}, {x509.SHA256WithRSAPSS, AlgorithmPS256}, {x509.SHA384WithRSAPSS, AlgorithmPS384}, {x509.SHA512WithRSAPSS, AlgorithmPS512}}
	for _, tc := range cases {
		t.Run(tc.algorithm.String(), func(t *testing.T) {
			f := newFixture(t)
			key := testKey(t, tc.key)
			caTemplate := *f.ca
			caTemplate.SignatureAlgorithm = tc.algorithm
			caTemplate.PublicKey = testPublic(key)
			caTemplate.SubjectKeyId = nil
			caTemplate.AuthorityKeyId = nil
			caDER, e := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, testPublic(key), key)
			if e != nil {
				t.Fatal(e)
			}
			ca, e := x509.ParseCertificate(caDER)
			if e != nil {
				t.Fatal(e)
			}
			leafTemplate := *f.leaf
			leafTemplate.SignatureAlgorithm = tc.algorithm
			leafDER, e := x509.CreateCertificate(rand.Reader, &leafTemplate, ca, &f.key.PublicKey, key)
			if e != nil {
				t.Fatal(e)
			}
			crlDER, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour), SignatureAlgorithm: tc.algorithm}, ca, key.(crypto.Signer))
			if e != nil {
				t.Fatal(e)
			}
			f.ev.Certificates = certificatePEM(leafDER)
			f.ev.CRLs = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
			f.root = certificatePEM(caDER)
			if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestStrictPSSAlgorithmIdentifierParameters(t *testing.T) {
	hashAI := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Parameters: asn1.RawValue{FullBytes: asn1.NullBytes}}
	hashDER, e := asn1.Marshal(hashAI)
	if e != nil {
		t.Fatal(e)
	}
	valid := strictPSSParameters{Hash: hashAI, MGF: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}, Parameters: asn1.RawValue{FullBytes: hashDER}}, SaltLength: 32}
	encoded, e := asn1.Marshal(valid)
	if e != nil {
		t.Fatal(e)
	}
	ai := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Parameters: asn1.RawValue{FullBytes: encoded}}
	if !strictPSS(ai, crypto.SHA256) {
		t.Fatal("rejected exact SHA256 PSS parameters")
	}
	explicit := valid
	explicit.Trailer = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: []byte{2, 1, 1}}
	b, e := asn1.Marshal(explicit)
	if e != nil {
		t.Fatal(e)
	}
	ai.Parameters.FullBytes = b
	if !strictPSS(ai, crypto.SHA256) {
		t.Fatal("rejected explicit trailer integer 1")
	}
	for _, salt := range []int{0, 20, 31, 33} {
		bad := valid
		bad.SaltLength = salt
		b, e = asn1.Marshal(bad)
		if e != nil {
			t.Fatal(e)
		}
		ai.Parameters.FullBytes = b
		if strictPSS(ai, crypto.SHA256) {
			t.Fatalf("accepted PSS salt %d", salt)
		}
	}
	badMGF := valid
	otherHash := hashAI
	otherHash.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	otherDER, e := asn1.Marshal(otherHash)
	if e != nil {
		t.Fatal(e)
	}
	badMGF.MGF.Parameters = asn1.RawValue{FullBytes: otherDER}
	b, e = asn1.Marshal(badMGF)
	if e != nil {
		t.Fatal(e)
	}
	ai.Parameters.FullBytes = b
	if strictPSS(ai, crypto.SHA256) {
		t.Fatal("accepted mismatched MGF1 digest")
	}
	badTrailer := valid
	badTrailer.Trailer = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: []byte{2, 1, 2}}
	b, e = asn1.Marshal(badTrailer)
	if e != nil {
		t.Fatal(e)
	}
	ai.Parameters.FullBytes = b
	if strictPSS(ai, crypto.SHA256) {
		t.Fatal("accepted trailer other than integer 1")
	}
	duplicate := append([]byte{0x30, byte(len(encoded) - 2 + 5)}, encoded[2:]...)
	duplicate = append(duplicate, 0xa2, 3, 2, 1, 32)
	ai.Parameters.FullBytes = duplicate
	if strictPSS(ai, crypto.SHA256) {
		t.Fatal("accepted duplicate PSS salt parameter")
	}
	ai.Parameters.FullBytes = append(bytes.Clone(encoded), 0)
	if strictPSS(ai, crypto.SHA256) {
		t.Fatal("accepted trailing PSS parameters")
	}
	ai.Parameters.FullBytes = append([]byte{0x30, byte(len(encoded) - 2 + 3)}, encoded[2:]...)
	ai.Parameters.FullBytes = append(ai.Parameters.FullBytes, 0xa4, 1, 0)
	if strictPSS(ai, crypto.SHA256) {
		t.Fatal("accepted unknown PSS parameter")
	}
}

func TestIdentityPublisherCannotAuthorizeArbitraryModule(t *testing.T) {
	f := newFixture(t)
	identity := ed25519.PublicKey(make([]byte, 32))
	identity[0] = 1
	template := *f.leaf
	der, e := x509.CreateCertificate(rand.Reader, &template, f.ca, identity, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	_, payload, _, e := Parse(f.ev.Signature)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := profile(AlgorithmEd25519)
	forgery := make([]byte, 64)
	forgery[0] = 1
	f.ev.Signature = encodeBundle(p, payload, forgery)
	f.ev.Certificates = certificatePEM(der)
	r := f.p.Modules[f.m.ModuleID]
	r.SPKI = SPKIDigest(leaf.RawSubjectPublicKeyInfo)
	r.Algorithms = []Algorithm{AlgorithmEd25519}
	f.p.Modules[f.m.ModuleID] = r
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil || !strings.Contains(e.Error(), "SIG_005") {
		t.Fatalf("weak but correctly issued/pinned publisher authorized module: %v", e)
	}
}

func TestEd25519PKISignaturesUseStrictEncoding(t *testing.T) {
	f := newFixture(t)
	key := testKey(t, AlgorithmEd25519).(ed25519.PrivateKey)
	template := *f.ca
	template.SignatureAlgorithm = x509.PureEd25519
	template.PublicKey = key.Public()
	template.SubjectKeyId = nil
	template.AuthorityKeyId = nil
	der, e := x509.CreateCertificate(rand.Reader, &template, &template, key.Public(), key)
	if e != nil {
		t.Fatal(e)
	}
	if !allowedPKISignature(x509.PureEd25519, der) {
		t.Fatal("valid Ed25519 certificate rejected")
	}
	var signed signedDER
	if rest, e := asn1.Unmarshal(der, &signed); e != nil || len(rest) != 0 {
		t.Fatal(e)
	}
	bad := bytes.Clone(signed.Signature.Bytes)
	clear(bad[:32])
	bad[0] = 1
	signed.Signature = asn1.BitString{Bytes: bad, BitLength: 512}
	altered, e := asn1.Marshal(signed)
	if e != nil {
		t.Fatal(e)
	}
	if allowedPKISignature(x509.PureEd25519, altered) {
		t.Fatal("Ed25519 CA signature accepted torsion-only R")
	}
	ca, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	crlDER, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour), SignatureAlgorithm: x509.PureEd25519}, ca, key)
	if e != nil {
		t.Fatal(e)
	}
	if !allowedPKISignature(x509.PureEd25519, crlDER) {
		t.Fatal("valid Ed25519 CRL rejected")
	}
	if rest, e := asn1.Unmarshal(crlDER, &signed); e != nil || len(rest) != 0 {
		t.Fatal(e)
	}
	bad = bytes.Clone(signed.Signature.Bytes)
	clear(bad[:32])
	bad[0] = 1
	signed.Signature = asn1.BitString{Bytes: bad, BitLength: 512}
	altered, e = asn1.Marshal(signed)
	if e != nil {
		t.Fatal(e)
	}
	if allowedPKISignature(x509.PureEd25519, altered) {
		t.Fatal("Ed25519 CRL accepted torsion-only R")
	}
}

func TestWholeCertificateProfilePrecedesRevocation(t *testing.T) {
	f := newFixture(t)
	// Go's general X.509 verifier admits RSA2048, but this WSEA profile does
	// not. Its authentic CRL must not produce CERT_004 before that decision.
	weak, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	interTemplate := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Disallowed RSA2048 intermediate"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(12 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	interDER, e := x509.CreateCertificate(rand.Reader, interTemplate, f.ca, &weak.PublicKey, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	inter, e := x509.ParseCertificate(interDER)
	if e != nil {
		t.Fatal(e)
	}
	leafTemplate := *f.leaf
	leafTemplate.AuthorityKeyId = nil
	leafTemplate.SignatureAlgorithm = x509.SHA256WithRSA
	leafDER, e := x509.CreateCertificate(rand.Reader, &leafTemplate, inter, &f.key.PublicKey, weak)
	if e != nil {
		t.Fatal(e)
	}
	revokedDER, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour), SignatureAlgorithm: x509.SHA256WithRSA, RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: f.leaf.SerialNumber, RevocationTime: f.now.Add(-time.Minute)}}}, inter, weak)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Certificates = append(certificatePEM(leafDER), certificatePEM(interDER)...)
	f.ev.CRLs = append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revokedDER}), f.ev.CRLs...)
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil || !strings.HasPrefix(e.Error(), "SIG_005:") {
		t.Fatalf("disallowed CA profile did not precede revoked CRL: %v", e)
	}
}

func TestAuthenticCertificateRequiresByteAlignedPublicKey(t *testing.T) {
	f := newFixture(t)
	// RightAlign can turn a 255-bit SPKI BIT STRING into a 32-byte Ed25519
	// key. Choose a key that fits that encoding, preserving its actual value.
	var key ed25519.PrivateKey
	for attempts := 0; attempts < 128; attempts++ {
		candidate := testKey(t, AlgorithmEd25519).(ed25519.PrivateKey)
		if candidate.Public().(ed25519.PublicKey)[0]&0x80 == 0 {
			key = candidate
			break
		}
	}
	if key == nil {
		t.Fatal("could not produce an Ed25519 key fitting the 255-bit test encoding")
	}
	replacePublisher(t, &f, key, AlgorithmEd25519)
	if _, err := Verify(f.module, f.ev, f.p, f.root, f.now); err != nil {
		t.Fatal("byte-aligned positive control failed", err)
	}
	block, _ := pem.Decode(f.ev.Certificates)
	var certificate signedDER
	if rest, err := asn1.Unmarshal(block.Bytes, &certificate); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	for remaining := certificate.TBS.Bytes; len(remaining) != 0; {
		var field asn1.RawValue
		var err error
		remaining, err = asn1.Unmarshal(remaining, &field)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, field)
	}
	index := 5
	if fields[0].Class == asn1.ClassContextSpecific && fields[0].Tag == 0 {
		index = 6
	}
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(fields[index].FullBytes, &spki); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	public := key.Public().(ed25519.PublicKey)
	shifted := make([]byte, 32)
	for i := range shifted {
		shifted[i] = public[i] << 1
		if i+1 < len(shifted) {
			shifted[i] |= public[i+1] >> 7
		}
	}
	spki.PublicKey = asn1.BitString{Bytes: shifted, BitLength: 255}
	rawSPKI, err := asn1.Marshal(spki)
	if err != nil {
		t.Fatal(err)
	}
	fields[index] = asn1.RawValue{FullBytes: rawSPKI}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, f.caKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	certificate.TBS = asn1.RawValue{FullBytes: tbs}
	certificate.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err := asn1.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("standard parser rejected the intended RightAlign fixture", err)
	}
	if !bytes.Equal(parsed.PublicKey.(ed25519.PublicKey), public) || parsed.CheckSignatureFrom(f.ca) != nil {
		t.Fatal("test certificate changed its signing key or has an invalid CA signature")
	}
	rule := f.p.Modules[f.m.ModuleID]
	rule.SPKI = SPKIDigest(parsed.RawSubjectPublicKeyInfo)
	f.p.Modules[f.m.ModuleID] = rule
	f.ev.Certificates = certificatePEM(der)
	if _, err = Verify(f.module, f.ev, f.p, f.root, f.now); err == nil || !strings.HasPrefix(err.Error(), "CERT_002:") {
		t.Fatalf("accepted authentic non-byte-aligned SPKI: %v", err)
	}
}
