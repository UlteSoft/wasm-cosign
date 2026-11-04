// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	module   []byte
	key      *ecdsa.PrivateKey
	caKey    *ecdsa.PrivateKey
	leaf, ca *x509.Certificate
	root     []byte
	ev       Evidence
	p        Policy
	m        Manifest
	now      time.Time
}

func certificatePEM(b []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b})
}
func newFixture(t *testing.T) fixture {
	t.Helper()
	var f fixture
	f.now = time.Unix(1800000000, 0)
	f.module = []byte{0, 97, 115, 109, 1, 0, 0, 0}
	var e error
	f.caKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	f.key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "WSEA Root"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	b, e := x509.CreateCertificate(rand.Reader, ca, ca, &f.caKey.PublicKey, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.root = certificatePEM(b)
	f.ca, e = x509.ParseCertificate(b)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "WSEA Publisher"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	b, e = x509.CreateCertificate(rand.Reader, leaf, f.ca, &f.key.PublicKey, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Certificates = certificatePEM(b)
	f.leaf, e = x509.ParseCertificate(b)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.CRLs = f.crl(t, f.now.Add(-time.Minute), f.now.Add(time.Hour), false)
	f.p = Policy{Version: 1, TrustRoot: "/secure/root.pem", StateDir: "/secure/state", MaxCRLAgeSeconds: 86400, MaxModuleBytes: 104857600, Modules: map[string]ModuleRule{"test.module": {ID: "test.module", ABI: "uwvm2", SPKI: SPKIDigest(f.leaf.RawSubjectPublicKeyInfo), MinVersion: 1, AllowedCapabilities: 63}}}
	f.m = Manifest{Embedded: true, ModuleID: "test.module", Version: 2, Epoch: 1, NotBefore: uint64(f.now.Add(-time.Minute).Unix()), NotAfter: uint64(f.now.Add(time.Hour).Unix()), ABI: "uwvm2", Capabilities: 1}
	f.ev.Signature, e = Sign(f.module, f.m, f.key)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f fixture) crl(t *testing.T, this, next time.Time, revoked bool) []byte {
	t.Helper()
	template := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: this, NextUpdate: next}
	if revoked {
		template.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: f.leaf.SerialNumber, RevocationTime: this}}
	}
	b, e := x509.CreateRevocationList(rand.Reader, template, f.ca, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: b})
}
func TestVerifySecurityBoundaries(t *testing.T) {
	f := newFixture(t)
	if _, e := Verify(f.module, f.ev, f.p, f.root, f.now); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name, code string
		change     func(*fixture)
	}{
		{"changed module", "SIG_004", func(f *fixture) { f.module = append(f.module, 0, 1, 0) }},
		{"wrong signer pin", "CERT_006", func(f *fixture) {
			r := f.p.Modules["test.module"]
			r.SPKI = strings.Repeat("0", 64)
			f.p.Modules["test.module"] = r
		}},
		{"version rollback", "POL_001", func(f *fixture) { r := f.p.Modules["test.module"]; r.MinVersion = 3; f.p.Modules["test.module"] = r }},
		{"epoch rollback", "POL_001", func(f *fixture) { r := f.p.Modules["test.module"]; r.MinEpoch = 2; f.p.Modules["test.module"] = r }},
		{"unauthorized capabilities", "POL_003", func(f *fixture) {
			r := f.p.Modules["test.module"]
			r.AllowedCapabilities = 0
			f.p.Modules["test.module"] = r
		}},
		{"expired manifest", "POL_004", func(f *fixture) { f.now = f.now.Add(2 * time.Hour) }},
		{"missing CRL", "CERT_005", func(f *fixture) { f.ev.CRLs = nil }},
		{"expired CRL", "CERT_005", func(f *fixture) { f.ev.CRLs = f.crl(t, f.now.Add(-2*time.Hour), f.now.Add(-time.Hour), false) }},
		{"expired CRL cannot hide behind fresh CRL", "CERT_005", func(f *fixture) {
			f.ev.CRLs = append(bytes.Clone(f.ev.CRLs), f.crl(t, f.now.Add(-2*time.Hour), f.now.Add(-time.Hour), false)...)
		}},
		{"stale CRL", "CERT_005", func(f *fixture) { f.p.MaxCRLAgeSeconds = 1 }},
		{"future CRL", "CERT_005", func(f *fixture) { f.ev.CRLs = f.crl(t, f.now.Add(time.Hour), f.now.Add(2*time.Hour), false) }},
		{"revoked signer", "CERT_004", func(f *fixture) { f.ev.CRLs = f.crl(t, f.now.Add(-time.Minute), f.now.Add(time.Hour), true) }},
		{"wrong root", "CERT_002", func(f *fixture) { other := newFixture(t); f.root = other.root }},
		{"signature tampering", "SIG_003", func(f *fixture) {
			f.ev.Signature = bytes.Clone(f.ev.Signature)
			f.ev.Signature[len(f.ev.Signature)-33] ^= 1
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := newFixture(t)
			tc.change(&candidate)
			_, e := Verify(candidate.module, candidate.ev, candidate.p, candidate.root, candidate.now)
			if e == nil || !strings.Contains(e.Error(), tc.code) {
				t.Fatalf("got %v, expected %s", e, tc.code)
			}
		})
	}
}
func TestStrictCOSE(t *testing.T) {
	f := newFixture(t)
	cases := [][]byte{append(bytes.Clone(f.ev.Signature), 0), append([]byte{0xd8, 18}, f.ev.Signature[1:]...), append([]byte{0xd2, 0x84, 0x58, 3}, f.ev.Signature[3:]...)}
	for _, b := range cases {
		if _, _, _, e := Parse(b); e == nil {
			t.Fatalf("accepted noncanonical %x", b)
		}
	}
	for i := 0; i < len(f.ev.Signature); i++ {
		if _, _, _, e := Parse(f.ev.Signature[:i]); e == nil {
			t.Fatalf("accepted truncation at %d", i)
		}
	}
	m, p, s, e := Parse(f.ev.Signature)
	if e != nil {
		t.Fatal(e)
	}
	if m.ModuleID != "test.module" {
		t.Fatal(m)
	}
	s = bytes.Clone(s)
	high := new(big.Int).Sub(f.key.Params().N, new(big.Int).SetBytes(s[32:]))
	high.FillBytes(s[32:])
	if e = verifySignature(p, s, &f.key.PublicKey); e == nil {
		t.Fatal("accepted high-S")
	}
}
func TestStrictPolicy(t *testing.T) {
	f := newFixture(t)
	p, e := f.p.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ParsePolicy(p); e != nil {
		t.Fatal(e)
	}
	cases := []string{string(p) + "unknown=1\n", string(p) + "policy_version=1\n", strings.Replace(string(p), "policy_version=1", "policy_version=01", 1), strings.Replace(string(p), "|63\n", "|64\n", 1), string(p) + "module=test.module|uwvm2|" + strings.Repeat("0", 64) + "|1|0|0\n"}
	for _, b := range cases {
		if _, e = ParsePolicy([]byte(b)); e == nil {
			t.Fatalf("accepted invalid policy %q", b)
		}
	}
}
func TestExclusivePublishAndHTTPSBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out")
	if e := WriteExclusive(path, []byte("first"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := WriteExclusive(path, []byte("second"), 0600); e == nil {
		t.Fatal("overwrote existing file")
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "first" {
		t.Fatal(string(b), e)
	}
	for _, u := range []string{"http://example.com/sig", "file:///tmp/sig", "https://u:p@example.com/sig", "https://example.com/sig#fragment"} {
		if _, e := FetchHTTPS(context.Background(), u, 1024); e == nil {
			t.Fatalf("accepted %s", u)
		}
	}
	if _, e = readBounded(strings.NewReader("12345"), 4); e == nil {
		t.Fatal("accepted oversized input")
	}
}
func FuzzParse(f *testing.F) {
	f.Add([]byte{0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa0})
	f.Fuzz(func(_ *testing.T, b []byte) { _, _, _, _ = Parse(b) })
}

func TestIntermediatePathRequiresEveryIssuerCRL(t *testing.T) {
	f := newFixture(t)
	ik, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Intermediate"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	ider, e := x509.CreateCertificate(rand.Reader, template, f.ca, &ik.PublicKey, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	inter, e := x509.ParseCertificate(ider)
	if e != nil {
		t.Fatal(e)
	}
	leafTemplate := *f.leaf
	leafDER, e := x509.CreateCertificate(rand.Reader, &leafTemplate, inter, &f.key.PublicKey, ik)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Certificates = append(certificatePEM(leafDER), certificatePEM(ider)...)
	crlDER, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour)}, inter, ik)
	if e != nil {
		t.Fatal(e)
	}
	leafCRL := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil || !strings.Contains(e.Error(), "CERT_005") {
		t.Fatalf("missing intermediate CRL: %v", e)
	}
	f.ev.CRLs = append(bytes.Clone(f.ev.CRLs), leafCRL...)
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e != nil {
		t.Fatalf("valid full chain: %v", e)
	}
	revokedDER, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: f.now.Add(-time.Minute), NextUpdate: f.now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: inter.SerialNumber, RevocationTime: f.now.Add(-time.Minute)}}}, f.ca, f.caKey)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.CRLs = append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: revokedDER}), leafCRL...)
	if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil || !strings.Contains(e.Error(), "CERT_004") {
		t.Fatalf("revoked intermediate: %v", e)
	}
}

func TestLeafUsageAndValidity(t *testing.T) {
	for _, name := range []string{"no-codeSigning", "no-digitalSignature", "CA-leaf", "expired"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			template := *f.leaf
			switch name {
			case "no-codeSigning":
				template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "no-digitalSignature":
				template.KeyUsage = x509.KeyUsageKeyEncipherment
			case "CA-leaf":
				template.IsCA = true
			case "expired":
				template.NotAfter = f.now.Add(-time.Minute)
			}
			der, e := x509.CreateCertificate(rand.Reader, &template, f.ca, &f.key.PublicKey, f.caKey)
			if e != nil {
				t.Fatal(e)
			}
			f.ev.Certificates = certificatePEM(der)
			if _, e = Verify(f.module, f.ev, f.p, f.root, f.now); e == nil {
				t.Fatal("accepted invalid leaf")
			}
		})
	}
}

func TestPEMCannotHideMalformedOrLeadingMaterial(t *testing.T) {
	f := newFixture(t)
	for _, b := range [][]byte{append([]byte("garbage"), f.ev.Certificates...), append([]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), f.ev.Certificates...), append(bytes.Clone(f.ev.Certificates), []byte("trailing")...)} {
		if _, e := Certificates(b); e == nil {
			t.Fatal("accepted malformed certificate PEM")
		}
	}
}
