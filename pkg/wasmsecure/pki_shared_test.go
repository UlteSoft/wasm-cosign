// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// Re-sign actual certificate TBS bytes, so rejected profile cases still have
// valid CA signatures, unchanged signer keys, and genuine module signatures.
func rewriteCertificateExtension(t *testing.T, input []byte, key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier, replacement *pkix.Extension) []byte {
	t.Helper()
	block, _ := pem.Decode(input)
	var cert signedDER
	if rest, err := asn1.Unmarshal(block.Bytes, &cert); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	var fields []asn1.RawValue
	if rest, err := asn1.Unmarshal(cert.TBS.FullBytes, &fields); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	found := false
	for i, field := range fields {
		if field.Class != asn1.ClassContextSpecific || field.Tag != 3 {
			continue
		}
		var exts []pkix.Extension
		if rest, err := asn1.Unmarshal(field.Bytes, &exts); err != nil || len(rest) != 0 {
			t.Fatal(err)
		}
		var changed []pkix.Extension
		for _, ext := range exts {
			if !ext.Id.Equal(oid) {
				changed = append(changed, ext)
			}
		}
		if replacement != nil {
			changed = append(changed, *replacement)
		}
		encoded, err := asn1.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		fields[i] = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 3, IsCompound: true, Bytes: encoded}
		found = true
	}
	if !found {
		t.Fatal("no certificate extensions")
	}
	tbs, err := asn1.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbs)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	cert.TBS = asn1.RawValue{FullBytes: tbs}
	cert.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
	der, err := asn1.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePEM(der)
}

func TestSharedStrictPKIAdmission(t *testing.T) {
	aki := asn1.ObjectIdentifier{2, 5, 29, 35}
	ski := asn1.ObjectIdentifier{2, 5, 29, 14}
	bc := asn1.ObjectIdentifier{2, 5, 29, 19}
	policies := asn1.ObjectIdentifier{2, 5, 29, 32}
	constraints := asn1.ObjectIdentifier{2, 5, 29, 36}
	cases := []struct {
		name   string
		change func(*fixture)
	}{
		{"corrupt root self-signature", func(f *fixture) {
			block, _ := pem.Decode(f.root)
			block.Bytes[len(block.Bytes)-1] ^= 1
			f.root = certificatePEM(block.Bytes)
		}},
		{"missing leaf AKI", func(f *fixture) {
			f.ev.Certificates = rewriteCertificateExtension(t, f.ev.Certificates, f.caKey, aki, nil)
		}},
		{"wrong leaf AKI", func(f *fixture) {
			f.ev.Certificates = rewriteCertificateExtension(t, f.ev.Certificates, f.caKey, aki, &pkix.Extension{Id: aki, Value: []byte{0x30, 3, 0x80, 1, 42}})
		}},
		{"missing CA SKI", func(f *fixture) { f.root = rewriteCertificateExtension(t, f.root, f.caKey, ski, nil) }},
		{"noncritical CA constraints", func(f *fixture) {
			f.root = rewriteCertificateExtension(t, f.root, f.caKey, bc, &pkix.Extension{Id: bc, Value: []byte{0x30, 3, 1, 1, 255}})
		}},
		{"empty policy constraints", func(f *fixture) {
			f.ev.Certificates = rewriteCertificateExtension(t, f.ev.Certificates, f.caKey, constraints, &pkix.Extension{Id: constraints, Value: []byte{0x30, 0}})
		}},
		{"negative policy constraints", func(f *fixture) {
			f.ev.Certificates = rewriteCertificateExtension(t, f.ev.Certificates, f.caKey, constraints, &pkix.Extension{Id: constraints, Value: []byte{0x30, 3, 0x80, 1, 255}})
		}},
		{"malformed certificate policies", func(f *fixture) {
			f.ev.Certificates = rewriteCertificateExtension(t, f.ev.Certificates, f.caKey, policies, &pkix.Extension{Id: policies, Value: []byte{0x30, 1, 0xff}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.m.Embedded = true
			var err error
			f.ev.Signature, err = Sign(f.module, f.m, f.key)
			if err != nil {
				t.Fatal(err)
			}
			valid, err := Embed(f.module, f.ev)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = VerifyEmbedded(valid, f.p, f.root, f.now); err != nil {
				t.Fatal("valid control:", err)
			}
			tc.change(&f)
			module, err := Embed(f.module, f.ev)
			if err != nil {
				t.Fatal(err)
			}
			for _, verify := range []func([]byte, Policy, []byte, time.Time) (Manifest, error){VerifyEmbedded, VerifyEmbeddedPartial} {
				if _, err = verify(module, f.p, f.root, f.now); err == nil || !strings.HasPrefix(err.Error(), "CERT_") {
					t.Fatalf("strict PKI rejection missing: %v", err)
				}
			}
		})
	}
}
