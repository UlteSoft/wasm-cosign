// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

func contribution(t *testing.T, f fixture, key any, name Algorithm, serial int64, m Manifest) (Evidence, string) {
	t.Helper()
	leaf := *f.leaf
	leaf.SerialNumber = big.NewInt(serial)
	der, err := x509.CreateCertificate(rand.Reader, &leaf, f.ca, testPublic(key), f.caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	m.Embedded = true
	m.Algorithm = name
	sig, err := Sign(f.module, m, key)
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{Signature: sig, Certificates: certificatePEM(der), CRLs: bytes.Clone(f.ev.CRLs)}, SPKIDigest(cert.RawSubjectPublicKeyInfo)
}

func multiFixture(t *testing.T, name Algorithm) (fixture, []Evidence) {
	t.Helper()
	f := newFixture(t)
	f.m.Embedded = true
	first, _ := contribution(t, f, f.key, AlgorithmES256, 2, f.m)
	second, pin := contribution(t, f, testKey(t, name), name, 3, f.m)
	rule := f.p.Modules[f.m.ModuleID]
	rule.AdditionalSPKIs = []string{pin}
	rule.SignatureThreshold = 2
	for _, profile := range algorithmProfiles {
		rule.Algorithms = append(rule.Algorithms, profile.name)
	}
	f.p.Modules[f.m.ModuleID] = rule
	return f, []Evidence{first, second}
}

func TestMultipleSignaturesAllProfiles(t *testing.T) {
	for _, profile := range algorithmProfiles {
		t.Run(string(profile.name), func(t *testing.T) {
			f, list := multiFixture(t, profile.name)
			for _, reverse := range []bool{false, true} {
				if reverse {
					list[0], list[1] = list[1], list[0]
				}
				module, err := EmbedAll(f.module, list)
				if err != nil {
					t.Fatal(err)
				}
				m, err := VerifyEmbedded(module, f.p, f.root, f.now)
				if err != nil || len(m.SignerSPKIs) != 2 || len(m.SignatureAlgorithms) != 2 {
					t.Fatal(m, err)
				}
				if _, _, err = Extract(module); err == nil {
					t.Fatal("single-contribution extraction silently discarded signatures")
				}
			}
			for index := range list {
				bad := append([]Evidence(nil), list...)
				bad[index].Signature = bytes.Clone(bad[index].Signature)
				bad[index].Signature[len(bad[index].Signature)-1] ^= 1
				module, err := EmbedAll(f.module, bad)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = VerifyEmbedded(module, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "SIG_003") {
					t.Fatal("forgery survived another valid signature", err)
				}
			}
		})
	}
}

func TestSignatureQuorumCannotBeDowngraded(t *testing.T) {
	f, list := multiFixture(t, AlgorithmEd25519)
	one, err := Embed(f.module, list[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyEmbedded(one, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "POL_002") {
		t.Fatal("stripped quorum accepted", err)
	}
	if _, err = Verify(f.module, list[0], f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "POL_002") {
		t.Fatal("single Verify bypassed quorum", err)
	}
	if m, err := VerifyEmbeddedPartial(one, f.p, f.root, f.now); err != nil || len(m.SignerSPKIs) != 1 {
		t.Fatal("explicit signing partial", m, err)
	}
	// A second algorithm under the SAME public key is not another signer.
	same, _ := contribution(t, f, f.key, AlgorithmESP256, 4, f.m)
	duplicateKey, err := EmbedAll(f.module, []Evidence{list[0], same})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyEmbedded(duplicateKey, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "POL_002") {
		t.Fatal("same key counted twice", err)
	}
	// The protected administrator may explicitly permit 1-of-2, while every
	// contribution that is present must still authenticate successfully.
	rule := f.p.Modules[f.m.ModuleID]
	rule.SignatureThreshold = 1
	f.p.Modules[f.m.ModuleID] = rule
	if _, err = VerifyEmbedded(one, f.p, f.root, f.now); err != nil {
		t.Fatal(err)
	}
	bundle, err := EmbedAll(f.module, list)
	if err != nil {
		t.Fatal(err)
	}
	rule.AdditionalSPKIs = nil
	f.p.Modules[f.m.ModuleID] = rule
	if _, err = VerifyEmbedded(bundle, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "CERT_006") {
		t.Fatal("untrusted extra signer ignored", err)
	}
}

func TestMultipleSignaturesExactManifestAndEncoding(t *testing.T) {
	f, list := multiFixture(t, AlgorithmEd25519)
	changed := f.m
	changed.Version++
	list[1], _ = contribution(t, f, testKey(t, AlgorithmEd25519), AlgorithmEd25519, 4, changed)
	certs, err := Certificates(list[1].Certificates)
	if err != nil {
		t.Fatal(err)
	}
	rule := f.p.Modules[f.m.ModuleID]
	rule.AdditionalSPKIs = []string{SPKIDigest(certs[0].RawSubjectPublicKeyInfo)}
	f.p.Modules[f.m.ModuleID] = rule
	bundle, err := EmbedAll(f.module, list)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyEmbedded(bundle, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "SIG_002") {
		t.Fatal("different authenticated manifests accepted", err)
	}
	if _, err = EmbedAll(f.module, []Evidence{list[0], list[0]}); err == nil {
		t.Fatal("identical contributions accepted")
	}
	if _, err = EmbedAll(f.module, nil); err == nil {
		t.Fatal("zero signatures")
	}
	if _, err = EmbedAll(f.module, make([]Evidence, MaxSignatures+1)); err == nil {
		t.Fatal("unbounded signatures")
	}
	// Bypass the producer to ensure the untrusted decoder rejects duplicates.
	payload := []byte{0x82, 2, 0x82}
	for i := 0; i < 2; i++ {
		payload = append(payload, 0x83)
		payload = appendBytes(payload, list[0].Signature)
		payload = appendBytes(payload, list[0].Certificates)
		payload = appendBytes(payload, list[0].CRLs)
	}
	section := appendULEB(nil, uint32(len(SectionName)))
	section = append(section, SectionName...)
	section = append(section, payload...)
	malformed := append(bytes.Clone(f.module), 0)
	malformed = appendULEB(malformed, uint32(len(section)))
	malformed = append(malformed, section...)
	if _, _, err = ExtractAll(malformed); err == nil || !strings.Contains(err.Error(), "SIG_002") {
		t.Fatal("decoder accepted duplicate", err)
	}
}

func TestProtectedMultipleSignerPolicy(t *testing.T) {
	f, _ := multiFixture(t, AlgorithmEd25519)
	encoded, err := f.p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePolicy(encoded)
	if err != nil || p.Modules[f.m.ModuleID].RequiredSignatures() != 2 {
		t.Fatal(err)
	}
	again, err := p.Marshal()
	if err != nil || !bytes.Equal(encoded, again) {
		t.Fatal("noncanonical policy round trip", err)
	}
	id := f.m.ModuleID
	for _, suffix := range []string{
		"module_threshold=" + id + "|1\n",
		"module_signer=" + id + "|" + p.Modules[id].SPKI + "\n",
		"module_signer=unknown.module|" + p.Modules[id].SPKI + "\n",
	} {
		if _, err = ParsePolicy(append(bytes.Clone(encoded), suffix...)); err == nil {
			t.Fatal("invalid policy accepted", suffix)
		}
	}
	for _, bad := range []string{"0", "3", "9", "02"} {
		data := bytes.Replace(encoded, []byte("module_threshold="+id+"|2"), []byte("module_threshold="+id+"|"+bad), 1)
		if _, err = ParsePolicy(data); err == nil {
			t.Fatal("invalid threshold", bad)
		}
	}
}

func TestMaximumDistinctSignatureQuorum(t *testing.T) {
	f := newFixture(t)
	f.m.Embedded = true
	rule := f.p.Modules[f.m.ModuleID]
	rule.SignatureThreshold = MaxSignatures
	var list []Evidence
	for i := 0; i < MaxSignatures; i++ {
		key := any(f.key)
		if i != 0 {
			key = testKey(t, AlgorithmES256)
		}
		ev, pin := contribution(t, f, key, AlgorithmES256, int64(i+2), f.m)
		list = append(list, ev)
		if i != 0 {
			rule.AdditionalSPKIs = append(rule.AdditionalSPKIs, pin)
		}
	}
	f.p.Modules[f.m.ModuleID] = rule
	full, err := EmbedAll(f.module, list)
	if err != nil {
		t.Fatal(err)
	}
	if m, err := VerifyEmbedded(full, f.p, f.root, f.now); err != nil || len(m.SignerSPKIs) != MaxSignatures {
		t.Fatal(m, err)
	}
	for missing := range list {
		stripped := append([]Evidence(nil), list[:missing]...)
		stripped = append(stripped, list[missing+1:]...)
		module, err := EmbedAll(f.module, stripped)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = VerifyEmbedded(module, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "POL_002") {
			t.Fatal("stripped signer", missing, err)
		}
	}
}

func TestMultiSignatureRevocationIsNotMasked(t *testing.T) {
	f, list := multiFixture(t, AlgorithmEd25519)
	revoked := fixture{ca: f.ca, caKey: f.caKey, leaf: &x509.Certificate{SerialNumber: big.NewInt(3)}}
	list[1].CRLs = revoked.crl(t, f.now.Add(-time.Minute), f.now.Add(time.Hour), true)
	rule := f.p.Modules[f.m.ModuleID]
	rule.SignatureThreshold = 1
	f.p.Modules[f.m.ModuleID] = rule
	module, err := EmbedAll(f.module, list)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyEmbedded(module, f.p, f.root, f.now); err == nil || !strings.Contains(err.Error(), "CERT_004") {
		t.Fatal("revoked contribution masked by valid contribution", err)
	}
}
