// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Produce the retired domain independently of the public signing entry point.
func legacyCOSE(t *testing.T, f fixture) []byte {
	t.Helper()
	_, payload, _, err := Parse(f.ev.Signature)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte("uwvm-wsea-v2"), []byte("uwvm-wsea-v1"), 1)
	p, _ := profile(AlgorithmES256)
	sig, err := signAlgorithm(p, payload, f.key)
	if err != nil {
		t.Fatal(err)
	}
	out := appendBytes([]byte{0xd2, 0x84}, p.protected())
	out = append(out, 0xa0)
	out = appendBytes(out, payload)
	return appendBytes(out, sig)
}

func TestVerifyRequiresWASMContainer(t *testing.T) {
	f := newFixture(t)
	module := append(bytes.Clone(f.module), 1, 3, 0)
	m := f.m
	m.Size = uint64(len(module))
	digest := sha256.Sum256(module)
	m.Digest = digest[:]
	p, _ := profile(AlgorithmES256)
	payload := m.payload()
	sig, err := signAlgorithm(p, payload, f.key)
	if err != nil {
		t.Fatal(err)
	}
	out := appendBytes([]byte{0xd2, 0x84}, p.protected())
	out = append(out, 0xa0)
	out = appendBytes(out, payload)
	f.ev.Signature = appendBytes(out, sig)
	if _, err = Verify(module, f.ev, f.p, f.root, f.now); err == nil {
		t.Fatal("verified independently signed malformed WASM container")
	}
}

func TestOnlyEmbeddedV2Domain(t *testing.T) {
	f := newFixture(t)
	f.m.Embedded = false
	if _, err := Sign(f.module, f.m, f.key); err == nil {
		t.Fatal("signed retired detached profile")
	}
	f.ev.Signature = legacyCOSE(t, f)
	if _, _, _, err := Parse(f.ev.Signature); err == nil {
		t.Fatal("parsed retired v1 domain")
	}
	if _, err := Verify(f.module, f.ev, f.p, f.root, f.now); err == nil {
		t.Fatal("verified retired v1 domain")
	}
}

func TestSigningRequiresWASMContainer(t *testing.T) {
	f := newFixture(t)
	f.m.Embedded = true
	signed := embeddedFixture(t, f)
	for name, input := range map[string][]byte{
		"text":                  []byte("arbitrary non-WASM object"),
		"elf":                   append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 20)...),
		"zip":                   append([]byte{'P', 'K', 3, 4}, make([]byte, 20)...),
		"truncated section":     append(bytes.Clone(f.module), 1, 3, 0),
		"truncated custom name": append(bytes.Clone(f.module), 0, 1, 3),
		"already signed":        signed,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign(input, f.m, f.key); err == nil {
				t.Fatal("signed invalid input")
			}
		})
	}
	if _, err := Sign(f.module, f.m, f.key); err != nil {
		t.Fatal(err)
	}
}
