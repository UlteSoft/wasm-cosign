// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"strings"
	"testing"
)

func embeddedFixture(t *testing.T, f fixture) []byte {
	t.Helper()
	f.m.Embedded = true
	sig, e := Sign(f.module, f.m, f.key)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Signature = sig
	b, e := Embed(f.module, f.ev)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestEmbeddedAll13Algorithms(t *testing.T) {
	for _, p := range algorithmProfiles {
		t.Run(string(p.name), func(t *testing.T) {
			f := newFixture(t)
			f.m.Embedded = true
			key := testKey(t, p.name)
			replacePublisher(t, &f, key, p.name)
			b, e := Embed(f.module, f.ev)
			if e != nil {
				t.Fatal(e)
			}
			m, e := VerifyEmbedded(b, f.p, f.root, f.now)
			if e != nil || !m.Embedded || m.Algorithm != p.name {
				t.Fatal(m, e)
			}
			f.ev.Signature[len(f.ev.Signature)-1] ^= 1
			bad, e := Embed(f.module, f.ev)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = VerifyEmbedded(bad, f.p, f.root, f.now); e == nil || !strings.Contains(e.Error(), "SIG_003") {
				t.Fatal("forged signature", e)
			}
		})
	}
}
func TestEmbeddedSectionBoundaries(t *testing.T) {
	f := newFixture(t)
	// A second ordinary custom section, including signature-like data, is covered.
	data := appendULEB(nil, 1)
	data = append(data, 'x')
	data = append(data, SectionName...)
	f.module = append(f.module, 0)
	f.module = appendULEB(f.module, uint32(len(data)))
	f.module = append(f.module, data...)
	good := embeddedFixture(t, f)
	core, ev, e := Extract(good)
	if e != nil || !bytes.Equal(core, f.module) {
		t.Fatal(e)
	}
	if _, e = VerifyEmbedded(good, f.p, f.root, f.now); e != nil {
		t.Fatal(e)
	}
	if _, e = SigningInput(good, false); e == nil {
		t.Fatal("silent signature replacement")
	}
	if b, e := SigningInput(good, true); e != nil || !bytes.Equal(b, f.module) {
		t.Fatal(e)
	}
	if _, e = Embed(good, ev); e == nil {
		t.Fatal("nested signature section")
	}
	mutate := bytes.Clone(good)
	mutate[len(f.module)-1] ^= 1
	legacySignature, e := Sign(f.module, f.m, f.key)
	if e != nil {
		t.Fatal(e)
	}
	f.ev.Signature = legacySignature
	legacy, e := Embed(f.module, f.ev)
	if e != nil {
		t.Fatal(e)
	}
	section := good[len(f.module):]
	badLength := append(bytes.Clone(f.module), 0, 0xff, 0xff, 0xff, 0xff, 0x0f)
	nonminimal := append(bytes.Clone(f.module), 0)
	p := 1
	n, e := readULEB(section, &p, false)
	if e != nil {
		t.Fatal(e)
	}
	length := appendULEB(nil, n)
	length[len(length)-1] |= 128
	length = append(length, 0)
	nonminimal = append(nonminimal, length...)
	nonminimal = append(nonminimal, section[p:]...)
	cases := []struct {
		name string
		b    []byte
		code string
	}{
		{"missing", f.module, "SIG_001"},
		{"appended bytes", append(bytes.Clone(good), 0), "SIG_002"},
		{"appended ordinary custom section", append(bytes.Clone(good), 0, 1, 0), "SIG_002"},
		{"duplicate WSEA", append(bytes.Clone(good), section...), "SIG_002"},
		{"signed custom content", mutate, "SIG_004"},
		{"truncated", good[:len(good)-1], "SIG_002"},
		{"overflow length", badLength, "SIG_002"},
		{"nonminimal WSEA length", nonminimal, "SIG_002"},
		{"detached schema downgrade", legacy, "SIG_002"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, e := VerifyEmbedded(tc.b, f.p, f.root, f.now)
			if e == nil || !strings.Contains(e.Error(), tc.code) {
				t.Fatalf("wanted %s: %v", tc.code, e)
			}
		})
	}
}
func FuzzEmbeddedSectionParser(f *testing.F) {
	f.Add([]byte{0, 97, 115, 109, 1, 0, 0, 0})
	f.Add([]byte{0, 97, 115, 109, 1, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 15})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > MaxEmbeddedEvidenceBytes+1024 {
			t.Skip()
		}
		_, _, _ = Extract(b)
	})
}
