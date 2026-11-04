//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedExpiryAtStateGate(t *testing.T) {
	for _, kind := range []string{"manifest", "certificate", "crl", "crl-max-age"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.m.Embedded = true
			f.m.NotAfter = uint64(f.now.Add(2 * time.Hour).Unix())
			expires := f.now.Add(30 * time.Minute)
			switch kind {
			case "manifest":
				f.m.NotAfter = uint64(expires.Unix())
			case "certificate":
				leaf := *f.leaf
				leaf.NotAfter = expires
				der, err := x509.CreateCertificate(rand.Reader, &leaf, f.ca, &f.key.PublicKey, f.caKey)
				if err != nil {
					t.Fatal(err)
				}
				f.ev.Certificates = certificatePEM(der)
			case "crl":
				f.ev.CRLs = f.crl(t, f.now.Add(-time.Minute), expires, false)
			case "crl-max-age":
				f.p.MaxCRLAgeSeconds = 1800
				f.ev.CRLs = f.crl(t, f.now, f.now.Add(time.Hour), false)
			}
			var err error
			f.ev.Signature, err = Sign(f.module, f.m, f.key)
			if err != nil {
				t.Fatal(err)
			}
			f.p.StateDir = canonicalTempDir(t)
			if err = os.Chmod(f.p.StateDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(f.p.StateDir, "state"), []byte(BootstrapState), 0600); err != nil {
				t.Fatal(err)
			}
			pb, err := f.p.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			m, err := Verify(f.module, f.ev, f.p, f.root, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if err = CheckState(pb, f.root, f.p, m, expires.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			// max_age is inclusive in the shared core; the first invalid second follows it.
			if kind == "crl-max-age" {
				expires = expires.Add(time.Second)
			}
			if err = CheckState(pb, f.root, f.p, m, expires); err == nil || !strings.Contains(err.Error(), "POL_004") {
				t.Fatalf("expired %s authorized: %v", kind, err)
			}
		})
	}
}

func TestStateRequiresFinalNewline(t *testing.T) {
	f := newFixture(t)
	f.p.StateDir = canonicalTempDir(t)
	if err := os.Chmod(f.p.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	pb, err := f.p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(append(append([]byte{}, pb...), f.root...))
	b := fmt.Sprintf("UWVM-WSEA-STATE-1\n1 %d %x", f.now.Unix(), d)
	path := filepath.Join(f.p.StateDir, "state")
	if err = os.WriteFile(path, []byte(b), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CheckState(pb, f.root, f.p, f.m, f.now); err == nil {
		t.Fatal("accepted unterminated protected state")
	}
	if err = os.WriteFile(path, []byte(b+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CheckState(pb, f.root, f.p, f.m, f.now); err != nil {
		t.Fatal(err)
	}
}

func TestMultisignatureUsesEarliestEvidenceExpiry(t *testing.T) {
	f, list := multiFixture(t, AlgorithmEd25519)
	expires := f.now.Add(20 * time.Minute)
	list[1].CRLs = f.crl(t, f.now.Add(-time.Minute), expires, false)
	for _, reverse := range []bool{false, true} {
		if reverse {
			list[0], list[1] = list[1], list[0]
		}
		module, err := EmbedAll(f.module, list)
		if err != nil {
			t.Fatal(err)
		}
		for _, verify := range []func([]byte, Policy, []byte, time.Time) (Manifest, error){VerifyEmbedded, VerifyEmbeddedPartial} {
			m, err := verify(module, f.p, f.root, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if m.validUntil != uint64(expires.Unix()) {
				t.Fatalf("lost earliest signer expiry: %d", m.validUntil)
			}
		}
	}
}
