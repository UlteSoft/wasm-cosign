//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecurecli

import (
	"bytes"
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

func TestSecureCLIEndToEnd(t *testing.T) {
	td, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CLI Root"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	ca, e = x509.ParseCertificate(caDER)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "CLI Publisher"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if e != nil {
		t.Fatal(e)
	}
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, ca, caKey)
	if e != nil {
		t.Fatal(e)
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	write := func(name, kind string, b []byte) string {
		t.Helper()
		p := filepath.Join(td, name)
		if kind != "" {
			b = pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b})
		}
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	root := write("root.pem", "CERTIFICATE", caDER)
	cert := write("leaf.pem", "CERTIFICATE", leafDER)
	crlPath := write("crls.pem", "X509 CRL", crl)
	keyPath := write("key.pem", "PRIVATE KEY", keyDER)
	module := write("module.wasm", "", []byte{0, 97, 115, 109, 1, 0, 0, 0, 0, 3, 1, 'x', 0})
	policy := filepath.Join(td, "policy")
	state := filepath.Join(td, "state-dir")
	run := func(args ...string) (string, error) {
		t.Helper()
		c := Command()
		var out bytes.Buffer
		c.SetOut(&out)
		c.SetErr(&out)
		c.SetArgs(args)
		err := c.Execute()
		return out.String(), err
	}
	if _, e = run("policy-init", "--output", policy, "--trust-root", root, "--state-dir", state, "--certificate", cert, "--module-id", "test.module"); e != nil {
		t.Fatal(e)
	}
	if _, e = run("sign", module, "--policy", policy, "--key", keyPath, "--certificate", cert, "--crl", crlPath, "--module-id", "test.module", "--module-version", "1", "--not-before", now.Add(-time.Minute).UTC().Format(time.RFC3339), "--not-after", now.Add(time.Hour).UTC().Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	if out, e := run("verify", module, "--policy", policy); e != nil || !strings.Contains(out, "VERIFIED") {
		t.Fatalf("verify: %s %v", out, e)
	}
	if _, e = run("policy-init", "--output", filepath.Join(td, "policy2"), "--trust-root", root, "--state-dir", state, "--certificate", cert, "--module-id", "test.module"); e == nil {
		t.Fatal("reset existing security state")
	}
	if _, e = run("policy-update", "--policy", policy, "--policy-version", "2", "--module-id", "second.module", "--certificate", cert, "--capabilities", "1"); e != nil {
		t.Fatal(e)
	}
	if _, e = run("verify", module, "--policy", policy); e != nil {
		t.Fatalf("retained first module after update: %v", e)
	}
	if _, e = run("policy-update", "--policy", policy, "--policy-version", "2"); e == nil {
		t.Fatal("accepted same-version policy update")
	}
	stateBytes, e := os.ReadFile(filepath.Join(state, "state"))
	if e != nil || string(stateBytes) != "UWVM-WSEA-STATE-1\n0 0 -\n" {
		t.Fatal("policy update modified VM state", e)
	}
	if _, e = run("policy-update", "--policy", policy, "--policy-version", "3", "--module-id", "test.module", "--algorithms", "ESP256"); e != nil {
		t.Fatal(e)
	}
	if _, e = run("verify", module, "--policy", policy); e == nil || !strings.Contains(e.Error(), "SIG_005") {
		t.Fatalf("removed ES256 was silently accepted: %v", e)
	}
	module2 := write("esp256.wasm", "", []byte{0, 97, 115, 109, 1, 0, 0, 0})
	if out, e := run("sign", module2, "--policy", policy, "--key", keyPath, "--certificate", cert, "--crl", crlPath, "--module-id", "test.module", "--module-version", "2", "--algorithm", "ESP256", "--not-before", now.Add(-time.Minute).UTC().Format(time.RFC3339), "--not-after", now.Add(time.Hour).UTC().Format(time.RFC3339)); e != nil || !strings.Contains(out, "ESP256") {
		t.Fatalf("explicit ESP256 signing: %s %v", out, e)
	}
	if out, e := run("verify", module2, "--policy", policy); e != nil || !strings.Contains(out, "ESP256") {
		t.Fatalf("ESP256 verification: %s %v", out, e)
	}
	beforeInvalid, e := os.ReadFile(policy)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = run("policy-update", "--policy", policy, "--policy-version", "4", "--module-id", "test.module", "--algorithms", "ESP256,ESP256"); e == nil {
		t.Fatal("accepted duplicate algorithm policy")
	}
	if _, e = run("policy-update", "--policy", policy, "--policy-version", "4", "--algorithms", "ES256"); e == nil {
		t.Fatal("changed algorithm rule without module identity")
	}
	afterInvalid, e := os.ReadFile(policy)
	if e != nil || !bytes.Equal(beforeInvalid, afterInvalid) {
		t.Fatal("rejected algorithm policy update modified protected policy", e)
	}
	tampered, e := os.ReadFile(module)
	if e != nil {
		t.Fatal(e)
	}
	tampered[12] ^= 1
	if e = os.WriteFile(module, tampered, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = run("verify", module, "--policy", policy); e == nil || !strings.Contains(e.Error(), "SIG_004") {
		t.Fatalf("tampered module: %v", e)
	}
}
