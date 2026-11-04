//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestUntrustedFIFOSymlinkAndProtectedHardlink(t *testing.T) {
	td := t.TempDir()
	fifo := filepath.Join(td, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { _, e := ReadBounded(fifo, 1024); done <- e }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("accepted FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO sidecar blocked before fstat")
	}
	regular := filepath.Join(td, "regular")
	if e := os.WriteFile(regular, []byte("data"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(td, "link")
	if e := os.Symlink(regular, link); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadBounded(link, 1024); e == nil {
		t.Fatal("followed untrusted symlink")
	}
	hard := filepath.Join(td, "hard")
	if e := os.Link(regular, hard); e != nil {
		t.Fatal(e)
	}
	if e := ProtectedPath(regular, false); e == nil {
		t.Fatal("accepted hard-linked trust file")
	}
}

func TestProtectedMonotonicState(t *testing.T) {
	f := newFixture(t)
	f.p.StateDir = canonicalTempDir(t)
	if e := os.Chmod(f.p.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	pb, e := f.p.Marshal()
	if e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(f.p.StateDir, "state")
	write := func(s string) {
		t.Helper()
		if e := os.WriteFile(state, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(BootstrapState)
	if e = CheckState(pb, f.root, f.p, f.m, f.now); e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	h.Write(pb)
	h.Write(f.root)
	digest := hex.EncodeToString(h.Sum(nil))
	header := fmt.Sprintf("UWVM-WSEA-STATE-1\n1 %d %s\n", f.now.Unix(), digest)
	write(header + "test.module|2|1\n")
	if e = CheckState(pb, f.root, f.p, f.m, f.now); e != nil {
		t.Fatal(e)
	}
	cases := []struct{ body, code string }{
		{header + "test.module|3|1\n", "POL_001"},
		{header + "test.module|2|2\n", "POL_001"},
		{fmt.Sprintf("UWVM-WSEA-STATE-1\n1 %d %s\n", f.now.Unix()+1, digest), "POL_004"},
		{"UWVM-WSEA-STATE-1\n1 0 " + strings.Repeat("0", 64) + "\n", "POL_002"},
		{"UWVM-WSEA-STATE-1\n2 0 " + digest + "\n", "POL_002"},
		{"UWVM-WSEA-STATE-1\n0 1 -\n", "POL_002"},
		{header + "test.module|2|1\ntest.module|2|1\n", "POL_002"},
	}
	for _, tc := range cases {
		write(tc.body)
		if e = CheckState(pb, f.root, f.p, f.m, f.now); e == nil || !strings.Contains(e.Error(), tc.code) {
			t.Fatalf("%q: got %v, expected %s", tc.body, e, tc.code)
		}
	}
	write(header + "test.module|2|1\n")
	marker := filepath.Join(f.p.StateDir, "revoked-"+f.p.Modules[f.m.ModuleID].SPKI)
	if e = os.WriteFile(marker, []byte("WSEA authenticated revocation\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = CheckState(pb, f.root, f.p, f.m, f.now); e == nil || !strings.Contains(e.Error(), "CERT_004") {
		t.Fatalf("ignored protected revocation marker: %v", e)
	}
	if e = os.Remove(marker); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink("missing-target", marker); e != nil {
		t.Fatal(e)
	}
	if e = CheckState(pb, f.root, f.p, f.m, f.now); e == nil || !strings.Contains(e.Error(), "CERT_004") {
		t.Fatalf("followed or ignored symlink revocation marker: %v", e)
	}
}

func TestCurrentStateClockObservation(t *testing.T) {
	f := newFixture(t)
	f.p.StateDir = canonicalTempDir(t)
	if err := os.Chmod(f.p.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	pb, err := f.p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	h.Write(pb)
	h.Write(f.root)
	digest := hex.EncodeToString(h.Sum(nil))
	now := time.Now()
	state := filepath.Join(f.p.StateDir, "state")
	current := fmt.Sprintf("UWVM-WSEA-STATE-1\n1 %d %s\ntest.module|2|1\n", now.Unix(), digest)
	if err = os.WriteFile(state, []byte(current), 0600); err != nil {
		t.Fatal(err)
	}
	earlier := time.Unix(now.Unix()-2, 0)
	if err = CheckState(pb, f.root, f.p, f.m, earlier); err == nil || !strings.Contains(err.Error(), "POL_004") {
		t.Fatalf("fixed-time API lost its explicit timestamp: %v", err)
	}
	if err = CheckCurrentState(pb, f.root, f.p, f.m, earlier); err != nil {
		t.Fatalf("earlier request incorrectly rejected after a later commit: %v", err)
	}
	if err = CheckCurrentState(pb, f.root, f.p, f.m, now.Add(time.Minute)); err == nil || !strings.Contains(err.Error(), "POL_004") {
		t.Fatalf("ignored rollback relative to request observation: %v", err)
	}
	unchanged, err := os.ReadFile(state)
	if err != nil || string(unchanged) != current {
		t.Fatalf("read-only state check changed protected state: %v", err)
	}
	// Advance this independent test's clock floor and never restore it.
	future := fmt.Sprintf("UWVM-WSEA-STATE-1\n1 %d %s\ntest.module|2|1\n", now.Unix()+3600, digest)
	if err = os.WriteFile(state, []byte(future), 0600); err != nil {
		t.Fatal(err)
	}
	if err = CheckCurrentState(pb, f.root, f.p, f.m, earlier); err == nil || !strings.Contains(err.Error(), "POL_004") {
		t.Fatalf("clamped or ignored protected future clock floor: %v", err)
	}
	unchanged, err = os.ReadFile(state)
	if err != nil || string(unchanged) != future {
		t.Fatalf("future floor was reset by read-only state check: %v", err)
	}
}

// macOS exposes its temporary directory through /var -> /private/var.
// Use the real path so protected-path checks still reject actual symlinks.
func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}
