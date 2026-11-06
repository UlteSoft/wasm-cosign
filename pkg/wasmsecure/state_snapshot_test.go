//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHostSnapshotMatchesProtectedNativeState(t *testing.T) {
	f := newFixture(t)
	f.p.StateDir = canonicalTempDir(t)
	if err := os.Chmod(f.p.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	policy, err := f.p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(append(append([]byte{}, policy...), f.root...))
	now := time.Now()
	valid := fmt.Sprintf("UWVM-WSEA-STATE-1\n%d %d %x\n", f.p.Version, now.Unix(), digest)
	for _, test := range []struct {
		name, state             string
		revoked, expired, allow bool
	}{
		{"bootstrap", BootstrapState, false, false, true},
		{"matching policy", valid, false, false, true},
		{"module rollback", valid + fmt.Sprintf("%s|%d|0\n", f.m.ModuleID, f.m.Version+1), false, false, false},
		{"epoch rollback", valid + fmt.Sprintf("%s|%d|%d\n", f.m.ModuleID, f.m.Version, f.m.Epoch+1), false, false, false},
		{"same-version replacement", strings.Replace(valid, fmt.Sprintf("%x", digest), strings.Repeat("0", 64), 1), false, false, false},
		{"future clock", fmt.Sprintf("UWVM-WSEA-STATE-1\n%d %d %x\n", f.p.Version, now.Unix()+3600, digest), false, false, false},
		{"truncated state", strings.TrimSuffix(valid, "\n"), false, false, false},
		{"permanent revocation", valid, true, false, false},
		{"expired evidence", valid, false, true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := f.m
			m.validUntil = uint64(now.Unix() + 3600)
			if test.expired {
				m.validUntil = uint64(now.Unix() - 1)
			}
			path := filepath.Join(f.p.StateDir, "state")
			if err := os.WriteFile(path, []byte(test.state), 0600); err != nil {
				t.Fatal(err)
			}
			pin := f.p.Modules[m.ModuleID].SPKI
			revoked := []string{}
			if test.revoked {
				revoked = append(revoked, pin)
				marker := filepath.Join(f.p.StateDir, "revoked-"+pin)
				if err := os.WriteFile(marker, nil, 0600); err != nil {
					t.Fatal(err)
				}
				defer os.Remove(marker)
			}
			for _, explicit := range []bool{false, true} {
				if explicit {
					m.SignerSPKIs = []string{pin}
				}
				native := CheckCurrentState(policy, f.root, f.p, m, now)
				snapshot := CheckStateSnapshot(policy, f.root, f.p, m, []byte(test.state), revoked, now)
				if (native == nil) != test.allow || (snapshot == nil) != test.allow {
					t.Fatalf("native=%v snapshot=%v expected allow=%t", native, snapshot, test.allow)
				}
			}
		})
	}
	if err := CheckStateSnapshot(policy, f.root, f.p, f.m, []byte(BootstrapState), nil, now); err == nil {
		t.Fatal("missing revocation snapshot accepted")
	}
}
