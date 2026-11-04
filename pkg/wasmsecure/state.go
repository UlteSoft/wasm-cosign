// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const BootstrapState = "UWVM-WSEA-STATE-1\n0 0 -\n"

// CheckState consults the VM's protected monotonic state without changing it.
// The VM rechecks and atomically advances this state when authorizing execution.
func CheckState(policyBytes, rootBytes []byte, p Policy, m Manifest, now time.Time) error {
	return checkState(policyBytes, rootBytes, p, m, now, false)
}

// CheckCurrentState reads protected state before observing the actual wall
// clock. checkedAt is the request's earlier trusted observation, so a slow
// verification may follow a later VM commit without reporting a false rollback.
// This only checks monotonic state; callers still authenticate evidence with Verify.
func CheckCurrentState(policyBytes, rootBytes []byte, p Policy, m Manifest, checkedAt time.Time) error {
	return checkState(policyBytes, rootBytes, p, m, checkedAt, true)
}

func checkState(policyBytes, rootBytes []byte, p Policy, m Manifest, now time.Time, observeCurrent bool) error {
	path := filepath.Join(p.StateDir, "state")
	if e := ProtectedPath(p.StateDir, true); e != nil {
		return e
	}
	if e := ProtectedPath(path, false); e != nil {
		return e
	}
	st, e := os.Stat(path)
	if e != nil {
		return e
	}
	if st.Mode().Perm() != 0600 {
		return errors.New("POL_002: security state requires mode 0600")
	}
	b, e := ReadBounded(path, 1<<20)
	if e != nil {
		return e
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return errors.New("POL_002: invalid security state encoding")
	}
	// A revocation learned and authenticated by the VM is permanent for the
	// publisher SPKI. Neither an older still-fresh CRL nor a policy version bump
	// may make this key trusted again. Lstat also rejects symlink markers.
	if rule, ok := p.Modules[m.ModuleID]; ok {
		pins := m.SignerSPKIs
		if len(pins) == 0 {
			pins = []string{rule.SPKI}
		}
		for _, pin := range pins {
			if !rule.AllowsSigner(pin) {
				return errors.New("CERT_006: state check signer is not authorized")
			}
			marker := filepath.Join(p.StateDir, "revoked-"+pin)
			if _, err := os.Lstat(marker); err == nil {
				return errors.New("CERT_004: publisher key has a protected permanent revocation marker")
			} else if !os.IsNotExist(err) {
				return errors.New("CERT_004: cannot establish absence of protected publisher revocation")
			}
		}
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) < 2 || lines[0] != "UWVM-WSEA-STATE-1" {
		return errors.New("POL_002: invalid security state")
	}
	f := strings.Split(lines[1], " ")
	if len(f) != 3 {
		return errors.New("POL_002: invalid security state header")
	}
	v, e := strictUint(f[0])
	if e != nil {
		return e
	}
	t, e := strictUint(f[1])
	if e != nil {
		return e
	}
	hash := sha256.New()
	hash.Write(policyBytes)
	hash.Write(rootBytes)
	digest := hex.EncodeToString(hash.Sum(nil))
	if v > p.Version || v == p.Version && f[2] != digest {
		return errors.New("POL_002: policy rollback or same-version policy replacement")
	}
	if v == 0 && string(b) != BootstrapState {
		return errors.New("POL_002: invalid bootstrap state")
	}
	if v != 0 && (len(f[2]) != 64 || strings.ToLower(f[2]) != f[2]) {
		return errors.New("POL_002: invalid state policy digest")
	}
	if v != 0 {
		if _, e = hex.DecodeString(f[2]); e != nil {
			return e
		}
	}
	if observeCurrent {
		observed := time.Now()
		// Compare wall-clock seconds rather than time.Time's monotonic component.
		if observed.Unix() < now.Unix() {
			return errors.New("POL_004: trusted wall clock moved backwards during verification")
		}
		now = observed
	}
	if now.Unix() < 1577836800 || uint64(now.Unix()) < t {
		return errors.New("POL_004: trusted wall clock moved backwards")
	}
	if m.validUntil != 0 && uint64(now.Unix()) >= m.validUntil {
		return errors.New("POL_004: authenticated evidence expired during verification")
	}
	seen := map[string]bool{}
	for _, line := range lines[2:] {
		f = strings.Split(line, "|")
		if len(f) != 3 || !validID(f[0]) || seen[f[0]] || len(seen) >= 1024 {
			return errors.New("POL_002: invalid state module entry")
		}
		seen[f[0]] = true
		version, e := strictUint(f[1])
		if e != nil || version == 0 {
			return errors.New("POL_002: invalid state module version")
		}
		epoch, e := strictUint(f[2])
		if e != nil {
			return e
		}
		if f[0] == m.ModuleID && (m.Version < version || m.Epoch < epoch) {
			return fmt.Errorf("POL_001: module rollback below protected state %d/%d", version, epoch)
		}
	}
	return nil
}
