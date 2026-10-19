// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const PolicyHeader = "UWVM-WSEA-POLICY-1"

type ModuleRule struct {
	ID                  string
	ABI                 string
	SPKI                string
	AdditionalSPKIs     []string
	SignatureThreshold  uint64
	MinVersion          uint64
	MinEpoch            uint64
	AllowedCapabilities uint64
	Algorithms          []Algorithm
}

func (r ModuleRule) RequiredSignatures() uint64 {
	if r.SignatureThreshold == 0 {
		return 1
	}
	return r.SignatureThreshold
}

func (r ModuleRule) AllowsSigner(pin string) bool {
	if pin == r.SPKI {
		return true
	}
	for _, additional := range r.AdditionalSPKIs {
		if pin == additional {
			return true
		}
	}
	return false
}

type Policy struct {
	Version          uint64
	TrustRoot        string
	StateDir         string
	MaxCRLAgeSeconds uint64
	MaxModuleBytes   uint64
	Modules          map[string]ModuleRule
}

// ParsePolicy accepts the exact versioned, line oriented local policy profile.
// No downloaded material is permitted to extend its trust roots or signer pins.
func ParsePolicy(data []byte) (Policy, error) {
	var p Policy
	p.Modules = make(map[string]ModuleRule)
	bad := func(s string) (Policy, error) { return p, fmt.Errorf("POL_002: %s", s) }
	if len(data) > MaxSignatureBytes || len(data) == 0 || data[len(data)-1] != '\n' || strings.ContainsAny(string(data), "\r\x00") {
		return bad("invalid policy encoding")
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) < 2 || lines[0] != PolicyHeader {
		return bad("invalid policy header")
	}
	seen := make(map[string]bool)
	thresholds := make(map[string]bool)
	for _, line := range lines[1:] {
		k, v, ok := strings.Cut(line, "=")
		if !ok || v == "" {
			return bad("invalid policy field")
		}
		if k != "module" && k != "module_signer" && k != "module_threshold" {
			if seen[k] {
				return bad("duplicate policy field")
			}
			seen[k] = true
		}
		var err error
		switch k {
		case "policy_version":
			p.Version, err = strictUint(v)
		case "trust_root":
			p.TrustRoot = v
			if !cleanSecurityPath(v) {
				err = errors.New("trust_root must be absolute")
			}
		case "state_dir":
			p.StateDir = v
			if !cleanSecurityPath(v) {
				err = errors.New("state_dir must be absolute")
			}
		case "max_crl_age_seconds":
			p.MaxCRLAgeSeconds, err = strictUint(v)
		case "max_module_bytes":
			p.MaxModuleBytes, err = strictUint(v)
		case "module":
			f := strings.Split(v, "|")
			if len(f) != 6 && len(f) != 7 {
				return bad("module requires six or seven fields")
			}
			var rule ModuleRule
			rule.ID = f[0]
			rule.ABI = f[1]
			rule.SPKI = f[2]
			if !validID(rule.ID) || rule.ABI != "uwvm2" || len(rule.SPKI) != 64 || strings.ToLower(rule.SPKI) != rule.SPKI {
				return bad("invalid module identity, ABI or SPKI")
			}
			if _, e := hex.DecodeString(rule.SPKI); e != nil {
				return bad("invalid SPKI digest")
			}
			if _, ok := p.Modules[rule.ID]; ok {
				return bad("duplicate module rule")
			}
			if rule.MinVersion, err = strictUint(f[3]); err != nil {
				return bad("invalid minimum version")
			}
			if rule.MinEpoch, err = strictUint(f[4]); err != nil {
				return bad("invalid minimum epoch")
			}
			if rule.AllowedCapabilities, err = strictUint(f[5]); err != nil {
				return bad("invalid capabilities")
			}
			if rule.MinVersion == 0 || rule.AllowedCapabilities & ^KnownCapabilities != 0 {
				return bad("invalid module security limits")
			}
			if len(f) == 7 {
				if rule.Algorithms, err = ParseAlgorithms(f[6]); err != nil {
					return bad(err.Error())
				}
			}
			p.Modules[rule.ID] = rule
		case "module_signer":
			f := strings.Split(v, "|")
			if len(f) != 2 {
				return bad("module_signer requires identity and SPKI")
			}
			rule, ok := p.Modules[f[0]]
			if !ok || len(f[1]) != 64 || strings.ToLower(f[1]) != f[1] || rule.AllowsSigner(f[1]) || len(rule.AdditionalSPKIs) >= MaxSignatures-1 {
				return bad("invalid, duplicate or excessive module signer")
			}
			if _, e := hex.DecodeString(f[1]); e != nil {
				return bad("invalid additional SPKI digest")
			}
			rule.AdditionalSPKIs = append(rule.AdditionalSPKIs, f[1])
			p.Modules[f[0]] = rule
		case "module_threshold":
			f := strings.Split(v, "|")
			if len(f) != 2 {
				return bad("module_threshold requires identity and count")
			}
			rule, ok := p.Modules[f[0]]
			if !ok || thresholds[f[0]] {
				return bad("unknown or duplicate module threshold")
			}
			n, e := strictUint(f[1])
			if e != nil || n == 0 || n > MaxSignatures {
				return bad("invalid signature threshold")
			}
			rule.SignatureThreshold = n
			thresholds[f[0]] = true
			p.Modules[f[0]] = rule
		default:
			return bad("unknown policy field")
		}
		if err != nil {
			return bad(err.Error())
		}
	}
	for _, k := range []string{"policy_version", "trust_root", "state_dir", "max_crl_age_seconds", "max_module_bytes"} {
		if !seen[k] {
			return bad("missing policy field " + k)
		}
	}
	if p.Version == 0 || p.MaxCRLAgeSeconds == 0 || p.MaxCRLAgeSeconds > 31536000 || p.MaxModuleBytes < 8 || p.MaxModuleBytes > 1<<30 || len(p.Modules) == 0 || len(p.Modules) > 1024 {
		return bad("invalid policy bounds")
	}
	for _, rule := range p.Modules {
		if rule.RequiredSignatures() > uint64(1+len(rule.AdditionalSPKIs)) {
			return bad("signature threshold exceeds distinct authorized keys")
		}
	}
	return p, nil
}
func cleanSecurityPath(v string) bool {
	if !filepath.IsAbs(v) || filepath.Clean(v) != v {
		return false
	}
	for _, c := range []byte(v) {
		if c < 32 || c == 127 {
			return false
		}
	}
	return true
}

func strictUint(v string) (uint64, error) {
	if v == "" || len(v) > 1 && v[0] == '0' {
		return 0, errors.New("noncanonical unsigned integer")
	}
	for _, c := range []byte(v) {
		if c < '0' || c > '9' {
			return 0, errors.New("invalid unsigned integer")
		}
	}
	return strconv.ParseUint(v, 10, 64)
}

// Marshal emits a single module bootstrap policy. Policy and trust root files
// must be installed by an administrator into OS protected locations.
func (p Policy) Marshal() ([]byte, error) {
	b := fmt.Sprintf("%s\npolicy_version=%d\ntrust_root=%s\nstate_dir=%s\nmax_crl_age_seconds=%d\nmax_module_bytes=%d\n", PolicyHeader, p.Version, p.TrustRoot, p.StateDir, p.MaxCRLAgeSeconds, p.MaxModuleBytes)
	// Stable output, independent of map iteration order.
	ids := make([]string, 0, len(p.Modules))
	for id := range p.Modules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := p.Modules[id]
		line := fmt.Sprintf("module=%s|%s|%s|%d|%d|%d", r.ID, r.ABI, r.SPKI, r.MinVersion, r.MinEpoch, r.AllowedCapabilities)
		algorithms, err := canonicalAlgorithms(r.Algorithms)
		if err != nil {
			return nil, err
		}
		if len(algorithms) > 0 {
			parts := make([]string, len(algorithms))
			for i, n := range algorithms {
				parts[i] = string(n)
			}
			line += "|" + strings.Join(parts, ",")
		}
		b += line + "\n"
		pins := append([]string(nil), r.AdditionalSPKIs...)
		sort.Strings(pins)
		for _, pin := range pins {
			b += "module_signer=" + r.ID + "|" + pin + "\n"
		}
		if r.RequiredSignatures() != 1 {
			b += fmt.Sprintf("module_threshold=%s|%d\n", r.ID, r.RequiredSignatures())
		}
	}
	_, err := ParsePolicy([]byte(b))
	return []byte(b), err
}

func SPKIDigest(spki []byte) string { d := sha256.Sum256(spki); return hex.EncodeToString(d[:]) }

// ReadBounded snapshots a regular file once and limits its memory cost.
func ReadBounded(path string, limit int64) ([]byte, error) {
	f, e := openSnapshot(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Size() < 0 || st.Size() > limit {
		return nil, errors.New("file is not regular or exceeds size limit")
	}
	return readBounded(f, limit)
}
