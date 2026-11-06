// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// Package wasmsdk is the memory-only WSEA interface. Trust and rollback snapshots
// must be supplied by the trusted host, never taken from downloaded module data.
package wasmsdk

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/sigstore/cosign/v3/pkg/wasmsecure"
)

const MaxRequestBytes = 96 << 20
const MaxModuleBytes = 32 << 20

type Trust struct {
	Policy       []byte   `json:"policy"`
	Roots        []byte   `json:"roots"`
	State        []byte   `json:"state"`
	RevokedSPKIs []string `json:"revoked_spkis"`
}

type Signing struct {
	Key          []byte              `json:"key"`
	Certificates []byte              `json:"certificates"`
	CRLs         []byte              `json:"crls"`
	Manifest     wasmsecure.Manifest `json:"manifest"`
	Append       bool                `json:"append"`
	Replace      bool                `json:"replace"`
	AllowPartial bool                `json:"allow_partial"`
}

type Request struct {
	Schema    string   `json:"schema"`
	Operation string   `json:"operation"`
	Module    []byte   `json:"module"`
	Trust     Trust    `json:"trust"`
	Signing   *Signing `json:"signing,omitempty"`
}

type Response struct {
	Status     string               `json:"status"`
	Error      string               `json:"error,omitempty"`
	Manifest   *wasmsecure.Manifest `json:"manifest,omitempty"`
	Module     []byte               `json:"module,omitempty"`
	CheckedAt  uint64               `json:"checked_at,omitempty"`
	ValidUntil uint64               `json:"valid_until,omitempty"`
}

// strictJSON rejects duplicate members at every nesting level, unknown fields,
// trailing values and excessively nested objects before binding security input.
func strictJSON(data []byte, request *Request) error {
	if !utf8.Valid(data) || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("SDK_001: UTF-8 request object required")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("SDK_001: excessive JSON depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				name, valid := key.(string)
				// encoding/json otherwise accepts case-insensitive aliases, which
				// could overwrite an earlier security field with a different spelling.
				if !valid || seen[name] || name != strings.ToLower(name) {
					return errors.New("SDK_001: duplicate JSON member")
				}
				for _, c := range name {
					if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
						return errors.New("SDK_001: noncanonical JSON member")
					}
				}
				seen[name] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("SDK_001: invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("SDK_001: trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(request)
}

func Process(data []byte) Response {
	fail := func(e error) Response { return Response{Status: "REJECTED", Error: e.Error()} }
	if len(data) > MaxRequestBytes {
		return fail(errors.New("SDK_001: request too large"))
	}
	var r Request
	if e := strictJSON(data, &r); e != nil {
		return fail(e)
	}
	defer clear(r.SigningKey())
	if r.Schema != "wsea-sdk-1" || (r.Operation != "sign" && r.Operation != "verify") || len(r.Module) > MaxModuleBytes {
		return fail(errors.New("SDK_001: unsupported request or module size"))
	}
	if len(r.Trust.Roots) == 0 || len(r.Trust.Roots) > wasmsecure.MaxEvidenceBytes || len(r.Trust.State) > 1<<20 || r.Trust.RevokedSPKIs == nil || len(r.Trust.RevokedSPKIs) > 8192 {
		return fail(errors.New("POL_002: incomplete protected host trust snapshot"))
	}
	seenPins := make(map[string]bool, len(r.Trust.RevokedSPKIs))
	for _, pin := range r.Trust.RevokedSPKIs {
		if len(pin) != 64 || strings.Trim(pin, "0123456789abcdef") != "" || seenPins[pin] {
			return fail(errors.New("POL_002: invalid protected revocation snapshot"))
		}
		seenPins[pin] = true
	}
	p, e := wasmsecure.ParsePolicy(r.Trust.Policy)
	if e != nil {
		return fail(e)
	}
	if uint64(len(r.Module)) > p.MaxModuleBytes {
		return fail(errors.New("SIG_004: module exceeds policy limit"))
	}
	check := func(m wasmsecure.Manifest, at time.Time) error {
		return wasmsecure.CheckStateSnapshot(r.Trust.Policy, r.Trust.Roots, p, m, r.Trust.State, r.Trust.RevokedSPKIs, at)
	}
	module := r.Module
	partial := false
	if r.Operation == "sign" {
		s := r.Signing
		if s == nil || s.Append && s.Replace || len(s.Key) == 0 || len(s.Key) > wasmsecure.MaxEvidenceBytes || len(s.Certificates) > wasmsecure.MaxEvidenceBytes || len(s.CRLs) > wasmsecure.MaxEvidenceBytes {
			return fail(errors.New("SDK_001: invalid signing inputs"))
		}
		profiles, err := wasmsecure.ParseAlgorithms(string(s.Manifest.Algorithm))
		if err != nil || len(profiles) != 1 || profiles[0] != s.Manifest.Algorithm {
			return fail(errors.New("SIG_005: exact algorithm required"))
		}
		core, err := wasmsecure.SigningInput(module, s.Append || s.Replace)
		if err != nil {
			return fail(err)
		}
		var contributions []wasmsecure.Evidence
		if s.Append {
			now := time.Now()
			old, err := wasmsecure.VerifyEmbeddedPartial(module, p, r.Trust.Roots, now)
			if err != nil {
				return fail(err)
			}
			if err = check(old, now); err != nil {
				return fail(err)
			}
			_, contributions, err = wasmsecure.ExtractAll(module)
			if err != nil {
				return fail(err)
			}
		}
		key, err := wasmsecure.ParsePrivateKey(s.Key)
		if err != nil {
			return fail(err)
		}
		sig, err := wasmsecure.Sign(core, s.Manifest, key)
		if err != nil {
			return fail(err)
		}
		contributions = append(contributions, wasmsecure.Evidence{Signature: sig, Certificates: s.Certificates, CRLs: s.CRLs})
		module, err = wasmsecure.EmbedAll(core, contributions)
		if err != nil {
			return fail(err)
		}
		if len(module) > MaxModuleBytes || uint64(len(module)) > p.MaxModuleBytes {
			return fail(errors.New("SIG_004: signed module exceeds size limit"))
		}
		partial = s.AllowPartial
	} else if r.Signing != nil {
		return fail(errors.New("SDK_001: signing options on verification request"))
	}
	now := time.Now()
	var m wasmsecure.Manifest
	if partial {
		m, e = wasmsecure.VerifyEmbeddedPartial(module, p, r.Trust.Roots, now)
	} else {
		m, e = wasmsecure.VerifyEmbedded(module, p, r.Trust.Roots, now)
	}
	if e != nil {
		return fail(e)
	}
	if e = check(m, now); e != nil {
		return fail(e)
	}
	result := Response{Status: "VERIFIED_SNAPSHOT", Manifest: &m, CheckedAt: uint64(now.Unix()), ValidUntil: m.ValidUntil()}
	if r.Operation == "sign" {
		result.Module = module
		if uint64(len(m.SignerSPKIs)) < p.Modules[m.ModuleID].RequiredSignatures() {
			result.Status = "SIGNED_PARTIAL"
		}
	}
	return result
}

func (r *Request) SigningKey() []byte {
	if r.Signing == nil {
		return nil
	}
	return r.Signing.Key
}
