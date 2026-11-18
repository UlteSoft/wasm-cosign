// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// Package wasmsdk is the memory-only WSEA interface. Trust and rollback snapshots
// must be supplied by the trusted host, never taken from downloaded module data.
package wasmsdk

import (
	"bytes"
	"crypto/sha256"
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
	Schema        string               `json:"schema"`
	Status        string               `json:"status"`
	RequestSHA256 []byte               `json:"request_sha256"`
	Operation     string               `json:"operation,omitempty"`
	Error         string               `json:"error,omitempty"`
	Manifest      *wasmsecure.Manifest `json:"manifest,omitempty"`
	Module        []byte               `json:"module,omitempty"`
	CheckedAt     uint64               `json:"checked_at,omitempty"`
	ValidUntil    uint64               `json:"valid_until,omitempty"`
}

// strictJSON rejects duplicate members at every nesting level, unknown fields,
// trailing values and excessively nested objects before binding security input.
func strictJSON(data []byte, target any) error {
	_, err := strictJSONMembers(data, target)
	return err
}

func strictJSONMembers(data []byte, target any) (map[string]bool, error) {
	if !utf8.Valid(data) || len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return nil, errors.New("SDK_001: UTF-8 JSON object required")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	members := make(map[string]bool)
	var value func(int, string) error
	value = func(depth int, path string) error {
		if depth > 16 {
			return errors.New("SDK_001: excessive JSON depth")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if t == nil {
			return errors.New("SDK_001: null is not a contract value")
		}
		if text, ok := t.(string); ok && isBytesMember(path) && !canonicalBase64(text) {
			return errors.New("SDK_001: noncanonical base64")
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
				child := name
				if path != "" {
					child = path + "." + name
				}
				members[child] = true
				if e = value(depth+1, child); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e := value(depth+1, path); e != nil {
					return e
				}
			}
		default:
			return errors.New("SDK_001: invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0, ""); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("SDK_001: trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return nil, err
	}
	return members, nil
}

func Process(data []byte) Response {
	requestDigest := sha256.Sum256(data)
	fail := func(e error) Response {
		message := e.Error()
		if len(message) > MaxErrorBytes {
			message = "SDK_001: request rejected"
		}
		return Response{Schema: ResponseSchema, Status: "REJECTED", RequestSHA256: requestDigest[:], Error: message}
	}
	r, e := decodeRequest(data)
	if e != nil {
		return fail(e)
	}
	defer clear(r.SigningKey())
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
		core, err := wasmsecure.SigningInput(module, s.Append || s.Replace)
		if err != nil {
			return fail(err)
		}
		contributions := make([]wasmsecure.Evidence, 0, 1)
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
	result := Response{Schema: ResponseSchema, RequestSHA256: requestDigest[:], Operation: r.Operation, Status: "VERIFIED_SNAPSHOT", Manifest: &m, CheckedAt: uint64(now.Unix()), ValidUntil: m.ValidUntil()}
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
