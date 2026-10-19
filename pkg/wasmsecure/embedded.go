// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"time"
)

const SectionName = "uwvm.wsea.v2"
const MaxSignatures = 8
const MaxEmbeddedEvidenceBytes = 16 * 1024 * 1024

func appendULEB(b []byte, n uint32) []byte {
	for n >= 128 {
		b = append(b, byte(n)|128)
		n >>= 7
	}
	return append(b, byte(n))
}
func readULEB(b []byte, p *int, canonical bool) (uint32, error) {
	start := *p
	var n uint32
	for i := 0; i < 5; i++ {
		if *p >= len(b) {
			return 0, errors.New("SIG_002: truncated WASM section length")
		}
		c := b[*p]
		*p++
		if i == 4 && c > 15 {
			return 0, errors.New("SIG_002: overflowing WASM section length")
		}
		n |= uint32(c&127) << uint(7*i)
		if c&128 == 0 {
			if canonical && len(appendULEB(nil, n)) != *p-start {
				return 0, errors.New("SIG_002: noncanonical WSEA section length")
			}
			return n, nil
		}
	}
	return 0, errors.New("SIG_002: overflowing WASM section length")
}

// splitSection retains every original byte of every other WASM section. Only
// one canonical, final WSEA section may be excluded from the signed prefix.
func splitSection(module []byte) ([]byte, []byte, error) {
	if len(module) < 8 || !bytes.Equal(module[:8], []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
		return nil, nil, errors.New("VM_001: expected a WebAssembly v1 module")
	}
	for p := 8; p < len(module); {
		start := p
		id := module[p]
		p++
		lengthStart := p
		n, e := readULEB(module, &p, false)
		if e != nil {
			return nil, nil, e
		}
		if uint64(n) > uint64(len(module)-p) {
			return nil, nil, errors.New("SIG_002: truncated WASM section")
		}
		end := p + int(n)
		if id == 0 {
			q := p
			nameStart := q
			nameSize, e := readULEB(module[:end], &q, false)
			if e != nil || uint64(nameSize) > uint64(end-q) {
				return nil, nil, errors.New("SIG_002: invalid custom-section name")
			}
			if string(module[q:q+int(nameSize)]) == SectionName {
				if end != len(module) || p-lengthStart != len(appendULEB(nil, n)) || q-nameStart != len(appendULEB(nil, nameSize)) {
					return nil, nil, errors.New("SIG_002: WSEA must be one canonical final custom section")
				}
				payload := module[q+int(nameSize) : end]
				if len(payload) > MaxEmbeddedEvidenceBytes {
					return nil, nil, errors.New("SIG_002: embedded evidence exceeds limit")
				}
				return module[:start], payload, nil
			}
		}
		p = end
	}
	return module, nil, nil
}

// SigningInput rejects accidental re-signing unless explicitly requested.
func SigningInput(module []byte, replace bool) ([]byte, error) {
	core, payload, e := splitSection(module)
	if e != nil {
		return nil, e
	}
	if payload != nil && !replace {
		return nil, errors.New("SIG_002: module already contains WSEA; use --replace-signature")
	}
	return core, nil
}

func Embed(module []byte, evidence Evidence) ([]byte, error) {
	return EmbedAll(module, []Evidence{evidence})
}

// EmbedAll preserves the legacy single-signature encoding. Multiple signatures
// occupy one final section: [2, [[COSE, certificates, CRLs], ...]].
// Every contribution signs exactly the same module prefix and manifest.
func EmbedAll(module []byte, evidence []Evidence) ([]byte, error) {
	core, existing, e := splitSection(module)
	if e != nil {
		return nil, e
	}
	if existing != nil {
		return nil, errors.New("SIG_002: duplicate WSEA custom section")
	}
	if len(evidence) == 0 || len(evidence) > MaxSignatures {
		return nil, errors.New("SIG_002: invalid signature count")
	}
	payload := []byte{0x84, 0x01}
	if len(evidence) > 1 {
		payload = appendHead([]byte{0x82, 0x02}, 4, uint64(len(evidence)))
	}
	seen := make(map[string]bool)
	for _, ev := range evidence {
		if len(ev.Signature) == 0 || len(ev.Signature) > MaxSignatureBytes || len(ev.Certificates) == 0 || len(ev.Certificates) > MaxEvidenceBytes || len(ev.CRLs) == 0 || len(ev.CRLs) > MaxEvidenceBytes || seen[string(ev.Signature)] {
			return nil, errors.New("SIG_002: invalid or duplicate embedded contribution")
		}
		seen[string(ev.Signature)] = true
		if len(evidence) > 1 {
			payload = append(payload, 0x83)
		}
		payload = appendBytes(payload, ev.Signature)
		payload = appendBytes(payload, ev.Certificates)
		payload = appendBytes(payload, ev.CRLs)
		if len(payload) > MaxEmbeddedEvidenceBytes {
			return nil, errors.New("SIG_002: embedded evidence exceeds limit")
		}
	}
	section := appendULEB(nil, uint32(len(SectionName)))
	section = append(section, SectionName...)
	section = append(section, payload...)
	out := make([]byte, 0, len(core)+len(section)+6)
	out = append(out, core...)
	out = append(out, 0)
	out = appendULEB(out, uint32(len(section)))
	out = append(out, section...)
	return out, nil
}

// Extract refuses a multi-signature bundle instead of silently returning its
// first signature. Use ExtractAll and VerifyEmbedded for bundle processing.
func Extract(module []byte) ([]byte, Evidence, error) {
	core, list, err := ExtractAll(module)
	if err != nil {
		return nil, Evidence{}, err
	}
	if len(list) != 1 {
		return nil, Evidence{}, errors.New("SIG_002: multiple signatures require ExtractAll")
	}
	return core, list[0], nil
}

func ExtractAll(module []byte) ([]byte, []Evidence, error) {
	core, payload, e := splitSection(module)
	if e != nil {
		return nil, nil, e
	}
	if payload == nil {
		return nil, nil, errors.New("SIG_001: missing embedded WSEA custom section")
	}
	r := cborReader{b: payload}
	count, e := r.head(4)
	if e != nil {
		return nil, nil, errors.New("SIG_002: malformed embedded evidence array")
	}
	version, e := r.head(0)
	if e != nil || !(version == 1 && count == 4 || version == 2 && count == 2) {
		return nil, nil, errors.New("SIG_002: unsupported embedded evidence version")
	}
	n := uint64(1)
	if version == 2 {
		n, e = r.head(4)
		if e != nil || n < 2 || n > MaxSignatures {
			return nil, nil, errors.New("SIG_002: invalid multi-signature count")
		}
	}
	evidence := make([]Evidence, 0, n)
	seen := make(map[string]bool)
	for i := uint64(0); i < n; i++ {
		if version == 2 {
			size, e := r.head(4)
			if e != nil || size != 3 {
				return nil, nil, errors.New("SIG_002: invalid signature contribution")
			}
		}
		var ev Evidence
		fields := []struct {
			value *[]byte
			limit int
		}{{&ev.Signature, MaxSignatureBytes}, {&ev.Certificates, MaxEvidenceBytes}, {&ev.CRLs, MaxEvidenceBytes}}
		for _, field := range fields {
			*field.value, e = r.blob(2)
			if e != nil || len(*field.value) == 0 || len(*field.value) > field.limit {
				return nil, nil, errors.New("SIG_002: malformed embedded contribution")
			}
		}
		if seen[string(ev.Signature)] {
			return nil, nil, errors.New("SIG_002: duplicate signature contribution")
		}
		seen[string(ev.Signature)] = true
		evidence = append(evidence, ev)
	}
	if r.p != len(payload) {
		return nil, nil, errors.New("SIG_002: trailing embedded evidence")
	}
	return core, evidence, nil
}

func VerifyEmbedded(module []byte, p Policy, roots []byte, now time.Time) (Manifest, error) {
	return verifyEmbedded(module, p, roots, now, true)
}

// VerifyEmbeddedPartial authenticates every present contribution for the signing
// workflow only. It does NOT establish the protected quorum and MUST NOT be
// used to authorize execution or publication by a download/verification agent.
func VerifyEmbeddedPartial(module []byte, p Policy, roots []byte, now time.Time) (Manifest, error) {
	return verifyEmbedded(module, p, roots, now, false)
}

func verifyEmbedded(module []byte, p Policy, roots []byte, now time.Time, quorum bool) (Manifest, error) {
	var zero Manifest
	if uint64(len(module)) > p.MaxModuleBytes {
		return zero, errors.New("SIG_004: complete signed module exceeds local size limit")
	}
	core, evidence, e := ExtractAll(module)
	if e != nil {
		return zero, e
	}
	digest := sha256.Sum256(core)
	var first Manifest
	var firstPayload []byte
	seen := make(map[string]bool)
	for i, ev := range evidence {
		m, e := verifyOne(core, ev, p, roots, now, digest[:])
		if e != nil {
			return zero, e
		}
		if !m.Embedded {
			return zero, errors.New("SIG_002: detached v1 signatures cannot authorize embedded v2 modules")
		}
		_, payload, _, e := Parse(ev.Signature)
		if e != nil {
			return zero, e
		}
		if i == 0 {
			first = m
			first.SignerSPKIs = nil
			first.SignatureAlgorithms = nil
			firstPayload = payload
		} else if !bytes.Equal(firstPayload, payload) {
			return zero, errors.New("SIG_002: signatures authenticate different manifests")
		}
		pin := m.SignerSPKIs[0]
		if !seen[pin] {
			first.SignerSPKIs = append(first.SignerSPKIs, pin)
			seen[pin] = true
		}
		first.SignatureAlgorithms = append(first.SignatureAlgorithms, m.Algorithm)
	}
	if quorum && uint64(len(seen)) < p.Modules[first.ModuleID].RequiredSignatures() {
		return zero, errors.New("POL_002: distinct valid signatures do not satisfy the protected threshold")
	}
	return first, nil
}
