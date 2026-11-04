// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package wasmsecure implements the UWVM WSEA v2 embedded WASM profile.
// It never retrieves trust anchors from a module bundle.
package wasmsecure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	Schema                   = "uwvm-wsea-v2"
	EmbeddedSchema           = "uwvm-wsea-v2"
	KnownCapabilities uint64 = 63
	MaxSignatureBytes        = 65536
	MaxEvidenceBytes         = 4 << 20
)

var protected = []byte{0xa1, 0x01, 0x26}

// Manifest is authenticated in its entirety by the detached COSE signature.
// Capabilities: 1 WASI imports, 2 filesystem, 4 sockets, 8 ROS1, 16 ROS2,
// 32 arbitrary host imports. Unknown bits are always rejected.
type Manifest struct {
	Embedded            bool        `json:"embedded"`
	Algorithm           Algorithm   `json:"algorithm"`
	ModuleID            string      `json:"module_id"`
	Version             uint64      `json:"version"`
	Epoch               uint64      `json:"security_epoch"`
	Size                uint64      `json:"size"`
	Digest              []byte      `json:"sha256"`
	NotBefore           uint64      `json:"not_before"`
	NotAfter            uint64      `json:"not_after"`
	ABI                 string      `json:"abi"`
	Capabilities        uint64      `json:"capabilities"`
	SignerSPKIs         []string    `json:"signer_spkis,omitempty"`
	SignatureAlgorithms []Algorithm `json:"signature_algorithms,omitempty"`
	// Authenticated minimum of manifest, certificate and CRL validity bounds.
	// This is verifier output only, never part of the signed wire format.
	validUntil uint64
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 255 {
		return false
	}
	for _, c := range []byte(id) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (m Manifest) validate() error {
	if !m.Embedded || !validID(m.ModuleID) || m.ABI != "uwvm2" || len(m.Digest) != 32 || m.Size < 8 || m.Version == 0 || m.NotAfter <= m.NotBefore || m.NotAfter > 1<<63-1 || m.Capabilities & ^KnownCapabilities != 0 {
		return errors.New("SIG_002: invalid WSEA manifest")
	}
	return nil
}

func appendHead(b []byte, major byte, n uint64) []byte {
	switch {
	case n < 24:
		return append(b, major<<5|byte(n))
	case n <= 255:
		return append(b, major<<5|24, byte(n))
	case n <= 65535:
		return append(b, major<<5|25, byte(n>>8), byte(n))
	case n <= 0xffffffff:
		return append(b, major<<5|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		b = append(b, major<<5|27)
		for i := 7; i >= 0; i-- {
			b = append(b, byte(n>>uint(i*8)))
		}
		return b
	}
}
func appendBytes(b, v []byte) []byte { b = appendHead(b, 2, uint64(len(v))); return append(b, v...) }
func appendText(b []byte, v string) []byte {
	b = appendHead(b, 3, uint64(len(v)))
	return append(b, v...)
}
func (m Manifest) payload() []byte {
	b := []byte{0x8a}
	b = appendText(b, EmbeddedSchema)
	b = appendText(b, m.ModuleID)
	for _, n := range []uint64{m.Version, m.Epoch, m.Size} {
		b = appendHead(b, 0, n)
	}
	b = appendBytes(b, m.Digest)
	b = appendHead(b, 0, m.NotBefore)
	b = appendHead(b, 0, m.NotAfter)
	b = appendText(b, m.ABI)
	return appendHead(b, 0, m.Capabilities)
}
func signingBytes(payload []byte) []byte {
	p, _ := profile(AlgorithmES256)
	return signingBytesFor(payload, p)
}

// Sign authenticates every module byte using the exact algorithm in m.Algorithm.
// Its zero value retains ES256. Supported concrete keys are ECDSA, Ed25519 and RSA.
// Embedded must be true; the retired detached v1 profile is not supported.
// module must be an unsigned WASM prefix; use SigningInput for explicit replacement.
func Sign(module []byte, m Manifest, key any) ([]byte, error) {
	p, ok := profile(m.Algorithm)
	if !ok {
		return nil, errors.New("SIG_005: unsupported signing algorithm")
	}
	if _, err := SigningInput(module, false); err != nil {
		return nil, err
	}
	m.Size = uint64(len(module))
	d := sha256.Sum256(module)
	m.Digest = d[:]
	if err := m.validate(); err != nil {
		return nil, err
	}
	if !bytes.Equal(module[:8], []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
		return nil, errors.New("VM_001: expected a WebAssembly v1 module")
	}
	payload := m.payload()
	signature, err := signAlgorithm(p, payload, key)
	if err != nil {
		return nil, err
	}
	out := appendBytes([]byte{0xd2, 0x84}, p.protected())
	out = append(out, 0xa0)
	out = appendBytes(out, payload)
	return appendBytes(out, signature), nil
}

type cborReader struct {
	b []byte
	p int
}

func (r *cborReader) head(major byte) (uint64, error) {
	if r.p >= len(r.b) {
		return 0, errors.New("truncated CBOR")
	}
	c := r.b[r.p]
	r.p++
	if c>>5 != major {
		return 0, errors.New("unexpected CBOR type")
	}
	a := c & 31
	if a < 24 {
		return uint64(a), nil
	}
	var nbytes int
	switch a {
	case 24:
		nbytes = 1
	case 25:
		nbytes = 2
	case 26:
		nbytes = 4
	case 27:
		nbytes = 8
	default:
		return 0, errors.New("indefinite CBOR is prohibited")
	}
	if nbytes > len(r.b)-r.p {
		return 0, errors.New("truncated CBOR integer")
	}
	var n uint64
	for range nbytes {
		n = n<<8 | uint64(r.b[r.p])
		r.p++
	}
	if n < 24 || nbytes > 1 && n <= 255 || nbytes > 2 && n <= 65535 || nbytes > 4 && n <= 0xffffffff {
		return 0, errors.New("noncanonical CBOR integer")
	}
	return n, nil
}
func (r *cborReader) blob(major byte) ([]byte, error) {
	n, err := r.head(major)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.b)-r.p) {
		return nil, errors.New("truncated CBOR string")
	}
	b := r.b[r.p : r.p+int(n)]
	r.p += int(n)
	return b, nil
}
func (r *cborReader) text() (string, error) { b, e := r.blob(3); return string(b), e }

// Parse rejects alternate encodings, unknown headers, trailing bytes, algorithm
// changes, indefinite strings, detached payloads and non-profile manifests.
func Parse(bundle []byte) (Manifest, []byte, []byte, error) {
	var m Manifest
	bad := func(e error) (Manifest, []byte, []byte, error) { return m, nil, nil, fmt.Errorf("SIG_002: %w", e) }
	if len(bundle) > MaxSignatureBytes {
		return bad(errors.New("COSE exceeds size limit"))
	}
	r := cborReader{b: bundle}
	n, e := r.head(6)
	if e != nil || n != 18 {
		return bad(errors.New("expected COSE_Sign1 tag 18"))
	}
	n, e = r.head(4)
	if e != nil || n != 4 {
		return bad(errors.New("expected COSE array(4)"))
	}
	ph, e := r.blob(2)
	if e != nil {
		return bad(e)
	}
	header := cborReader{b: ph}
	count, e := header.head(5)
	if e != nil || count != 1 {
		return bad(errors.New("protected header must contain exactly one algorithm"))
	}
	label, e := header.head(0)
	if e != nil || label != 1 {
		return bad(errors.New("only protected algorithm label is permitted"))
	}
	negative, e := header.head(1)
	if e != nil || negative > 1<<63-1 || header.p != len(ph) {
		return bad(errors.New("algorithm must be a canonical negative COSE identifier"))
	}
	algorithm, known := profileID(-1 - int64(negative))
	if !known {
		return m, nil, nil, errors.New("SIG_005: unknown or disallowed COSE algorithm")
	}
	m.Algorithm = algorithm.name
	n, e = r.head(5)
	if e != nil || n != 0 {
		return bad(errors.New("unprotected headers are prohibited"))
	}
	p, e := r.blob(2)
	if e != nil {
		return bad(e)
	}
	sig, e := r.blob(2)
	if e != nil || !algorithm.signatureLength(len(sig)) || r.p != len(r.b) {
		return bad(errors.New("invalid signature length or trailing bytes"))
	}
	q := cborReader{b: p}
	n, e = q.head(4)
	if e != nil || n != 10 {
		return bad(errors.New("expected manifest array(10)"))
	}
	schema, e := q.text()
	if e != nil || schema != EmbeddedSchema {
		return bad(errors.New("unsupported schema"))
	}
	m.Embedded = schema == EmbeddedSchema
	if m.ModuleID, e = q.text(); e != nil {
		return bad(e)
	}
	for _, v := range []*uint64{&m.Version, &m.Epoch, &m.Size} {
		*v, e = q.head(0)
		if e != nil {
			return bad(e)
		}
	}
	if m.Digest, e = q.blob(2); e != nil {
		return bad(e)
	}
	for _, v := range []*uint64{&m.NotBefore, &m.NotAfter} {
		*v, e = q.head(0)
		if e != nil {
			return bad(e)
		}
	}
	if m.ABI, e = q.text(); e != nil {
		return bad(e)
	}
	if m.Capabilities, e = q.head(0); e != nil {
		return bad(e)
	}
	if q.p != len(q.b) {
		return bad(errors.New("trailing manifest data"))
	}
	if e = m.validate(); e != nil {
		return bad(e)
	}
	return m, p, sig, nil
}

// Legacy internal helper retains its ES256 meaning for existing callers.
func verifySignature(p, sig []byte, key *ecdsa.PublicKey) error {
	return verifyAlgorithmSignature(AlgorithmES256, p, sig, key)
}
