// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// Algorithm is an exact local-policy name for the authenticated COSE algorithm.
// Its zero value retains the original ES256-only policy and signing behavior.
type Algorithm string

const (
	AlgorithmES256   Algorithm = "ES256"
	AlgorithmESP256  Algorithm = "ESP256"
	AlgorithmES384   Algorithm = "ES384"
	AlgorithmESP384  Algorithm = "ESP384"
	AlgorithmES512   Algorithm = "ES512"
	AlgorithmESP512  Algorithm = "ESP512"
	AlgorithmEd25519 Algorithm = "Ed25519"
	AlgorithmPS256   Algorithm = "PS256"
	AlgorithmPS384   Algorithm = "PS384"
	AlgorithmPS512   Algorithm = "PS512"
	AlgorithmRS256   Algorithm = "RS256"
	AlgorithmRS384   Algorithm = "RS384"
	AlgorithmRS512   Algorithm = "RS512"
)

type algorithmInfo struct {
	name  Algorithm
	id    int64
	hash  crypto.Hash
	curve elliptic.Curve
	width int
	kind  byte // ECDSA, pure Ed25519, RSA-PSS or RSA PKCS1 v1.5.
}

var algorithmProfiles = []algorithmInfo{
	{AlgorithmES256, -7, crypto.SHA256, elliptic.P256(), 32, 'e'},
	{AlgorithmESP256, -9, crypto.SHA256, elliptic.P256(), 32, 'e'},
	{AlgorithmES384, -35, crypto.SHA384, elliptic.P384(), 48, 'e'},
	{AlgorithmESP384, -51, crypto.SHA384, elliptic.P384(), 48, 'e'},
	{AlgorithmES512, -36, crypto.SHA512, elliptic.P521(), 66, 'e'},
	{AlgorithmESP512, -52, crypto.SHA512, elliptic.P521(), 66, 'e'},
	{AlgorithmEd25519, -19, 0, nil, 32, 'd'},
	{AlgorithmPS256, -37, crypto.SHA256, nil, 0, 'p'},
	{AlgorithmPS384, -38, crypto.SHA384, nil, 0, 'p'},
	{AlgorithmPS512, -39, crypto.SHA512, nil, 0, 'p'},
	{AlgorithmRS256, -257, crypto.SHA256, nil, 0, 'r'},
	{AlgorithmRS384, -258, crypto.SHA384, nil, 0, 'r'},
	{AlgorithmRS512, -259, crypto.SHA512, nil, 0, 'r'},
}

func profile(name Algorithm) (algorithmInfo, bool) {
	if name == "" {
		name = AlgorithmES256
	}
	for _, p := range algorithmProfiles {
		if p.name == name {
			return p, true
		}
	}
	return algorithmInfo{}, false
}
func profileID(id int64) (algorithmInfo, bool) {
	for _, p := range algorithmProfiles {
		if p.id == id {
			return p, true
		}
	}
	return algorithmInfo{}, false
}
func (p algorithmInfo) protected() []byte { return appendHead([]byte{0xa1, 0x01}, 1, uint64(-p.id-1)) }
func (p algorithmInfo) signatureLength(n int) bool {
	if p.kind == 'p' || p.kind == 'r' {
		return n >= 384 && n <= 1024
	}
	return n == 2*p.width
}

// ParseAlgorithms rejects aliases, whitespace, empty entries and duplicates,
// then returns a deterministic ordering for the policy's semantic set.
func ParseAlgorithms(value string) ([]Algorithm, error) {
	if value == "" {
		return nil, errors.New("POL_002: algorithm set must not be empty")
	}
	var names []Algorithm
	seen := map[Algorithm]bool{}
	for _, part := range strings.Split(value, ",") {
		name := Algorithm(part)
		p, ok := profile(name)
		if !ok || part == "" || p.name != name || seen[name] {
			return nil, errors.New("POL_002: unknown, empty or duplicate signing algorithm")
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names, nil
}
func canonicalAlgorithms(names []Algorithm) ([]Algorithm, error) {
	if len(names) == 0 {
		return nil, nil
	}
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = string(n)
	}
	return ParseAlgorithms(strings.Join(parts, ","))
}

// AllowsAlgorithm checks the protected module policy; a nil set means ES256 only.
func (r ModuleRule) AllowsAlgorithm(name Algorithm) bool {
	p, ok := profile(name)
	if !ok {
		return false
	}
	if len(r.Algorithms) == 0 {
		return p.name == AlgorithmES256
	}
	normalized, err := canonicalAlgorithms(r.Algorithms)
	if err != nil {
		return false
	}
	for _, n := range normalized {
		if n == p.name {
			return true
		}
	}
	return false
}
func signingBytesFor(payload []byte, p algorithmInfo) []byte {
	b := appendText([]byte{0x84}, "Signature1")
	b = appendBytes(b, p.protected())
	b = appendBytes(b, nil)
	return appendBytes(b, payload)
}
func hashMessage(h crypto.Hash, b []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(b)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(b)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(b)
		return d[:]
	default:
		return nil
	}
}
func strongRSA(key *rsa.PublicKey) bool {
	return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.BitLen() >= 3072 && key.N.BitLen() <= 8192 && key.N.Bit(0) == 1 && key.E == 65537
}
func matchingKey(p algorithmInfo, key any) bool {
	switch p.kind {
	case 'e':
		k, ok := key.(*ecdsa.PublicKey)
		return ok && k != nil && k.Curve == p.curve && k.X != nil && k.Y != nil && p.curve.IsOnCurve(k.X, k.Y)
	case 'd':
		k, ok := key.(ed25519.PublicKey)
		return ok && strongEd25519Encoding(k)
	default:
		k, ok := key.(*rsa.PublicKey)
		return ok && strongRSA(k)
	}
}
func signAlgorithm(p algorithmInfo, payload []byte, key any) ([]byte, error) {
	input := signingBytesFor(payload, p)
	digest := hashMessage(p.hash, input)
	mismatch := errors.New("SIG_005: signing key does not satisfy the exact selected algorithm profile")
	switch p.kind {
	case 'e':
		k, ok := key.(*ecdsa.PrivateKey)
		if !ok || k == nil || !matchingKey(p, &k.PublicKey) {
			return nil, mismatch
		}
		r, s, e := ecdsa.Sign(rand.Reader, k, digest)
		if e != nil {
			return nil, e
		}
		half := new(big.Int).Rsh(new(big.Int).Set(k.Params().N), 1)
		if s.Cmp(half) > 0 {
			s.Sub(k.Params().N, s)
		}
		sig := make([]byte, 2*p.width)
		r.FillBytes(sig[:p.width])
		s.FillBytes(sig[p.width:])
		return sig, nil
	case 'd':
		k, ok := key.(ed25519.PrivateKey)
		if !ok || len(k) != ed25519.PrivateKeySize {
			return nil, mismatch
		}
		if !bytes.Equal(ed25519.NewKeyFromSeed(k[:ed25519.SeedSize]), k) || !matchingKey(p, k.Public()) {
			return nil, mismatch
		}
		sig := ed25519.Sign(k, input)
		if !canonicalEd25519Signature(sig) {
			return nil, errors.New("SIG_003: Ed25519 signature does not satisfy the strict encoding profile")
		}
		return sig, nil
	case 'p', 'r':
		k, ok := key.(*rsa.PrivateKey)
		if !ok || k == nil || !strongRSA(&k.PublicKey) {
			return nil, mismatch
		}
		if e := k.Validate(); e != nil {
			return nil, mismatch
		}
		if p.kind == 'p' {
			return rsa.SignPSS(rand.Reader, k, p.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: p.hash})
		}
		return rsa.SignPKCS1v15(rand.Reader, k, p.hash, digest)
	}
	return nil, mismatch
}
func verifyAlgorithmSignature(name Algorithm, payload, sig []byte, key any) error {
	p, ok := profile(name)
	if !ok || !matchingKey(p, key) {
		return errors.New("SIG_005: signer key does not match the authenticated algorithm profile")
	}
	if !p.signatureLength(len(sig)) {
		return errors.New("SIG_003: invalid signature width")
	}
	input := signingBytesFor(payload, p)
	digest := hashMessage(p.hash, input)
	valid := false
	switch p.kind {
	case 'e':
		k := key.(*ecdsa.PublicKey)
		r, s := new(big.Int).SetBytes(sig[:p.width]), new(big.Int).SetBytes(sig[p.width:])
		half := new(big.Int).Rsh(new(big.Int).Set(k.Params().N), 1)
		if r.Sign() <= 0 || s.Sign() <= 0 || s.Cmp(half) > 0 {
			return errors.New("SIG_003: noncanonical ECDSA signature")
		}
		valid = ecdsa.Verify(k, digest, r, s)
	case 'd':
		if !canonicalEd25519Signature(sig) {
			return errors.New("SIG_003: noncanonical or small-order Ed25519 signature")
		}
		valid = ed25519.Verify(key.(ed25519.PublicKey), input, sig)
	case 'p':
		valid = rsa.VerifyPSS(key.(*rsa.PublicKey), p.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: p.hash}) == nil
	case 'r':
		valid = rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), p.hash, digest, sig) == nil
	}
	if !valid {
		return fmt.Errorf("SIG_003: invalid %s digital signature", p.name)
	}
	return nil
}
