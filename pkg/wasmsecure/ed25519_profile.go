// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import "bytes"

// strongEd25519Encoding adds a finite encoding policy to the standard library's
// on-curve/signature checks. It does no curve arithmetic. Require canonical
// y<p and reject every torsion-only point, with either sign bit. Nontrivial
// order-8 encodings are from libsodium 1.0.18 ge25519_has_small_order:
// https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c#L965
func strongEd25519Encoding(encoded []byte) bool {
	if len(encoded) != 32 {
		return false
	}
	var y, prime, minusOne [32]byte
	copy(y[:], encoded)
	y[31] &= 0x7f
	for i := range prime {
		prime[i] = 0xff
	}
	prime[0] = 0xed
	prime[31] = 0x7f
	minusOne = prime
	minusOne[0] = 0xec
	less := false
	for i := 31; i >= 0; i-- {
		if y[i] < prime[i] {
			less = true
			break
		}
		if y[i] > prime[i] {
			return false
		}
	}
	if !less {
		return false
	}
	var zero [32]byte
	one := [32]byte{1}
	if y == zero || y == one || y == minusOne {
		return false
	}
	order8a := []byte{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}
	order8b := []byte{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}
	return !bytes.Equal(y[:], order8a) && !bytes.Equal(y[:], order8b)
}

// The canonical little-endian Ed25519 scalar order L from RFC 8032. Signature
// R uses the same strict finite point-encoding policy as publisher public keys.
func canonicalEd25519Signature(signature []byte) bool {
	if len(signature) != 64 || !strongEd25519Encoding(signature[:32]) {
		return false
	}
	order := [32]byte{0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}
	for i := 31; i >= 0; i-- {
		if signature[32+i] < order[i] {
			return true
		}
		if signature[32+i] > order[i] {
			return false
		}
	}
	return false
}
