// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

type signedDER struct {
	TBS       asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func strictSubjectPublicKeyInfo(raw []byte) bool {
	var info subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(raw, &info)
	return err == nil && len(rest) == 0 && derEqual(info, raw) && info.PublicKey.BitLength > 0 && info.PublicKey.BitLength%8 == 0
}

// All SHA2 PSS fields are mandatory (their ASN.1 defaults select forbidden
// SHA1). The optional trailer is retained verbatim so explicit integer 1 and
// the omitted default both have a strict, exact-consumption representation.
type strictPSSParameters struct {
	Hash       pkix.AlgorithmIdentifier `asn1:"explicit,tag:0"`
	MGF        pkix.AlgorithmIdentifier `asn1:"explicit,tag:1"`
	SaltLength int                      `asn1:"explicit,tag:2"`
	Trailer    asn1.RawValue            `asn1:"optional"`
}

func derEqual(value any, encoded []byte) bool {
	b, e := asn1.Marshal(value)
	return e == nil && bytes.Equal(b, encoded)
}
func nullOrAbsent(v asn1.RawValue) bool {
	return len(v.FullBytes) == 0 || bytes.Equal(v.FullBytes, asn1.NullBytes)
}
func strictPSS(ai pkix.AlgorithmIdentifier, hash crypto.Hash) bool {
	var p strictPSSParameters
	rest, e := asn1.Unmarshal(ai.Parameters.FullBytes, &p)
	if e != nil || len(rest) != 0 || !derEqual(p, ai.Parameters.FullBytes) || p.SaltLength != hash.Size() {
		return false
	}
	expected := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	switch hash {
	case crypto.SHA384:
		expected[len(expected)-1] = 2
	case crypto.SHA512:
		expected[len(expected)-1] = 3
	}
	if !p.Hash.Algorithm.Equal(expected) || !nullOrAbsent(p.Hash.Parameters) || !p.MGF.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}) {
		return false
	}
	var mgfHash pkix.AlgorithmIdentifier
	rest, e = asn1.Unmarshal(p.MGF.Parameters.FullBytes, &mgfHash)
	if e != nil || len(rest) != 0 || !derEqual(mgfHash, p.MGF.Parameters.FullBytes) || !mgfHash.Algorithm.Equal(expected) || !nullOrAbsent(mgfHash.Parameters) {
		return false
	}
	if len(p.Trailer.FullBytes) > 0 {
		if p.Trailer.Class != asn1.ClassContextSpecific || p.Trailer.Tag != 3 || !p.Trailer.IsCompound {
			return false
		}
		var trailer int
		rest, e = asn1.Unmarshal(p.Trailer.Bytes, &trailer)
		if e != nil || len(rest) != 0 || trailer != 1 || !derEqual(trailer, p.Trailer.Bytes) {
			return false
		}
	}
	return true
}

// Go x509 verifies certificate/CRL signatures and exact inner/outer algorithm
// equality. This additionally rejects unknown/duplicate PSS parameters and
// checks canonical algorithm identifiers before relying on those signatures.
//
//nolint:unparam // Test oracle keeps the algorithm explicit; production PKI verification uses the shared native core.
func allowedPKISignature(algorithm x509.SignatureAlgorithm, raw []byte) bool {
	var signed signedDER
	rest, e := asn1.Unmarshal(raw, &signed)
	if e != nil || len(rest) != 0 || !derEqual(signed, raw) || signed.Signature.BitLength%8 != 0 {
		return false
	}
	ai := signed.Algorithm
	switch algorithm {
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		suffix := 2
		switch algorithm {
		case x509.ECDSAWithSHA384:
			suffix = 3
		case x509.ECDSAWithSHA512:
			suffix = 4
		}
		return ai.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, suffix}) && len(ai.Parameters.FullBytes) == 0
	case x509.PureEd25519:
		return ai.Algorithm.Equal(asn1.ObjectIdentifier{1, 3, 101, 112}) && len(ai.Parameters.FullBytes) == 0 && canonicalEd25519Signature(signed.Signature.Bytes)
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		suffix := 11
		switch algorithm {
		case x509.SHA384WithRSA:
			suffix = 12
		case x509.SHA512WithRSA:
			suffix = 13
		}
		return ai.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, suffix}) && nullOrAbsent(ai.Parameters)
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		if !ai.Algorithm.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}) {
			return false
		}
		hash := crypto.SHA256
		switch algorithm {
		case x509.SHA384WithRSAPSS:
			hash = crypto.SHA384
		case x509.SHA512WithRSAPSS:
			hash = crypto.SHA512
		}
		return strictPSS(ai, hash)
	}
	return false
}
func allowedPublicKey(key any) bool {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return k != nil && k.X != nil && k.Y != nil && (k.Curve == elliptic.P256() || k.Curve == elliptic.P384() || k.Curve == elliptic.P521()) && k.IsOnCurve(k.X, k.Y) //nolint:staticcheck // SA1019: preserve explicit rejection of malformed caller-supplied coordinates.
	case ed25519.PublicKey:
		return strongEd25519Encoding(k)
	case *rsa.PublicKey:
		return strongRSA(k)
	}
	return false
}
