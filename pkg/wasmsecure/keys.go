// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// ParsePrivateKey accepts exactly one unencrypted PKCS8, SEC1 EC or PKCS1 RSA
// PEM block. It never skips malformed leading blocks, ignores PEM headers, or
// retries a different key parser after a failure. Key/algorithm agreement is
// checked separately by Sign, with no algorithm fallback.
func ParsePrivateKey(data []byte) (any, error) {
	data = bytes.TrimSpace(data)
	var kind string
	for _, candidate := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"} {
		if bytes.HasPrefix(data, []byte("-----BEGIN "+candidate+"-----")) {
			kind = candidate
			break
		}
	}
	if kind == "" {
		return nil, errors.New("SIG_005: expected one unencrypted PKCS8, EC or RSA private key PEM")
	}
	block, rest := strictPEM(data, kind)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, errors.New("SIG_005: malformed or multiple private key PEM blocks")
	}
	// Several x509 private-key parsers intentionally ignore bytes following
	// their outer ASN.1 object. A WSEA key file contains exactly one DER object.
	var outer asn1.RawValue
	trailing, parseErr := asn1.Unmarshal(block.Bytes, &outer)
	if parseErr != nil || len(trailing) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence || !outer.IsCompound {
		return nil, errors.New("SIG_005: private key must contain exactly one DER sequence")
	}
	var key any
	var err error
	switch kind {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	switch key.(type) {
	case *ecdsa.PrivateKey, *rsa.PrivateKey, ed25519.PrivateKey:
		return key, nil
	}
	return nil, errors.New("SIG_005: unsupported private key type")
}
