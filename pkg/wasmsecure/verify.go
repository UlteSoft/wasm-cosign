// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Evidence contains untrusted downloaded material. Roots must always come from
// the independently installed local policy, never the evidence bundle.
type Evidence struct{ Signature, Certificates, CRLs []byte }

// strictPEM never skips malformed or unrelated leading blocks, as pem.Decode
// normally does. Each next block must be complete before the following begins.
func strictPEM(data []byte, kind string) (*pem.Block, []byte) {
	data = bytes.TrimSpace(data)
	begin := []byte("-----BEGIN " + kind + "-----")
	end := []byte("-----END " + kind + "-----")
	if !bytes.HasPrefix(data, begin) {
		return nil, nil
	}
	n := bytes.Index(data, end)
	if n < 0 || bytes.Contains(data[len(begin):n], []byte("-----BEGIN ")) {
		// pem.Decode skips malformed leading blocks. A nested BEGIN before
		// this block's first END must never become a substitute certificate.
		return nil, nil
	}
	n += len(end)
	block, rest := pem.Decode(data[:n])
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, nil
	}
	return block, data[n:]
}

func Certificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := strictPEM(data, "CERTIFICATE")
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("CERT_002: invalid PEM certificate bundle")
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("CERT_002: %w", e)
		}
		if !strictSubjectPublicKeyInfo(c.RawSubjectPublicKeyInfo) {
			return nil, errors.New("CERT_002: public key requires a complete DER SPKI with a byte-aligned BIT STRING")
		}
		out = append(out, c)
		data = rest
		if len(out) > 16 {
			return nil, errors.New("CERT_002: too many certificates")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("CERT_002: missing signer certificate")
	}
	return out, nil
}
func parseCRLs(data []byte) ([]*x509.RevocationList, error) {
	var out []*x509.RevocationList
	for len(bytes.TrimSpace(data)) > 0 {
		block, rest := strictPEM(data, "X509 CRL")
		if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 {
			return nil, errors.New("CERT_005: invalid CRL PEM")
		}
		c, e := x509.ParseRevocationList(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("CERT_005: %w", e)
		}
		// ParseRevocationList retains only the first outer sequence in Raw;
		// unlike ParseCertificate it need not reject following DER bytes.
		if !bytes.Equal(c.Raw, block.Bytes) {
			return nil, errors.New("CERT_005: trailing DER inside CRL PEM")
		}
		out = append(out, c)
		data = rest
		if len(out) > 16 {
			return nil, errors.New("CERT_005: too many CRLs")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("CERT_005: missing CRL evidence")
	}
	return out, nil
}
func allowedCertificate(c *x509.Certificate) bool {
	if c.IsCA && (!c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0) {
		return false
	}
	return allowedPKISignature(c.SignatureAlgorithm, c.Raw) && allowedPublicKey(c.PublicKey)
}
func checkCRL(cert, issuer *x509.Certificate, crls []*x509.RevocationList, now time.Time, maxAge uint64) error {
	found := false
	for _, crl := range crls {
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
			continue
		}
		if crl.CheckSignatureFrom(issuer) != nil {
			return errors.New("CERT_005: CRL signature or issuer usage verification failed")
		}
		// Only complete direct CRLs are supported; distribution point scoping,
		// delta CRLs and indirect CRLs must never be treated as complete evidence.
		for _, ext := range crl.Extensions {
			if ext.Critical || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) {
				return errors.New("CERT_005: unsupported critical, delta or scoped CRL")
			}
		}
		if !allowedPKISignature(crl.SignatureAlgorithm, crl.Raw) {
			return errors.New("SIG_005: disallowed CRL signature algorithm or parameters")
		}

		if crl.ThisUpdate.After(now) || crl.NextUpdate.IsZero() || !crl.NextUpdate.After(now) || crl.NextUpdate.Before(crl.ThisUpdate) || now.Sub(crl.ThisUpdate) < 0 || uint64(now.Unix()-crl.ThisUpdate.Unix()) > maxAge {
			return errors.New("CERT_005: CRL evidence is stale or not yet valid")
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, ext := range entry.Extensions {
				if ext.Critical || ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 29}) {
					return errors.New("CERT_005: unsupported indirect CRL entry")
				}
			}
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return errors.New("CERT_004: signer or intermediate certificate is revoked")
			}
		}
		found = true
	}
	if !found {
		return errors.New("CERT_005: missing valid fresh CRL for certificate issuer")
	}
	return nil
}

// Verify performs the upper, offline deployment gate. It authenticates exact
// module bytes, the whole certificate path and fresh CRLs, then applies the
// independently provisioned module rule. It does not mutate VM rollback state.
func Verify(module []byte, e Evidence, p Policy, rootsPEM []byte, now time.Time) (Manifest, error) {
	m, err := verifyOne(module, e, p, rootsPEM, now, nil)
	if err == nil && p.Modules[m.ModuleID].RequiredSignatures() > 1 {
		return Manifest{}, errors.New("POL_002: one signature cannot satisfy the protected signature threshold")
	}
	return m, err
}

// verifyOne authenticates one contribution. Only the enclosing bundle verifier
// may authorize a multi-signature quorum. sharedDigest is computed once there.
func verifyOne(module []byte, e Evidence, p Policy, rootsPEM []byte, now time.Time, sharedDigest []byte) (Manifest, error) {
	var zero Manifest
	if uint64(len(module)) > p.MaxModuleBytes || len(module) < 8 || !bytes.Equal(module[:8], []byte{0, 97, 115, 109, 1, 0, 0, 0}) {
		return zero, errors.New("VM_001: invalid or oversized WebAssembly module")
	}
	if len(e.Signature) > MaxSignatureBytes || len(e.Certificates) > MaxEvidenceBytes || len(e.CRLs) > MaxEvidenceBytes || len(rootsPEM) > MaxEvidenceBytes {
		return zero, errors.New("SIG_002: evidence exceeds size limit")
	}
	m, payload, sig, err := Parse(e.Signature)
	if err != nil {
		return zero, err
	}
	if now.Unix() < 1577836800 || uint64(now.Unix()) < m.NotBefore || uint64(now.Unix()) >= m.NotAfter {
		return zero, errors.New("POL_004: manifest is not currently valid")
	}
	if sharedDigest == nil {
		d := sha256.Sum256(module)
		sharedDigest = d[:]
	}
	if m.Size != uint64(len(module)) || !bytes.Equal(m.Digest, sharedDigest) {
		return zero, errors.New("SIG_004: exact module bytes do not match signature")
	}
	rule, ok := p.Modules[m.ModuleID]
	if !ok {
		return zero, errors.New("CERT_006: module has no publisher authorization")
	}
	if !rule.AllowsAlgorithm(m.Algorithm) {
		return zero, errors.New("SIG_005: protected signing algorithm is not allowed for this module")
	}
	if m.ABI != rule.ABI {
		return zero, errors.New("POL_003: runtime ABI is not authorized")
	}
	if m.Version < rule.MinVersion || m.Epoch < rule.MinEpoch {
		return zero, errors.New("POL_001: module version or security epoch rollback")
	}
	if m.Capabilities & ^rule.AllowedCapabilities != 0 {
		return zero, errors.New("POL_003: module requests unauthorized capabilities")
	}
	certs, err := Certificates(e.Certificates)
	if err != nil {
		return zero, err
	}
	leaf := certs[0]
	if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return zero, errors.New("CERT_002: signer must be a digital-signature leaf certificate")
	}
	eku := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageCodeSigning {
			eku = true
		}
	}
	if !eku {
		return zero, errors.New("CERT_002: signer requires codeSigning EKU")
	}
	pin := SPKIDigest(leaf.RawSubjectPublicKeyInfo)
	if !rule.AllowsSigner(pin) {
		return zero, errors.New("CERT_006: signer SPKI is not authorized for this module")
	}
	m.SignerSPKIs = []string{pin}
	m.SignatureAlgorithms = []Algorithm{m.Algorithm}
	if err = verifyAlgorithmSignature(m.Algorithm, payload, sig, leaf.PublicKey); err != nil {
		return zero, err
	}

	rootCerts, err := Certificates(rootsPEM)
	if err != nil {
		return zero, fmt.Errorf("CERT_001: invalid trust anchor certificate bundle: %v", err)
	}
	roots := x509.NewCertPool()
	for _, c := range rootCerts {
		if !c.IsCA || !allowedCertificate(c) {
			return zero, errors.New("CERT_001: root fails certificate algorithm or CA constraints")
		}
		roots.AddCert(c)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		return zero, fmt.Errorf("CERT_002: %w", err)
	}
	crls, err := parseCRLs(e.CRLs)
	if err != nil {
		return zero, err
	}
	var last error
	for _, chain := range chains {
		last = nil
		if len(chain) < 2 {
			last = errors.New("CERT_001: self-signed leaf is prohibited")
			continue
		}
		// Admit every key and signature profile on the trusted path before a
		// revocation result is reported as an authenticated security fact.
		for _, c := range chain {
			if !allowedCertificate(c) {
				last = errors.New("SIG_005: disallowed certificate algorithm")
				break
			}
		}
		if last != nil {
			continue
		}
		for i := 0; i+1 < len(chain); i++ {
			if last = checkCRL(chain[i], chain[i+1], crls, now, p.MaxCRLAgeSeconds); last != nil {
				break
			}
		}
		if last == nil {
			return m, nil
		}
	}
	return zero, last
}
