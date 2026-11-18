// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsdk

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/wasmsecure"
)

const RequestSchema = "wsea-sdk-1"
const ResponseSchema = "wsea-sdk-response-1"
const MaxResponseBytes = 96 << 20
const MaxExchangeBytes = ((MaxRequestBytes+2)/3)*4 + ((MaxResponseBytes+2)/3)*4 + 1024
const MaxErrorBytes = 4096

func required(m map[string]bool, paths ...string) bool {
	for _, path := range paths {
		if !m[path] {
			return false
		}
	}
	return true
}

func isBytesMember(path string) bool {
	switch path {
	case "request", "response", "module", "request_sha256", "trust.policy", "trust.roots", "trust.state", "signing.key", "signing.certificates", "signing.crls", "signing.manifest.sha256", "manifest.sha256":
		return true
	}
	return false
}

// encoding/json accepts whitespace and nonzero padding bits in base64. Require
// one unambiguous standard encoding without allocating a second decoded copy.
func canonicalBase64(text string) bool {
	if len(text)%4 != 0 {
		return false
	}
	index := func(c byte) int {
		switch {
		case c >= 'A' && c <= 'Z':
			return int(c - 'A')
		case c >= 'a' && c <= 'z':
			return int(c-'a') + 26
		case c >= '0' && c <= '9':
			return int(c-'0') + 52
		case c == '+':
			return 62
		case c == '/':
			return 63
		}
		return -1
	}
	end := len(text)
	for end > 0 && text[end-1] == '=' {
		end--
	}
	padding := len(text) - end
	if padding > 2 || (padding != 0 && end == 0) {
		return false
	}
	for i := 0; i < end; i++ {
		if index(text[i]) < 0 {
			return false
		}
	}
	if padding == 1 && index(text[end-1])&3 != 0 || padding == 2 && index(text[end-1])&15 != 0 {
		return false
	}
	return true
}

func validPins(pins []string, limit int) bool {
	if pins == nil || len(pins) > limit {
		return false
	}
	seen := make(map[string]bool, len(pins))
	for _, pin := range pins {
		if len(pin) != 64 || strings.Trim(pin, "0123456789abcdef") != "" || seen[pin] {
			return false
		}
		seen[pin] = true
	}
	return true
}

func exactAlgorithm(name wasmsecure.Algorithm) bool {
	profiles, err := wasmsecure.ParseAlgorithms(string(name))
	return err == nil && len(profiles) == 1 && profiles[0] == name
}

// ValidateRequestJSON validates the wire contract only. It does not establish
// the authenticity, freshness or authorization of a supplied trust snapshot.
func ValidateRequestJSON(data []byte) error {
	r, err := decodeRequest(data)
	clear(r.SigningKey())
	return err
}

func decodeRequest(data []byte) (Request, error) {
	var r Request
	bad := func() (Request, error) {
		clear(r.SigningKey())
		return Request{}, errors.New("SDK_001: invalid request contract")
	}
	if len(data) > MaxRequestBytes {
		return bad()
	}
	members, err := strictJSONMembers(data, &r)
	if err != nil {
		clear(r.SigningKey())
		return Request{}, err
	}
	if !required(members, "schema", "operation", "module", "trust", "trust.policy", "trust.roots", "trust.state", "trust.revoked_spkis") ||
		r.Schema != RequestSchema || (r.Operation != "sign" && r.Operation != "verify") ||
		len(r.Module) < 8 || len(r.Module) > MaxModuleBytes ||
		len(r.Trust.Policy) == 0 || len(r.Trust.Policy) > wasmsecure.MaxSignatureBytes ||
		len(r.Trust.Roots) == 0 || len(r.Trust.Roots) > wasmsecure.MaxEvidenceBytes ||
		len(r.Trust.State) == 0 || len(r.Trust.State) > 1<<20 || !validPins(r.Trust.RevokedSPKIs, 8192) {
		return bad()
	}
	if r.Operation == "verify" {
		if members["signing"] {
			return bad()
		}
		return r, nil
	}
	if r.Signing == nil || !required(members, "signing", "signing.key", "signing.certificates", "signing.crls",
		"signing.manifest", "signing.manifest.embedded", "signing.manifest.algorithm", "signing.manifest.module_id",
		"signing.manifest.version", "signing.manifest.security_epoch", "signing.manifest.not_before",
		"signing.manifest.not_after", "signing.manifest.abi", "signing.manifest.capabilities") ||
		members["signing.manifest.size"] || members["signing.manifest.sha256"] ||
		members["signing.manifest.signer_spkis"] || members["signing.manifest.signature_algorithms"] {
		return bad()
	}
	s := r.Signing
	if s.Append && s.Replace || len(s.Key) == 0 || len(s.Key) > wasmsecure.MaxEvidenceBytes ||
		len(s.Certificates) == 0 || len(s.Certificates) > wasmsecure.MaxEvidenceBytes ||
		len(s.CRLs) == 0 || len(s.CRLs) > wasmsecure.MaxEvidenceBytes {
		return bad()
	}
	// These two fields are calculated by Sign from the actual module bytes.
	m := s.Manifest
	m.Size = 8
	m.Digest = make([]byte, sha256.Size)
	if err := m.Validate(); err != nil || !exactAlgorithm(m.Algorithm) {
		return bad()
	}
	return r, nil
}

// ValidateResponseJSON checks shape and snapshot invariants, not signatures or
// the host's current trust state. An expired snapshot remains a valid historical
// response; callers must recheck the current clock and trust before using it.
func ValidateResponseJSON(data []byte) error {
	_, err := decodeResponse(data)
	return err
}

func decodeResponse(data []byte) (Response, error) {
	var r Response
	bad := func() (Response, error) { return Response{}, errors.New("SDK_001: invalid response contract") }
	if len(data) > MaxResponseBytes {
		return bad()
	}
	members, err := strictJSONMembers(data, &r)
	if err != nil {
		return Response{}, err
	}
	if !required(members, "schema", "status", "request_sha256") || r.Schema != ResponseSchema || len(r.RequestSHA256) != sha256.Size {
		return bad()
	}
	if r.Status == "REJECTED" {
		if !members["error"] || r.Error == "" || len(r.Error) > MaxErrorBytes || members["operation"] ||
			members["manifest"] || members["module"] || members["checked_at"] || members["valid_until"] {
			return bad()
		}
		return r, nil
	}
	if r.Status != "VERIFIED_SNAPSHOT" && r.Status != "SIGNED_PARTIAL" || members["error"] ||
		!required(members, "operation", "manifest", "checked_at", "valid_until", "manifest.embedded",
			"manifest.algorithm", "manifest.module_id", "manifest.version", "manifest.security_epoch", "manifest.size",
			"manifest.sha256", "manifest.not_before", "manifest.not_after", "manifest.abi", "manifest.capabilities",
			"manifest.signer_spkis", "manifest.signature_algorithms") || r.Manifest == nil ||
		(r.Operation != "sign" && r.Operation != "verify") ||
		(r.Operation == "verify" && (r.Status == "SIGNED_PARTIAL" || members["module"])) ||
		(r.Operation == "sign" && (!members["module"] || len(r.Module) < 8 || len(r.Module) > MaxModuleBytes)) {
		return bad()
	}
	m := r.Manifest
	if err := m.Validate(); err != nil || m.Size > MaxModuleBytes || !exactAlgorithm(m.Algorithm) ||
		len(m.SignerSPKIs) == 0 || !validPins(m.SignerSPKIs, wasmsecure.MaxSignatures) ||
		len(m.SignatureAlgorithms) < len(m.SignerSPKIs) || len(m.SignatureAlgorithms) > wasmsecure.MaxSignatures ||
		m.SignatureAlgorithms[0] != m.Algorithm || r.CheckedAt < 1577836800 ||
		r.CheckedAt < m.NotBefore || r.CheckedAt >= r.ValidUntil || r.ValidUntil > m.NotAfter {
		return bad()
	}
	for _, algorithm := range m.SignatureAlgorithms {
		if !exactAlgorithm(algorithm) {
			return bad()
		}
	}
	if r.Operation == "sign" && matchModule(r.Module, m) != nil {
		return bad()
	}
	return r, nil
}

func matchModule(module []byte, manifest *wasmsecure.Manifest) error {
	core, evidence, err := wasmsecure.ExtractAll(module)
	if err != nil || len(evidence) != len(manifest.SignatureAlgorithms) {
		return errors.New("SDK_001: module evidence does not match snapshot")
	}
	digest := sha256.Sum256(core)
	if manifest.Size != uint64(len(core)) || !bytes.Equal(manifest.Digest, digest[:]) {
		return errors.New("SDK_001: module bytes do not match snapshot")
	}
	for i, contribution := range evidence {
		parsed, _, _, err := wasmsecure.Parse(contribution.Signature)
		if err != nil || parsed.Algorithm != manifest.SignatureAlgorithms[i] {
			return errors.New("SDK_001: signature metadata does not match snapshot")
		}
		want := *manifest
		want.Algorithm = parsed.Algorithm
		want.SignerSPKIs = nil
		want.SignatureAlgorithms = nil
		if !reflect.DeepEqual(parsed, want) {
			return errors.New("SDK_001: authenticated payload does not match snapshot")
		}
	}
	return nil
}

// ValidateExchangeJSON binds a successful response to its exact request. It
// checks module/payload consistency but does not independently verify crypto.
func ValidateExchangeJSON(request, response []byte) error {
	r, err := decodeResponse(response)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(request)
	if !bytes.Equal(r.RequestSHA256, digest[:]) {
		return errors.New("SDK_001: response request digest does not match")
	}
	if r.Status == "REJECTED" {
		return nil
	}
	q, err := decodeRequest(request)
	if err != nil {
		return err
	}
	defer clear(q.SigningKey())
	if q.Operation != r.Operation {
		return errors.New("SDK_001: response operation does not match request")
	}
	if q.Operation == "verify" {
		return matchModule(q.Module, r.Manifest)
	}
	if r.Status == "SIGNED_PARTIAL" && !q.Signing.AllowPartial {
		return errors.New("SDK_001: partial signing result was not requested")
	}
	core, err := wasmsecure.SigningInput(q.Module, q.Signing.Append || q.Signing.Replace)
	if err != nil {
		return err
	}
	digest = sha256.Sum256(core)
	want := q.Signing.Manifest
	want.Size = uint64(len(core))
	want.Digest = digest[:]
	got := *r.Manifest
	got.Algorithm = want.Algorithm
	got.SignerSPKIs = nil
	got.SignatureAlgorithms = nil
	if !reflect.DeepEqual(want, got) || r.Manifest.SignatureAlgorithms[len(r.Manifest.SignatureAlgorithms)-1] != want.Algorithm {
		return errors.New("SDK_001: signed response does not match request")
	}
	return nil
}

// ValidateExchangeEnvelopeJSON accepts base64-encoded original request and
// response bytes, preserving whitespace and full-width integers exactly.
func ValidateExchangeEnvelopeJSON(data []byte) error {
	if len(data) > MaxExchangeBytes {
		return errors.New("SDK_001: exchange too large")
	}
	var envelope struct {
		Request  []byte `json:"request"`
		Response []byte `json:"response"`
	}
	members, err := strictJSONMembers(data, &envelope)
	if err != nil {
		return err
	}
	if !required(members, "request", "response") {
		return errors.New("SDK_001: incomplete exchange")
	}
	defer clear(envelope.Request)
	return ValidateExchangeJSON(envelope.Request, envelope.Response)
}
