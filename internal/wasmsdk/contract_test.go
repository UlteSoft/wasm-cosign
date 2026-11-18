// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sigstore/cosign/v3/pkg/wasmsecure"
)

func contractFixture(t *testing.T) (Request, Response, Request, Response) {
	t.Helper()
	core := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := wasmsecure.Manifest{Embedded: true, Algorithm: wasmsecure.AlgorithmEd25519,
		ModuleID: "test.module", Version: ^uint64(0), Epoch: 9007199254740993,
		NotBefore: 1700000000, NotAfter: 1900000000, ABI: "uwvm2"}
	signature, err := wasmsecure.Sign(core, input, key)
	if err != nil {
		t.Fatal(err)
	}
	module, err := wasmsecure.Embed(core, wasmsecure.Evidence{Signature: signature, Certificates: []byte("cert"), CRLs: []byte("crl")})
	if err != nil {
		t.Fatal(err)
	}
	verified := input
	verified.Size = uint64(len(core))
	digest := sha256.Sum256(core)
	verified.Digest = digest[:]
	verified.SignerSPKIs = []string{strings.Repeat("a", 64)}
	verified.SignatureAlgorithms = []wasmsecure.Algorithm{wasmsecure.AlgorithmEd25519}
	trust := Trust{Policy: []byte("policy"), Roots: []byte("roots"), State: []byte("state"), RevokedSPKIs: []string{}}
	verifyRequest := Request{Schema: RequestSchema, Operation: "verify", Module: module, Trust: trust}
	verifyDigest := sha256.Sum256(contractJSON(t, verifyRequest))
	verifyResponse := Response{Schema: ResponseSchema, Status: "VERIFIED_SNAPSHOT", Operation: "verify", Manifest: &verified,
		RequestSHA256: verifyDigest[:], CheckedAt: 1750000000, ValidUntil: 1800000000}
	signRequest := Request{Schema: RequestSchema, Operation: "sign", Module: core, Trust: trust,
		Signing: &Signing{Key: []byte("key"), Certificates: []byte("cert"), CRLs: []byte("crl"), Manifest: input}}
	signDigest := sha256.Sum256(contractJSON(t, signRequest))
	signResponse := verifyResponse
	signResponse.Operation = "sign"
	signResponse.RequestSHA256 = signDigest[:]
	signResponse.Module = module
	return verifyRequest, verifyResponse, signRequest, signResponse
}

func contractJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestContractValidSnapshotsAndFullWidthIntegers(t *testing.T) {
	verifyRequest, verifyResponse, signRequest, signResponse := contractFixture(t)
	for _, pair := range [][2]any{{verifyRequest, verifyResponse}, {signRequest, signResponse}} {
		request, response := contractJSON(t, pair[0]), contractJSON(t, pair[1])
		if err := ValidateRequestJSON(request); err != nil {
			t.Fatalf("valid request: %v", err)
		}
		if err := ValidateResponseJSON(response); err != nil {
			t.Fatalf("valid response: %v", err)
		}
		if err := ValidateExchangeJSON(request, response); err != nil {
			t.Fatalf("valid exchange: %v", err)
		}
		if !strings.Contains(string(response), `"version":18446744073709551615`) ||
			!strings.Contains(string(response), `"security_epoch":9007199254740993`) {
			t.Fatal("full-width integer was rounded")
		}
		envelope := contractJSON(t, struct {
			Request  []byte `json:"request"`
			Response []byte `json:"response"`
		}{request, response})
		if err := ValidateExchangeEnvelopeJSON(envelope); err != nil {
			t.Fatalf("valid exchange envelope: %v", err)
		}
	}
	partial := signResponse
	partial.Status = "SIGNED_PARTIAL"
	if err := ValidateResponseJSON(contractJSON(t, partial)); err != nil {
		t.Fatalf("valid partial snapshot: %v", err)
	}
	if err := ValidateExchangeJSON(contractJSON(t, signRequest), contractJSON(t, partial)); err == nil {
		t.Fatal("accepted an unrequested partial signing result")
	}
	options := *signRequest.Signing
	options.AllowPartial = true
	signRequest.Signing = &options
	partialRequest := contractJSON(t, signRequest)
	partialDigest := sha256.Sum256(partialRequest)
	partial.RequestSHA256 = partialDigest[:]
	if err := ValidateExchangeJSON(partialRequest, contractJSON(t, partial)); err != nil {
		t.Fatalf("valid partial signing exchange: %v", err)
	}
	rejected := Process([]byte(`{}`))
	if rejected.Status != "REJECTED" || ValidateResponseJSON(contractJSON(t, rejected)) != nil {
		t.Fatal("rejection is not a versioned contract response")
	}
}

func TestContractRejectsAmbiguousOrInvalidRequests(t *testing.T) {
	verify, _, sign, _ := contractFixture(t)
	base := string(contractJSON(t, verify))
	invalid := []string{
		strings.Replace(base, `"schema":"wsea-sdk-1"`, `"schema":"wrong"`, 1),
		strings.Replace(base, `"operation":"verify"`, `"operation":"verify","operation":"sign"`, 1),
		strings.Replace(base, `"trust":{`, `"trust":{"unknown":1,`, 1),
		strings.Replace(base, `"revoked_spkis":[]`, `"revoked_spkis":null`, 1),
		strings.Replace(base, `"revoked_spkis":[]`, `"revoked_spkis":["`+strings.Repeat("a", 64)+`","`+strings.Repeat("a", 64)+`"]`, 1),
		strings.Replace(base, `"policy":"cG9saWN5"`, `"policy":"cG9saWN5\n"`, 1),
		strings.Replace(base, `"policy":"cG9saWN5"`, `"policy":"AB=="`, 1),
		base + `{}`,
	}
	signing := string(contractJSON(t, sign))
	invalid = append(invalid,
		strings.Replace(signing, `"version":18446744073709551615`, `"version":18446744073709551616`, 1),
		strings.Replace(signing, `"version":18446744073709551615`, `"version":-1`, 1),
		strings.Replace(signing, `"not_after":1900000000`, `"not_after":1700000000`, 1),
		strings.Replace(signing, `"manifest":{`, `"manifest":{"size":8,`, 1),
		strings.Replace(strings.Replace(signing, `"append":false`, `"append":true`, 1), `"replace":false`, `"replace":true`, 1),
	)
	for _, text := range invalid {
		if err := ValidateRequestJSON([]byte(text)); err == nil {
			t.Errorf("accepted invalid request: %s", text)
		}
	}
}

func TestContractRejectsInvalidResponsesAndMismatchedExchange(t *testing.T) {
	request, response, signRequest, signResponse := contractFixture(t)
	base := string(contractJSON(t, response))
	rejected := string(contractJSON(t, Process([]byte(`{}`))))
	invalid := []string{
		strings.Replace(base, ResponseSchema, "wrong", 1),
		strings.Replace(base, `"status":"VERIFIED_SNAPSHOT"`, `"status":"VERIFIED_SNAPSHOT","status":"REJECTED"`, 1),
		strings.Replace(base, `"manifest":{`, `"manifest":{"unknown":0,`, 1),
		strings.Replace(base, `"checked_at":1750000000`, `"checked_at":1800000000`, 1),
		strings.Replace(base, `"valid_until":1800000000`, `"valid_until":1900000001`, 1),
		strings.Replace(base, `"checked_at":1750000000`, `"checked_at":-1`, 1),
		strings.Replace(base, `"version":18446744073709551615`, `"version":18446744073709551616`, 1),
		strings.Replace(base, `"status":"VERIFIED_SNAPSHOT"`, `"status":"SIGNED_PARTIAL"`, 1),
		strings.Replace(base, `"operation":"verify"`, `"operation":"sign"`, 1),
		strings.Replace(base, `"signer_spkis":[`, `"signer_spkis":["bad",`, 1),
		strings.Replace(base, `"signature_algorithms":["Ed25519"]`, `"signature_algorithms":[]`, 1),
		strings.Replace(rejected, `"status":"REJECTED"`, `"status":"REJECTED","checked_at":1`, 1),
		strings.Replace(rejected, `"status":"REJECTED"`, `"status":"REJECTED","extra":true`, 1),
		strings.Replace(rejected, `"status":"REJECTED"`, `"status":"ERROR"`, 1),
	}
	for _, text := range invalid {
		if err := ValidateResponseJSON([]byte(text)); err == nil {
			t.Errorf("accepted invalid response: %s", text)
		}
	}
	request.Module = append([]byte(nil), request.Module...)
	request.Module[4] ^= 1
	changedRequest := contractJSON(t, request)
	changedDigest := sha256.Sum256(changedRequest)
	response.RequestSHA256 = changedDigest[:]
	if ValidateExchangeJSON(changedRequest, contractJSON(t, response)) == nil {
		t.Fatal("accepted snapshot for a different module")
	}
	signRequest.Signing.Manifest.Version--
	changedSignRequest := contractJSON(t, signRequest)
	changedSignDigest := sha256.Sum256(changedSignRequest)
	signResponse.RequestSHA256 = changedSignDigest[:]
	if ValidateExchangeJSON(changedSignRequest, contractJSON(t, signResponse)) == nil {
		t.Fatal("accepted signing snapshot for different requested metadata")
	}
	signResponse.Module = append([]byte(nil), signResponse.Module...)
	signResponse.Module[4] ^= 1
	if ValidateResponseJSON(contractJSON(t, signResponse)) == nil {
		t.Fatal("accepted corrupted signed module")
	}
}

func TestContractRejectsOversizedDocuments(t *testing.T) {
	data := make([]byte, MaxRequestBytes+1)
	if ValidateRequestJSON(data) == nil || ValidateResponseJSON(data) == nil {
		t.Fatal("accepted document above the transport limit")
	}
}
