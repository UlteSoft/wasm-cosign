// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bundle

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"testing"

	"github.com/sigstore/cosign/v3/internal/test"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

func TestLocalCertChainProvider_GetCertificateChain(t *testing.T) {
	rootCert, rootKey, err := test.GenerateRootCa()
	if err != nil {
		t.Fatalf("GenerateRootCa: %v", err)
	}
	subCert, subKey, err := test.GenerateSubordinateCa(rootCert, rootKey)
	if err != nil {
		t.Fatalf("GenerateSubordinateCa: %v", err)
	}
	leafCert, _, err := test.GenerateLeafCert("subject@mail.com", "oidc-issuer", subCert, subKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert: %v", err)
	}

	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("MarshalCertificateToPEM: %v", err)
	}
	subAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}
	leafSubAndRootPEM, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{leafCert, subCert, rootCert})
	if err != nil {
		t.Fatalf("MarshalCertificatesToPEM: %v", err)
	}

	testCases := []struct {
		name      string
		cert      []byte
		chain     []byte
		wantDER   [][]byte
		wantError bool
	}{
		{
			name:    "leaf with root-only chain drops the self-signed root",
			cert:    leafPEM,
			chain:   rootPEM,
			wantDER: [][]byte{leafCert.Raw},
		},
		{
			name:    "leaf with sub and root chain drops the self-signed root",
			cert:    leafPEM,
			chain:   subAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:    "leaf already present in chain is deduped and root is dropped",
			cert:    leafPEM,
			chain:   leafSubAndRootPEM,
			wantDER: [][]byte{leafCert.Raw, subCert.Raw},
		},
		{
			name:      "invalid leaf PEM",
			cert:      []byte("not a pem"),
			chain:     rootPEM,
			wantError: true,
		},
		{
			name:      "invalid chain PEM",
			cert:      leafPEM,
			chain:     []byte("not a pem"),
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := &localCertChainProvider{cert: tc.cert, chain: tc.chain}
			got, err := provider.GetCertificateChain(context.Background(), nil, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != len(tc.wantDER) {
				t.Fatalf("expected %d certs, got %d", len(tc.wantDER), len(got))
			}
			for i := range got {
				if !bytes.Equal(got[i], tc.wantDER[i]) {
					t.Errorf("cert at index %d does not match expected DER", i)
				}
			}
		})
	}
}

func TestVerifierOptionsForKeypair(t *testing.T) {
	tests := []struct {
		name        string
		algorithm   protocommon.PublicKeyDetails
		privateKey  crypto.PrivateKey
		wantType    any
		expectEmpty bool
	}{
		{
			name:      "ed25519ph",
			algorithm: protocommon.PublicKeyDetails_PKIX_ED25519_PH,
			wantType:  &signature.ED25519phVerifier{},
		},
		{
			name:       "rsa-pss",
			algorithm:  protocommon.PublicKeyDetails_PKIX_RSA_PSS_2048_SHA256,
			privateKey: mustRSAKey(t),
			wantType:   &signature.RSAPSSVerifier{},
		},
		{
			name:        "default-ecdsa",
			algorithm:   protocommon.PublicKeyDetails_PKIX_ECDSA_P256_SHA_256,
			expectEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keypair, err := sign.NewEphemeralKeypair(&sign.EphemeralKeypairOptions{Algorithm: tt.algorithm})
			if err != nil {
				t.Fatal(err)
			}
			opts := VerifierOptionsForKeypair(keypair)
			if tt.expectEmpty {
				if len(opts) != 0 {
					t.Fatalf("len(opts) = %d, want 0", len(opts))
				}
				return
			}

			pubKey := keypair.GetPublicKey()
			if tt.privateKey != nil {
				pubKey = tt.privateKey.(*rsa.PrivateKey).Public()
			}
			verifier, err := signature.LoadDefaultVerifier(pubKey, opts...)
			if err != nil {
				t.Fatal(err)
			}
			switch tt.wantType.(type) {
			case *signature.ED25519phVerifier:
				if _, ok := verifier.(*signature.ED25519phVerifier); !ok {
					t.Fatalf("verifier = %T, want *signature.ED25519phVerifier", verifier)
				}
			case *signature.RSAPSSVerifier:
				if _, ok := verifier.(*signature.RSAPSSVerifier); !ok {
					t.Fatalf("verifier = %T, want *signature.RSAPSSVerifier", verifier)
				}
			}
		})
	}
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
