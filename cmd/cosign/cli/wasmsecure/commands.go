// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.

// Package wasmsecurecli manages embedded WSEA signatures and local trust.
package wasmsecurecli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/v3/pkg/wasmsecure"
	"github.com/spf13/cobra"
)

func Command() *cobra.Command {
	c := &cobra.Command{Use: "secure", Short: "Manage embedded WSEA custom-section signatures and offline UWVM trust"}
	c.AddCommand(signCommand(), verifyCommand(), fetchCommand(), policyCommand(), policyUpdateCommand())
	return c
}

type verification struct{ policy, certificate, crl string }

func (v *verification) flags(c *cobra.Command, signing bool) {
	c.Flags().StringVar(&v.policy, "policy", "", "protected WSEA policy file (required)")
	if signing {
		c.Flags().StringVar(&v.certificate, "certificate", "", "PEM leaf followed by intermediates to embed")
		c.Flags().StringVar(&v.crl, "crl", "", "authenticated complete CRL bundle to embed")
	}
	_ = c.MarkFlagRequired("policy")
}
func loadPolicy(path string) (wasmsecure.Policy, []byte, []byte, error) {
	var zero wasmsecure.Policy
	if e := wasmsecure.ProtectedPath(path, false); e != nil {
		return zero, nil, nil, e
	}
	b, e := wasmsecure.ReadBounded(path, wasmsecure.MaxSignatureBytes)
	if e != nil {
		return zero, nil, nil, e
	}
	p, e := wasmsecure.ParsePolicy(b)
	if e != nil {
		return p, nil, nil, e
	}
	if e = wasmsecure.ProtectedPath(p.TrustRoot, false); e != nil {
		return p, nil, nil, e
	}
	roots, e := wasmsecure.ReadBounded(p.TrustRoot, wasmsecure.MaxEvidenceBytes)
	return p, b, roots, e
}
func validate(module []byte, e wasmsecure.Evidence, p wasmsecure.Policy, pb, roots []byte) (wasmsecure.Manifest, error) {
	now := time.Now()
	m, err := wasmsecure.Verify(module, e, p, roots, now)
	if err == nil {
		err = wasmsecure.CheckCurrentState(pb, roots, p, m, now)
	}
	return m, err
}
func output(c *cobra.Command, m wasmsecure.Manifest) error {
	return json.NewEncoder(c.OutOrStdout()).Encode(struct {
		Status   string              `json:"status"`
		Manifest wasmsecure.Manifest `json:"manifest"`
	}{"VERIFIED", m})
}

func verifyCommand() *cobra.Command {
	v := new(verification)
	c := &cobra.Command{Use: "verify <module>", Short: "Verify exact module bytes, pinned signer, X.509 path, fresh CRLs and local rollback state", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		p, pb, roots, e := loadPolicy(v.policy)
		if e != nil {
			return e
		}
		module, e := wasmsecure.ReadBounded(a[0], int64(p.MaxModuleBytes))
		if e != nil {
			return e
		}
		now := time.Now()
		m, e := wasmsecure.VerifyEmbedded(module, p, roots, now)
		if e == nil {
			e = wasmsecure.CheckCurrentState(pb, roots, p, m, now)
		}
		if e != nil {
			return e
		}
		return output(c, m)
	}}
	v.flags(c, false)
	return c
}

func signCommand() *cobra.Command {
	v := new(verification)
	var key, id, algorithm, outputPath string
	var replaceSignature, appendSignature, allowPartial bool
	var version, epoch, capabilities uint64
	var notBefore, notAfter string
	c := &cobra.Command{Use: "sign <module>", Short: "Embed a policy-authorized signature, certificate chain and CRLs in one final WASM custom section", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		p, pb, roots, e := loadPolicy(v.policy)
		if e != nil {
			return e
		}
		requested, e := wasmsecure.ParseAlgorithms(algorithm)
		if e != nil || len(requested) != 1 || string(requested[0]) != algorithm {
			return errors.New("SIG_005: --algorithm requires one exact supported algorithm name")
		}
		rule, authorized := p.Modules[id]
		if !authorized {
			return errors.New("CERT_006: module has no publisher authorization")
		}
		if !rule.AllowsAlgorithm(wasmsecure.Algorithm(algorithm)) {
			return errors.New("SIG_005: signing algorithm is not allowed for this module")
		}
		module, e := wasmsecure.ReadBounded(a[0], int64(p.MaxModuleBytes))
		if e != nil {
			return e
		}
		if appendSignature && replaceSignature {
			return errors.New("--append-signature and --replace-signature are mutually exclusive")
		}
		core, e := wasmsecure.SigningInput(module, replaceSignature || appendSignature)
		if e != nil {
			return e
		}
		var contributions []wasmsecure.Evidence
		if appendSignature {
			now := time.Now()
			existing, err := wasmsecure.VerifyEmbeddedPartial(module, p, roots, now)
			if err != nil {
				return err
			}
			if err = wasmsecure.CheckCurrentState(pb, roots, p, existing, now); err != nil {
				return err
			}
			_, contributions, err = wasmsecure.ExtractAll(module)
			if err != nil {
				return err
			}
		}
		if e = wasmsecure.ProtectedPath(key, false); e != nil {
			return e
		}
		st, e := os.Stat(key)
		if e != nil {
			return e
		}
		if st.Mode().Perm()&0077 != 0 {
			return errors.New("signing key must not be accessible to group or others")
		}
		kb, e := wasmsecure.ReadBounded(key, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		private, e := wasmsecure.ParsePrivateKey(kb)
		if e != nil {
			return e
		}

		before, e := time.Parse(time.RFC3339, notBefore)
		if e != nil {
			return fmt.Errorf("--not-before: %w", e)
		}
		after, e := time.Parse(time.RFC3339, notAfter)
		if e != nil {
			return fmt.Errorf("--not-after: %w", e)
		}
		if before.Unix() < 0 || after.Unix() < 0 {
			return errors.New("validity timestamps must be after Unix epoch")
		}
		m := wasmsecure.Manifest{Embedded: true, Algorithm: wasmsecure.Algorithm(algorithm), ModuleID: id, Version: version, Epoch: epoch, NotBefore: uint64(before.Unix()), NotAfter: uint64(after.Unix()), ABI: "uwvm2", Capabilities: capabilities}
		sig, e := wasmsecure.Sign(core, m, private)
		if e != nil {
			return e
		}
		if v.certificate == "" || v.crl == "" {
			return errors.New("--certificate and --crl are required for signing")
		}
		cert, e := wasmsecure.ReadBounded(v.certificate, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		crl, e := wasmsecure.ReadBounded(v.crl, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		contributions = append(contributions, wasmsecure.Evidence{Signature: sig, Certificates: cert, CRLs: crl})
		signed, e := wasmsecure.EmbedAll(core, contributions)
		if e != nil {
			return e
		}
		now := time.Now()
		if allowPartial {
			m, e = wasmsecure.VerifyEmbeddedPartial(signed, p, roots, now)
		} else {
			m, e = wasmsecure.VerifyEmbedded(signed, p, roots, now)
		}
		if e != nil {
			return e
		}
		if e = wasmsecure.CheckCurrentState(pb, roots, p, m, now); e != nil {
			return e
		}
		if uint64(len(signed)) > p.MaxModuleBytes {
			return errors.New("SIG_004: signed module exceeds local size limit")
		}
		if outputPath == "" || filepath.Clean(outputPath) == filepath.Clean(a[0]) {
			latest, err := wasmsecure.ReadBounded(a[0], int64(p.MaxModuleBytes))
			if err != nil {
				return err
			}
			if !bytes.Equal(latest, module) {
				return errors.New("module changed during signing")
			}
			e = wasmsecure.ReplaceProtected(a[0], signed)
		} else {
			e = wasmsecure.WriteExclusive(outputPath, signed, 0600)
		}
		if e != nil {
			return e
		}
		if uint64(len(m.SignerSPKIs)) < rule.RequiredSignatures() {
			return json.NewEncoder(c.OutOrStdout()).Encode(struct {
				Status   string              `json:"status"`
				Manifest wasmsecure.Manifest `json:"manifest"`
			}{"SIGNED_PARTIAL", m})
		}
		return output(c, m)
	}}
	v.flags(c, true)
	c.Flags().StringVar(&outputPath, "output", "", "new signed WASM output; default atomically replaces the input")
	c.Flags().BoolVar(&replaceSignature, "replace-signature", false, "explicitly replace an existing final WSEA section")
	c.Flags().BoolVar(&appendSignature, "append-signature", false, "authenticate existing contributions and append a signature over the identical manifest")
	c.Flags().BoolVar(&allowPartial, "allow-partial", false, "signing workflow only: emit SIGNED_PARTIAL if the protected quorum is incomplete; verification, fetch and VM still refuse it")
	c.Flags().StringVar(&algorithm, "algorithm", "ES256", "exact signing algorithm permitted by the protected module rule")
	c.Flags().StringVar(&key, "key", "", "absolute path to a protected PEM ECDSA, Ed25519 or RSA private key")
	c.Flags().StringVar(&id, "module-id", "", "authorized module identity")
	c.Flags().Uint64Var(&version, "module-version", 0, "monotonic module release version")
	c.Flags().Uint64Var(&epoch, "security-epoch", 0, "monotonic module security epoch")
	c.Flags().Uint64Var(&capabilities, "capabilities", 0, "requested host capability mask (0..63)")
	c.Flags().StringVar(&notBefore, "not-before", "", "validity start in RFC3339 UTC")
	c.Flags().StringVar(&notAfter, "not-after", "", "validity end in RFC3339 UTC")
	for _, n := range []string{"key", "module-id", "module-version", "not-before", "not-after", "certificate", "crl"} {
		_ = c.MarkFlagRequired(n)
	}
	return c
}

func fetchCommand() *cobra.Command {
	var policy, moduleURL string
	c := &cobra.Command{Use: "fetch <output.wasm>", Short: "Download one bounded signed WASM over HTTPS, verify embedded WSEA, then publish without clobbering files", Args: cobra.ExactArgs(1), RunE: func(c *cobra.Command, a []string) error {
		p, pb, roots, e := loadPolicy(policy)
		if e != nil {
			return e
		}
		module, e := wasmsecure.FetchHTTPS(c.Context(), moduleURL, int64(p.MaxModuleBytes))
		if e != nil {
			return e
		}
		now := time.Now()
		m, e := wasmsecure.VerifyEmbedded(module, p, roots, now)
		if e != nil {
			return e
		}
		if e = wasmsecure.CheckCurrentState(pb, roots, p, m, now); e != nil {
			return e
		}
		if e = wasmsecure.WriteExclusive(a[0], module, 0600); e != nil {
			return e
		}
		return output(c, m)
	}}
	c.Flags().StringVar(&policy, "policy", "", "protected local WSEA policy")
	c.Flags().StringVar(&moduleURL, "url", "", "HTTPS URL of the complete WASM with embedded WSEA")
	_ = c.MarkFlagRequired("policy")
	_ = c.MarkFlagRequired("url")
	return c
}
func policyCommand() *cobra.Command {
	var out, root, state, cert, id, algorithms string
	var additionalCertificates []string
	var signatureThreshold uint64
	var version, minVersion, minEpoch, capabilities, maxAge, maxSize uint64
	c := &cobra.Command{Use: "policy-init", Short: "Bootstrap an OS protected local trust policy and VM rollback state (administrator operation)", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		for _, path := range []string{out, root, state, cert} {
			if !filepath.IsAbs(path) || filepath.Clean(path) != path {
				return errors.New("policy, trust root, certificate and state paths must be clean absolute paths")
			}
		}
		if e := wasmsecure.ProtectedPath(root, false); e != nil {
			return e
		}
		rb, e := wasmsecure.ReadBounded(root, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		if _, e = wasmsecure.Certificates(rb); e != nil {
			return e
		}
		cb, e := wasmsecure.ReadBounded(cert, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		certs, e := wasmsecure.Certificates(cb)
		if e != nil {
			return e
		}
		allowedAlgorithms, e := wasmsecure.ParseAlgorithms(algorithms)
		if e != nil {
			return e
		}
		pins, e := additionalSignerPins(additionalCertificates)
		if e != nil {
			return e
		}
		p := wasmsecure.Policy{Version: version, TrustRoot: root, StateDir: state, MaxCRLAgeSeconds: maxAge, MaxModuleBytes: maxSize, Modules: map[string]wasmsecure.ModuleRule{id: {ID: id, ABI: "uwvm2", SPKI: wasmsecure.SPKIDigest(certs[0].RawSubjectPublicKeyInfo), AdditionalSPKIs: pins, SignatureThreshold: signatureThreshold, MinVersion: minVersion, MinEpoch: minEpoch, AllowedCapabilities: capabilities, Algorithms: allowedAlgorithms}}}
		b, e := p.Marshal()
		if e != nil {
			return e
		}
		if e = os.Mkdir(state, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e = wasmsecure.ProtectedPath(state, true); e != nil {
			return e
		}
		statePath := filepath.Join(state, "state")
		if _, e = os.Lstat(statePath); os.IsNotExist(e) {
			if e = wasmsecure.WriteExclusive(statePath, []byte(wasmsecure.BootstrapState), 0600); e != nil {
				return e
			}
		} else if e != nil {
			return e
		} else {
			return errors.New("refusing to reset existing VM security state")
		}
		if e = wasmsecure.WriteExclusive(out, b, 0600); e != nil {
			return e
		}
		if e = wasmsecure.ProtectedPath(out, false); e != nil {
			return e
		}
		_, e = fmt.Fprintf(c.OutOrStdout(), "Created protected policy %s and rollback state %s\n", out, statePath)
		return e
	}}
	c.Flags().StringVar(&algorithms, "algorithms", "ES256", "comma-separated exact allowed algorithm names (no aliases or duplicates)")
	c.Flags().StringVar(&out, "output", "", "absolute policy output path")
	c.Flags().StringVar(&root, "trust-root", "", "absolute locally trusted CA PEM path")
	c.Flags().StringVar(&state, "state-dir", "", "absolute protected VM state directory")
	c.Flags().StringVar(&cert, "certificate", "", "absolute leaf certificate PEM path to authorize")
	c.Flags().StringArrayVar(&additionalCertificates, "additional-certificate", nil, "additional protected leaf certificate path; repeat for distinct authorized signers (at most eight total)")
	c.Flags().Uint64Var(&signatureThreshold, "signature-threshold", 1, "required number of distinct valid authorized public keys")
	c.Flags().StringVar(&id, "module-id", "", "authorized module ID")
	c.Flags().Uint64Var(&version, "policy-version", 1, "policy version")
	c.Flags().Uint64Var(&minVersion, "minimum-version", 1, "minimum module version")
	c.Flags().Uint64Var(&minEpoch, "minimum-epoch", 0, "minimum security epoch")
	c.Flags().Uint64Var(&capabilities, "capabilities", 0, "allowed capability mask")
	c.Flags().Uint64Var(&maxAge, "max-crl-age-seconds", 86400, "maximum age of authenticated CRLs")
	c.Flags().Uint64Var(&maxSize, "max-module-bytes", 104857600, "maximum exact module size")
	for _, n := range []string{"output", "trust-root", "state-dir", "certificate", "module-id"} {
		_ = c.MarkFlagRequired(n)
	}
	return c
}

func policyUpdateCommand() *cobra.Command {
	var policy, root, cert, id, algorithms string
	var additionalCertificates []string
	var signatureThreshold uint64
	var clearAdditional bool
	var version, minVersion, minEpoch, capabilities, maxAge, maxSize uint64
	c := &cobra.Command{Use: "policy-update", Short: "Atomically update a protected policy as its local administrator, preserving VM state", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
		p, old, _, e := loadPolicy(policy)
		if e != nil {
			return e
		}
		if version <= p.Version {
			return errors.New("POL_002: administrator policy updates require a strictly increasing version")
		}
		p.Version = version
		if c.Flags().Changed("trust-root") {
			if e = wasmsecure.ProtectedPath(root, false); e != nil {
				return e
			}
			rb, e := wasmsecure.ReadBounded(root, wasmsecure.MaxEvidenceBytes)
			if e != nil {
				return e
			}
			if _, e = wasmsecure.Certificates(rb); e != nil {
				return e
			}
			p.TrustRoot = root
		}
		if c.Flags().Changed("max-crl-age-seconds") {
			p.MaxCRLAgeSeconds = maxAge
		}
		if c.Flags().Changed("max-module-bytes") {
			p.MaxModuleBytes = maxSize
		}
		if id != "" {
			r, exists := p.Modules[id]
			if !exists {
				r = wasmsecure.ModuleRule{ID: id, ABI: "uwvm2", MinVersion: 1}
				if cert == "" {
					return errors.New("new module rules require --certificate")
				}
			}
			if cert != "" {
				cb, e := wasmsecure.ReadBounded(cert, wasmsecure.MaxEvidenceBytes)
				if e != nil {
					return e
				}
				certs, e := wasmsecure.Certificates(cb)
				if e != nil {
					return e
				}
				r.SPKI = wasmsecure.SPKIDigest(certs[0].RawSubjectPublicKeyInfo)
			}
			if clearAdditional && c.Flags().Changed("additional-certificate") {
				return errors.New("cannot clear and replace additional signers together")
			}
			if clearAdditional {
				r.AdditionalSPKIs = nil
			}
			if c.Flags().Changed("additional-certificate") {
				r.AdditionalSPKIs, e = additionalSignerPins(additionalCertificates)
				if e != nil {
					return e
				}
			}
			if c.Flags().Changed("signature-threshold") {
				r.SignatureThreshold = signatureThreshold
			}
			if c.Flags().Changed("minimum-version") {
				r.MinVersion = minVersion
			}
			if c.Flags().Changed("minimum-epoch") {
				r.MinEpoch = minEpoch
			}
			if c.Flags().Changed("capabilities") {
				r.AllowedCapabilities = capabilities
			}
			if c.Flags().Changed("algorithms") {
				r.Algorithms, e = wasmsecure.ParseAlgorithms(algorithms)
				if e != nil {
					return e
				}
			}
			p.Modules[id] = r
		} else if c.Flags().Changed("algorithms") || cert != "" || c.Flags().Changed("minimum-version") || c.Flags().Changed("minimum-epoch") || c.Flags().Changed("capabilities") || c.Flags().Changed("additional-certificate") || c.Flags().Changed("signature-threshold") || clearAdditional {
			return errors.New("module rule changes require --module-id")
		}
		b, e := p.Marshal()
		if e != nil {
			return e
		}
		roots, e := wasmsecure.ReadBounded(p.TrustRoot, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return e
		}
		if e = wasmsecure.CheckCurrentState(b, roots, p, wasmsecure.Manifest{}, time.Now()); e != nil {
			return e
		}
		// Detect another completed administrator update before publishing this one.
		latest, e := wasmsecure.ReadBounded(policy, wasmsecure.MaxSignatureBytes)
		if e != nil {
			return e
		}
		if string(latest) != string(old) {
			return errors.New("policy changed during administrator update; retry with the new version")
		}
		if e = wasmsecure.ReplaceProtected(policy, b); e != nil {
			return e
		}
		_, e = fmt.Fprintf(c.OutOrStdout(), "Updated protected policy %s to version %d; preserved VM state\n", policy, p.Version)
		return e
	}}
	c.Flags().StringVar(&algorithms, "algorithms", "ES256", "replace this module's exact allowed algorithm set (requires --module-id)")
	c.Flags().StringVar(&policy, "policy", "", "existing protected policy path")
	c.Flags().Uint64Var(&version, "policy-version", 0, "strictly increasing administrator policy version")
	c.Flags().StringVar(&root, "trust-root", "", "explicit new locally provisioned trust root PEM path")
	c.Flags().StringVar(&cert, "certificate", "", "PEM leaf certificate to authorize for this module")
	c.Flags().StringArrayVar(&additionalCertificates, "additional-certificate", nil, "replace the additional signer certificate set; repeat for distinct keys")
	c.Flags().Uint64Var(&signatureThreshold, "signature-threshold", 1, "explicitly replace this module's required number of distinct valid signers")
	c.Flags().BoolVar(&clearAdditional, "clear-additional-signers", false, "explicitly remove additional signer pins; a compatible threshold must also be supplied")
	c.Flags().StringVar(&id, "module-id", "", "module rule to add or update")
	c.Flags().Uint64Var(&minVersion, "minimum-version", 1, "minimum module version")
	c.Flags().Uint64Var(&minEpoch, "minimum-epoch", 0, "minimum module security epoch")
	c.Flags().Uint64Var(&capabilities, "capabilities", 0, "allowed module capability mask")
	c.Flags().Uint64Var(&maxAge, "max-crl-age-seconds", 86400, "maximum CRL age")
	c.Flags().Uint64Var(&maxSize, "max-module-bytes", 104857600, "maximum exact module size")
	_ = c.MarkFlagRequired("policy")
	_ = c.MarkFlagRequired("policy-version")
	return c
}

func additionalSignerPins(paths []string) ([]string, error) {
	if len(paths) >= wasmsecure.MaxSignatures {
		return nil, errors.New("POL_002: too many additional signers")
	}
	var pins []string
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return nil, errors.New("certificate paths must be clean absolute paths")
		}
		if e := wasmsecure.ProtectedPath(path, false); e != nil {
			return nil, e
		}
		b, e := wasmsecure.ReadBounded(path, wasmsecure.MaxEvidenceBytes)
		if e != nil {
			return nil, e
		}
		certs, e := wasmsecure.Certificates(b)
		if e != nil {
			return nil, e
		}
		pins = append(pins, wasmsecure.SPKIDigest(certs[0].RawSubjectPublicKeyInfo))
	}
	return pins, nil
}
