# Embedded WASM secure execution (WSEA v2)

The legacy `wasm-cosign` signature container is **deprecated**. Use the
`uwvm.wsea.v2` format described here for new signatures. These containers are
not interchangeable, and changing a custom-section name does not convert a
signature. The wasm-cosign tool and project name remain current.

`cosign wasm secure` signs, verifies and downloads one WASM containing a final
`uwvm.wsea.v2` custom section. The section holds canonical COSE_Sign1, a signing
certificate chain and complete issuer CRLs. Trust roots, signer pins, algorithm
allowlists, permissions and rollback storage remain independently provisioned.
Only explicit per-module UWVM `--secure` selection activates the second gate.

The manifest domain is `uwvm-wsea-v2`. It authenticates every original WASM byte
before the final seal. The seal cannot be duplicated or followed by any bytes.
Every other custom section is covered. The VM also binds the complete final
image in its private execution receipt. Existing detached-v1 library helpers are
retained for migration/tests; the secure CLI and embedded VM do not authorize v1
signatures or fall back to sidecars.

Use `policy-init` / increasing-version `policy-update` for protected local trust.
`sign input.wasm --policy ... --key ... --certificate ... --crl ... --module-id ...
--module-version ... --algorithm ... --not-before ... --not-after ...` embeds a
verified signature atomically. `--output` creates a new signed file;
`--replace-signature` explicitly replaces an existing final seal. `verify
signed.wasm --policy ...` checks embedded evidence and local rollback state.
`fetch new.wasm --policy ... --url https://server/signed.wasm` authenticates TLS,
downloads bounded bytes, verifies WSEA, then publishes without overwriting a file.
No network response may change trust roots, policy, signer pins or VM state.

The 13 exact profiles are ES256, ESP256, ES384, ESP384, ES512, ESP512, Ed25519,
PS256, PS384, PS512, RS256, RS384 and RS512. Six-field policies retain ES256 only;
additional profiles require explicit unique CSV `--algorithms`. RSA requires
3072–8192 bits/exponent 65537; PSS requires matching SHA-2/MGF1 and digest-sized
salt. EC uses exact P-256/P-384/P-521 curves and fixed-width low-S signatures.
Ed25519 is pure, with canonical public/R/S encodings and small-order rejection.
Generic EdDSA, Ed448, DSA, SHA-1/MD5 and restricted RSA-PSS SPKI are unsupported.

Certificate SPKI must be byte-aligned: RSA requires explicit NULL parameters,
EC requires a named curve and uncompressed point, and Ed25519 requires absent
parameters and 32 public-key bytes. PEM permits no nested armor, headers or
trailing DER. Inner/outer certificate and v2-CRL algorithms must agree. Code
signing purpose, complete path validation, certificate validity and authenticated
fresh CRLs are mandatory; any listed serial, including removeFromCRL, denies.
The VM remembers authenticated revocation permanently for a release key.
Historical timestamp exceptions and asynchronous revocation delivery are outside
this offline profile. A privileged administrator and trustworthy OS clock/storage
are part of the local trust boundary.

Go verification reads protected state; successful VM verification advances it.
The VM performs independent OpenSSL verification on every selected load. Its
initialization receipt rechecks the immutable complete image, current policy,
clock bounds and state without repeating the same load's PKI operations.

See UWVM `documents/security/wsea.md` for the complete wire, import-capability,
filesystem and execution contract. Actual fixtures, HTTPS simulation, startup
measurements and target evidence are retained separately from source preparation.
