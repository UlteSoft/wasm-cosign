# WSEA v2 security and interoperability

[简体中文](wasm-secure-execution.zh_CN.md) | [Documentation](../README.en_US.md)

The legacy `wasm-cosign` signature container is **deprecated**. Use the
`uwvm.wsea.v2` format described here for new signatures. These containers are
not interchangeable, and changing a custom-section name does not convert a
signature. The wasm-cosign tool and project name remain current.

`cosign wasm secure` signs, verifies and downloads one WASM containing a final
`uwvm.wsea.v2` custom section. The section holds one or up to eight contributions, each with canonical
COSE_Sign1, a signing certificate chain and complete issuer CRLs. Trust roots, signer pins, algorithm
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

## Multiple signers and publisher versions

A single signature retains its established encoding. Two through eight
contributions use the existing bounded list inside the same final WSEA section;
there is no second container type. All contributions authenticate identical
module identity, prefix digest, size, ABI, version, epoch, validity and capabilities.
Their permitted algorithms, certificates and keys may differ. Every contribution
must pass even if the threshold would be met without it. Invalid extra evidence
cannot be ignored to turn a rejected bundle into an accepted one.

The policy authorizes one primary SPKI and up to seven additional distinct SPKIs.
A threshold is a count of **different authorized public keys**, not signatures,
algorithm names, certificates or human-readable certificate subjects. Signing
twice with one key never supplies two votes. `--allow-partial` is restricted to
collecting signatures; it never permits verification, fetch or VM execution.

A publisher is authorized by the protected module rule and SPKI set, not by a
certificate's displayed organization name. Publish a higher `--module-version`
for a new release and increase `--security-epoch` for the intended security
transition. Policy floors and learned state both constrain acceptance. Reusing
a version with different authenticated content is not a safe release process.
To rotate keys, provision a strictly newer local policy authorizing the new key,
apply the intended threshold, distribute fresh evidence and retire old keys
through an authenticated policy/revocation procedure. Never delete state or
revocation markers to make an older release pass.

## Local storage and time

Policy and trust files must be controlled by root or the effective user, have no
symlink/hardlink substitution or group/other-write permissions, and reside under
protected ancestors. Root-owned sticky ancestors are permitted by the native
profile. State directories are private mode 0700; state files are mode 0600 and
owned by the effective user. The shared `.lock` serializes state-sensitive work.
Missing, malformed or rollback-inconsistent state is a refusal, not an invitation
to create a fresh floor. Policy initialization is an explicit administrator action.

A trustworthy system clock is required. A result expires at the earliest bound
from the signed manifest, certificates and CRLs. Native state checks also reject
clock rollback relative to a recorded floor. There is no hidden grace period,
network refresh in UWVM, or timestamp exception that bypasses expiry.

## Portable SDK boundary

The WASM SDK uses the same pinned verifier and profile. The cryptographic reactor
is intentionally single-threaded and has no host file or network access. It does
not turn a memory buffer into protected local storage. `VERIFIED_SNAPSHOT` means
the provided policy, roots, state and complete revocation list passed together
with the signed module at `checked_at`, up to exclusive `valid_until`.

The POSIX `run.py` adapter authenticates the files, holds the shared lock and
rechecks trust/state/expiry before reporting `VERIFIED`. A browser integrator
must establish equivalent trusted provisioning and freshness outside WASM. Neither
result is a VM execution receipt; only explicit UWVM `--secure` processing near
execution issues and consumes that receipt. The two gates serve different times
and do not replace each other.

## Failure handling and scope

Treat nonzero exit, `REJECTED`, malformed JSON, trap, timeout, missing runtime,
missing crypto backend and entropy failure as failure. Do not retry via the
legacy container, weaker algorithm, pure-Go PKI or a host crypto substitute.
Diagnostic families include `SIG_` (container/signature/backend), `CERT_`
(certificate, signer or revocation), `POL_` (policy, protected state, time or rollback). Read the full diagnostic before acting; refresh authentic evidence
or repair the trusted deployment configuration, rather than disable a check.

The threat model trusts the administrator, OS, clock, runtime and protected
storage. It does not claim to protect against an administrator who replaces the
trust root or malicious JavaScript that controls the whole SDK host. Resource
limits can make the portable SDK reject a size that the native tool accepts;
they never relax a signature acceptance rule. Testing establishes the recorded
coverage, not a proof that every possible bug is absent.

See the [native command guide](wsea-cli.en_US.md),
[portable SDK guide](../wasm/README.en_US.md) and
[UWVM execution contract](https://github.com/UlteSoft/uwvm2-ros/blob/d8ece7e3fc6471236905320849a968b8868ce8b8/documents/security/wsea.md).

