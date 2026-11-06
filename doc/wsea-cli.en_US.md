# Native commands and deployment

[简体中文](wsea-cli.zh_CN.md) | [Documentation](../README.en_US.md)

## Prerequisites and protected paths

Use the native `cosign` from a qualified release. The supported top-level
commands are `wasm secure` and `version`; `cosign --help` shows the actual surface.
All examples assume an administrator has provisioned `/protected` with mode
0700, an independently trusted `roots.pem`, code-signing leaf/intermediate PEM
bundles, complete current CRLs and private keys readable only by their owner.
Replace paths and identities with your deployment values. Never copy test CA
keys or the examples' identity into a production trust decision.

Policies and keys require absolute protected paths. Ancestors must not be
writable by other users; do not bypass this requirement with `chmod 777` or by
running an untrusted checkout as root. The state directory and files have
additional ownership/mode checks described in the [security guide](wasm-secure-execution.en_US.md).

## Initialize policy once

```sh
./cosign wasm secure policy-init \
  --output /protected/policy --state-dir /protected/state \
  --trust-root /protected/roots.pem --certificate /protected/signer-chain.pem \
  --module-id vendor.module --algorithms ES256,Ed25519,PS256 \
  --minimum-version 1 --minimum-epoch 0 --capabilities 0 \
  --policy-version 1 --max-module-bytes 33554432 --max-crl-age-seconds 86400
```

`policy-init` is an administrator bootstrap operation, not a normal verification
step. It creates the local trust policy and initial VM rollback state. Do not
repeat initialization to recover from a rollback refusal. `--certificate`
authorizes the leaf's SHA-256 SPKI, while `--trust-root` selects the independently
trusted CA bundle. A matching certificate name alone never grants authorization.

`--algorithms` is an exact, unique comma-separated allowlist; default `ES256`.
`--minimum-version` defaults to 1, `--minimum-epoch` and `--capabilities` to 0,
`--policy-version` to 1. Default bounds are 100 MiB per module and 86400 seconds
maximum CRL age. The portable SDK has a stricter 32 MiB module bound, so this
example chooses a limit usable by both. Capability masks contain only the known
six bits (0..63); request only capabilities the guest actually needs.

For multiple signers add `--additional-certificate /protected/second.pem`
(repeatable, at most eight distinct keys total) and `--signature-threshold 2`.
The threshold defaults to one and cannot exceed the authorized distinct-key count.

## Sign a release

Set RFC3339 UTC validity times for the actual release; the values below are
placeholders, not dates that should be used verbatim.

```sh
./cosign wasm secure sign unsigned.wasm \
  --policy /protected/policy --key /protected/signer.key \
  --certificate /protected/signer-chain.pem --crl /protected/complete-crls.pem \
  --module-id vendor.module --module-version 1 --security-epoch 0 \
  --algorithm ES256 --capabilities 0 \
  --not-before "$VALID_FROM_UTC" --not-after "$VALID_UNTIL_UTC" \
  --output /protected/release.wasm
```

The native CLI accepts protected PEM PKCS#8, PKCS#1 or EC private keys supported
by the selected profile. The certificate bundle is the leaf followed by
intermediates; the CRL bundle must cover every non-root certificate's issuer.
The key, certificate and policy-authorized signer must match. No key is embedded
in the output. The authenticated size and SHA-256 digest are calculated from
the actual WASM prefix, never caller-supplied metadata.

`--output` publishes a new file and refuses to clobber an existing destination.
Without it, the native CLI atomically replaces the input. Prefer explicit
`--output` when preserving the unsigned input matters. Existing embedded
signatures require explicit `--append-signature` or `--replace-signature`.
The SDK adapter always requires a new absolute output filename.

## Collect a multi-signature quorum

Initialize the intended signer set and threshold before collecting signatures.
Sign the first contribution with the same arguments as above plus
`--allow-partial`, writing `partial-1.wasm`. Then sign that file with the next
key/certificate/CRL, `--append-signature`, and unchanged module identity, version,
epoch, validity and capabilities. The next signer's allowed algorithm may differ.
Use a new output each time. Keep `--allow-partial` only while further contributions
are required; the final contribution should meet the protected quorum.

A partial operation explicitly reports `SIGNED_PARTIAL`. It is not deployable.
`verify`, `fetch` and UWVM enforce the threshold and reject every invalid present
contribution. A repeated key counts once, even under a second certificate or
algorithm label. The existing container supports at most eight contributions.
See [multi-signature rules](wasm-secure-execution.en_US.md#multiple-signers-and-publisher-versions).

## Verify, fetch and execute

```sh
./cosign wasm secure verify /protected/release.wasm --policy /protected/policy
./cosign wasm secure fetch /protected/downloaded.wasm \
  --policy /protected/policy --url https://publisher.example/release.wasm
uwvm2-ros --secure module /protected/release.wasm /protected/policy \
  --run /protected/release.wasm
```

`verify` reads current state and does not advance the VM's rollback floors.
`fetch` authenticates TLS, enforces bounded HTTPS responses and verifies the
complete WSEA module before atomic publication. TLS trust for transport is
separate from WSEA's local publisher trust. No downloaded certificate/policy
becomes trusted merely because HTTPS succeeded. UWVM's built-in gate does no
network access; all required evidence must already be available.

`--secure module <path> <policy>` selects a path. UWVM also supports
`--secure named-module <path> <policy> <expected-id>` for an explicitly selected module
identity. Repeat selections for all modules requiring authorization; do not
assume signing the entry module authorizes imported modules. The VM independently
verifies selected modules and rechecks its private receipt near initialization.
Do not carry a cosign success into execution after changing bytes or trust state.

## Update policy and rotate keys

Use `policy-update` with the same administrative trust/rule options as
`policy-init`, but a strictly higher `--policy-version`. Preserve the existing
state directory and learned rollback/revocation history. Plan a transition that
authorizes the new key before publishing a release signed by it; explicitly
choose whether the overlap requires one signer or a multi-key quorum.

For each module maintain increasing release versions and intended security
epochs. Policy minimums and stored floors both apply. An old vendor certificate
or identical organization name does not bypass either. Refresh expired CRLs and
certificates from authenticated sources. A permanent authenticated revocation
cannot be cleared by substituting an older CRL or deleting its marker.

## Diagnostics and automation

Use process exit status, not text matching a success-looking substring. Treat a
signal, timeout, missing backend or unavailable entropy as failure. `SIG_005`
can indicate an unsupported algorithm/backend; inspect the full message.
`CERT_` failures require examining the chain, authorization, validity and CRLs;
`POL_` failures require checking protected policy/state and the clock.
Never suppress a failure by lowering a threshold or resetting floors.

The generated command help is kept as an English, mechanically checked record
of exact flag spellings: [secure](wsea-cli/cosign_wasm_secure.md),
[policy-init](wsea-cli/cosign_wasm_secure_policy-init.md),
[policy-update](wsea-cli/cosign_wasm_secure_policy-update.md),
[sign](wsea-cli/cosign_wasm_secure_sign.md),
[verify](wsea-cli/cosign_wasm_secure_verify.md),
[fetch](wsea-cli/cosign_wasm_secure_fetch.md). The bilingual guide above explains
the same supported operations; flags are not translated.
