# WSEA Studio user guide

[简体中文](README.zh_CN.md) · [Documentation index](README.md)

WSEA Studio is a local Chinese and English interface for wasm-cosign. It provides WASM signing, verification, multisignatures, HTTPS retrieval and policy management.

## Start the interface

You need Python 3.10+ and an existing native wasm-cosign WSEA v2 executable. Python uses only the standard library; no additional packages are required. The interface does not compile or download the program.

From the repository root:

```sh
python3 webgui/server.py \
  --binary /home/you/tools/cosign \
  --browse-root /home/you/releases
```

Open the complete session link printed in the terminal, or paste the startup token into the connection page. The address is fixed to `127.0.0.1`; use the printed address rather than substituting `localhost`. After refreshing the page, use the session link again. Press `Ctrl+C` to stop the server.

Use `EN / 中` in the upper right to switch languages without losing form values. Original command output is retained verbatim so error codes remain searchable.

| Option | Default | Purpose |
| --- | --- | --- |
| `--binary PATH` | Required | Existing native executable path; command strings and runtime wrappers are not accepted |
| `--port N` | `8765` | Loopback port; `0` chooses an available port |
| `--browse-root PATH` | Current directory | File-picker root; repeat to allow multiple roots |
| `--timeout SECONDS` | `120` | Per-operation deadline, from 1 to 3600 seconds |

Operation forms use clean absolute paths without `.` or `..` components. Folder buttons select existing files or enter new output names. `--browse-root` limits browsing in the picker only; other absolute paths can be entered directly.

The service performs operations with the starting user's permissions, which must allow the requested file access. The session link authorizes local operations; do not share it or forward the service port externally.

## Features

| Page | Function | Command |
| --- | --- | --- |
| Sign workspace | Create, append or replace signatures; save intermediate multisignatures | `wasm secure sign` |
| Verify module | Fully check module bytes, certificates, CRLs, quorum and local state | `wasm secure verify` |
| Secure fetch | Retrieve a module over HTTPS and save a new file after verification | `wasm secure fetch` |
| Create policy | Configure trust roots, signers, thresholds and initial state | `wasm secure policy-init` |
| Update policy | Update rules, versions, key authorization and resource limits | `wasm secure policy-update` |
| Session activity | Review the latest 20 operations and results in the server session | — |
| Help & environment | Command help, version, executable path and configuration | `--help`, `version` |

## Signing

### Files and identity

| Field | CLI argument | Requirement |
| --- | --- | --- |
| WASM module | `<module>` | Required existing module |
| Trust policy | `--policy` | Required existing protected policy |
| Output file | `--output` | New file; omitted for in-place signing |
| Private key file | `--key` | Required PEM key matching the algorithm |
| Signer certificate chain | `--certificate` | Required PEM bundle: leaf first, then intermediates |
| CRL evidence bundle | `--crl` | Required complete, valid CRL bundle |
| Signature algorithm | `--algorithm` | Default `ES256`; must be allowed by policy |

Private keys must not be group/other-accessible. Policies, trust roots, state files and parent directories must satisfy the program's protected-path rules. Prepare keys, certificates and CRLs before signing.

| Family | Algorithms |
| --- | --- |
| ECDSA | `ES256`, `ESP256`, `ES384`, `ESP384`, `ES512`, `ESP512` |
| EdDSA | `Ed25519` |
| RSA-PSS | `PS256`, `PS384`, `PS512` |
| RSA PKCS#1 v1.5 | `RS256`, `RS384`, `RS512` |

### Manifest

| Field | CLI argument | Format / initial value |
| --- | --- | --- |
| Module ID | `--module-id` | Identity authorized by the policy |
| Module version | `--module-version` | Unsigned 64-bit integer; initially `1` |
| Security epoch | `--security-epoch` | Unsigned 64-bit integer; initially `0` |
| Capability mask | `--capabilities` | `0`–`63`; initially `0` |
| Valid from | `--not-before` | RFC3339; initially one minute before opening the page |
| Valid until | `--not-after` | RFC3339; initially 24 hours after opening the page |

`Z` denotes UTC. The end must be later than the start. Review timestamps if the page has been open for a long time. Versions and numeric values use complete decimal strings to retain unsigned 64-bit precision.

### Signing modes

- **New signature**: sign an unsigned module.
- **Append signature**: retain existing signatures and add a contribution with `--append-signature`. All manifest fields must match.
- **Replace signatures**: replace all existing signatures with `--replace-signature`.
- **Replace the input file in place**: atomically write back to the input. Otherwise, provide a new output path. New outputs never overwrite existing files.
- **Allow an intermediate signature below quorum**: use `--allow-partial` to save `SIGNED_PARTIAL` for further signing.

## Multisignature workflow

For a 3-of-3 policy using ECDSA, RSA and Ed25519:

1. Create a policy with a primary signer certificate, two additional certificates and the required trust roots. Allow `ES256,RS256,Ed25519` and set the threshold to `3`.
2. Enter the original module, shared manifest and first signer's material. Enable intermediate output and save a new file.
3. The result shows “Partial signature · quorum incomplete.” Click “Append another signature”: the module and manifest are retained, while key, certificate, CRL and output fields are cleared.
4. Select the second signer's material, keep intermediate output enabled and sign again.
5. Append the third signer with intermediate output disabled to require the complete quorum.
6. Click “Open full verification” for an independent verification operation.

At most eight signature contributions are supported. The threshold counts **distinct authorized public-key SPKIs**; re-signing with the same key does not increase the distinct signer count. Results show distinct SPKIs separately from contribution algorithms.

`SIGNED_PARTIAL` cannot pass full verification or secure fetch. Existing signatures must also remain valid when appending.

## Create and update policies

| Field | CLI argument | Initialization / update |
| --- | --- | --- |
| New policy file | `--output` | Required for initialization; new file |
| Existing policy | `--policy` | Required for updates |
| Trust root | `--trust-root` | Required initially; trusted CA PEM |
| Rollback state directory | `--state-dir` | Initialization only; existing state is never reset |
| Authorized certificate | `--certificate` | Required initially or for a new module rule; the first PEM certificate is the authorized leaf |
| Additional signer certificates | Repeated `--additional-certificate` | One absolute path per line, up to seven; an update replaces the entire additional signer set |
| Clear additional signers | `--clear-additional-signers` | Update only; cannot also supply additional certificates |
| Signature threshold | `--signature-threshold` | Initially `1`; range 1–8, no greater than the number of distinct authorized keys |
| Module ID | `--module-id` | Required initially and when changing module rules |
| Allowed algorithms | `--algorithms` | Initially `ES256`; leaving all unchecked during update preserves the current set |
| Policy version | `--policy-version` | Initially `1`; required and strictly increasing on update |
| Minimum module version | `--minimum-version` | Initially `1` |
| Minimum security epoch | `--minimum-epoch` | Initially `0` |
| Capability mask | `--capabilities` | Initially `0`; range 0–63 |
| Maximum CRL age | `--max-crl-age-seconds` | Initially `86400` seconds |
| Maximum module size | `--max-module-bytes` | Initially `104857600` bytes, including signatures |

Optional update fields **remain unchanged when blank**. Entering `0` is an explicit change. Selecting algorithms or supplying additional certificates replaces their sets, rather than adding to them. When clearing signers, also provide a compatible threshold. Policy updates preserve existing state.

Raising a minimum version or epoch rejects older modules. Rotate keys by updating the authorized certificates.

Initialization can create state files or directories before a later step fails. Inspect the result before retrying; do not reset existing security state.

## Verification and HTTPS retrieval

**Verify module** requires a module and policy. Success requires all signature checks and the policy threshold to pass.

**Secure fetch** requires the complete module's HTTPS URL, a policy and a new output path. URLs cannot include credentials or fragments. The file is saved only after TLS and full WSEA verification succeed; existing outputs are not overwritten. HTTPS TLS trust comes from the executable's environment, while WSEA signing trust comes from the selected policy.

## Results and activity

| Status | Meaning |
| --- | --- |
| Full verification passed | `VERIFIED` with native exit code 0 |
| Partial signature | `SIGNED_PARTIAL`; additional signatures are required |
| Operation completed | A policy, help or version command completed |
| Operation did not pass | Nonzero exit or unexpected result format; inspect the original output and error code |
| Interrupted | Timeout, server shutdown or output limit; inspect actual file state before deciding to retry |

One command runs at a time. You can preview the actual command, expand raw output and the full manifest, and copy results. Activity keeps the latest 20 entries until server restart. Command output is limited to 1 MiB. Operations are not retried automatically.

## Development checks

Tests are in `webgui/tests/`. Scratch data and reports are written only under the project's `.tmp/`.

- `test_server.py`: arguments, session authentication, request boundaries, process deadlines and output limits.
- `integration.py --binary PATH`: all commands, 13 algorithms, multisignatures and HTTPS with an existing binary; requires local `openssl`.

Example using a Linux cgroup with 64 GiB memory and zero swap:

```sh
mkdir -p .tmp/webgui
systemd-run --user --wait --pipe --collect \
  --property=MemoryMax=64G --property=MemorySwapMax=0 \
  --property=TasksMax=512 --property=CPUQuota=200% \
  --working-directory="$PWD" \
  /usr/bin/env PYTHONDONTWRITEBYTECODE=1 TMPDIR="$PWD/.tmp/webgui" \
  python3 webgui/tests/integration.py \
  --binary /absolute/path/to/cosign --require-cgroup
```

For boundary tests, use the same cgroup command, replacing the last two lines with `python3 webgui/tests/test_server.py`. Integration reports are saved in a new `.tmp/webgui/integration-*/report.json`. Rerun tests after upgrading the binary; help-coverage checks detect new options not covered by the GUI.
