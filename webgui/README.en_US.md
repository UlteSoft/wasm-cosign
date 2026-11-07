# WSEA Studio — English guide

[简体中文](README.zh_CN.md) · [Documentation index](README.md)

A local Python interface for an existing native wasm-cosign executable. The main navigation contains **Sign**, **Verify** and **More tools**. More tools groups policy creation, policy updates and HTTPS retrieval. Chinese and English can be switched without clearing the form.

## Start

Requirements:

- Python 3.10 or newer and an existing native wasm-cosign WSEA v2 executable.
- A local graphical desktop. Linux uses `zenity` when installed; otherwise the helper uses Python `tkinter`. Windows and macOS use `tkinter` file dialogs. Install the platform's desktop package yourself if needed; the GUI never installs dependencies.
- A browser with JavaScript enabled. No frontend build, package manager, CDN or third-party web service is required.

```sh
python3 webgui/server.py --binary /absolute/path/to/cosign
```

Open the private session link printed in the terminal. The server binds only to `127.0.0.1`; default port is `8765`. `--port 0` chooses a free port. `--timeout 120` sets the native command deadline, with a range of 1–3600 seconds. Stop with Ctrl+C.

The executable is never compiled, downloaded or replaced. File dialogs open on the computer running Python, so run it in your desktop session rather than a headless remote shell. The selected executable must be trusted; the startup version check establishes compatibility, not executable authenticity.

The page removes the token from its URL and keeps it in memory. Refreshing the page requires the session link again. Forms and file names are not saved to browser storage. Keep the link private. Do not expose this local service through a proxy or port forwarding.

## Select local files

Click **Choose file** to open the system file dialog. The browser receives only the name you explicitly selected and a random, session-scoped identifier. Absolute paths, directory listings and private-key contents do not cross the HTTP API. Remove a selection with its × button or choose another file.

**Choose save location** opens a save dialog. Choose a new output filename. For a new state directory, enter the directory name and its parent location in that dialog; the native program creates it. The native program retains all its ownership, permission, symlink, exclusive-create and state checks.

The former web directory browser, manual path inputs, command preview, raw console output and environment page have been removed. `--browse-root` is no longer an option. File identifiers cannot be used interchangeably: a key selection cannot become an output file or policy. Output identifiers become readable module/policy identifiers only when explicitly starting a follow-up operation after success.

## Sign a module

1. Select the WASM module, trust policy, private key, certificate chain and CRL. Select a new output location. For deliberate in-place signing, open **Advanced options** in this first step and enable **Sign in place**.
2. Select **Next**. Enter the module ID and version, choose the algorithm and set the validity interval. Date controls are labeled UTC; the server receives RFC3339 timestamps. The 1, 7 and 30 day shortcuts reset both ends of the interval relative to now.
3. In the second step's **Advanced options**, choose append/replace mode, security epoch, capability mask or partial signing if needed.
4. Select **Sign file**. The result distinguishes complete verification from a signature that still needs additional signers.

Default mode creates a signature. **Replace all signatures** deliberately replaces all existing contributions. **Append signature** authenticates existing contributions and requires the same manifest. Choosing a new output never permits overwriting an existing file. In-place mode atomically writes back to the selected input.

| Field | CLI argument | Requirement |
| --- | --- | --- |
| WASM module | `<module>` | Required existing module |
| Trust policy | `--policy` | Required existing protected policy |
| Output file | `--output` | New file; omitted for in-place signing |
| Private key file | `--key` | Required PEM key matching the algorithm |
| Signer certificate chain | `--certificate` | Required PEM bundle: leaf first, then intermediates |
| CRL evidence bundle | `--crl` | Required complete, valid CRL bundle |
| Signature algorithm | `--algorithm` | Default `ES256`; must be allowed by policy |

| Field | CLI argument | Format / initial value |
| --- | --- | --- |
| Module ID | `--module-id` | Identity authorized by the policy |
| Module version | `--module-version` | Unsigned 64-bit integer; initially `1` |
| Security epoch | `--security-epoch` | Unsigned 64-bit integer; initially `0` |
| Capability mask | `--capabilities` | `0`–`63`; initially `0` |
| Valid from | `--not-before` | RFC3339; initially one minute before opening the page |
| Valid until | `--not-after` | RFC3339; initially 24 hours after opening the page |

Unsigned integers remain decimal strings through JavaScript and JSON, preserving the full uint64 range. Allowed algorithms are `ES256`, `ESP256`, `ES384`, `ESP384`, `ES512`, `ESP512`, `Ed25519`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`. The protected policy must authorize the chosen algorithm and signer.

## Collect multiple signatures

For a 3-of-3 policy with ECDSA, RSA and Ed25519:

1. Create the policy in **More tools**, select three authorized certificates, allow `ES256`, `RS256` and `Ed25519`, and set the threshold to `3`.
2. Sign with the first key and enable **Allow an intermediate multisignature file**. A partial result is not a full verification success.
3. Select **Add signature** in the result. The module, policy and manifest are retained. The private key, certificate, CRL and output selections are cleared.
4. Select the next signer's files and a new output, proceed to settings and choose its algorithm. Keep partial signing enabled until the last signature.
5. For the last signer, disable partial signing to require the complete threshold. Select **Verify this file** to run a separate full verification.

A maximum of eight contributions is supported. The threshold counts distinct authorized public keys, not signatures: signing twice with the same key does not increase the distinct signer count. Results show that count separately from contribution algorithms. Partial modules cannot pass full verification or HTTPS retrieval. Existing signatures and the shared manifest remain checked by the native executable.

## Verify or retrieve

**Verify** needs only a selected module and trust policy. A successful result means native verification, the signature threshold and security state checks passed.

**More tools → Fetch & verify** takes an HTTPS URL, policy and new output location. Credentials and fragments in URLs are rejected. TLS and full WSEA verification must both succeed before publishing the file. Existing outputs are not overwritten. TLS trust comes from the native executable's environment; signing trust comes from the selected policy. There is no option to disable these checks.

## Create or update a policy

Use **More tools → Create policy** or **Update policy**. Additional signer certificates and resource limits are under Advanced options.

| Field | CLI argument | Initialization / update |
| --- | --- | --- |
| New policy file | `--output` | Required for initialization; new file |
| Existing policy | `--policy` | Required for updates |
| Trust root | `--trust-root` | Required initially; trusted CA PEM |
| Rollback state directory | `--state-dir` | Initialization only; existing state is never reset |
| Authorized certificate | `--certificate` | Required initially or for a new module rule; the first PEM certificate is the authorized leaf |
| Additional signer certificates | Repeated `--additional-certificate` | Select files one at a time, up to seven; an update replaces the entire additional signer set |
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

During updates, blank optional fields keep their current values; `0` is an explicit change. Selecting algorithms replaces the allowed set. Supplying additional certificates replaces that set. Clearing signers cannot be combined with adding them and requires a compatible threshold. A module ID is required when changing a module rule. State is preserved.

A higher minimum version or epoch rejects older releases. Updating authorized certificates rotates signers. Native policy initialization may create state before a later error; inspect local files before retrying. The GUI never automatically retries a mutation or resets security state.

## Structured results and privacy

All API responses, including failures, are JSON. The GUI reads only validated, allowlisted fields and renders concise result cards. **Copy JSON result** copies the sanitized document, without local paths or execution details.

The current native WSEA CLI **does not have a `--format json` option**. Signing, verification and HTTPS retrieval already return JSON by default. The bridge parses that JSON strictly, rejects duplicate keys and malformed success results, and requires native exit code zero. Policy commands currently print text containing local paths; the bridge discards that text and emits `{"status":"COMPLETED"}` only after a successful exit. Native errors are reduced to known error codes or `OPERATION_FAILED`; the raw message is never returned. No unsupported flag is passed and no native source change is needed.

For example, a successful result document contains `status: VERIFIED` and a manifest with module ID, decimal-string version/epoch/capabilities/timestamps, signer count and contribution algorithms. Unknown native fields, SPKI lists, ABI metadata and diagnostic details are not forwarded. `SIGNED_PARTIAL` is a separate incomplete state. `INVALID_RESULT` means a success response could not be validated. `INTERRUPTED` means the final write state is uncertain: inspect locally before retrying.

One operation or file dialog is active at a time. A dialog times out after five minutes. Recent operations hold at most 20 sanitized results in memory until the server stops. The private server-side file map is limited to 512 selections per session. The service has no file download/upload, directory enumeration, command preview, raw-output or environment API. It uses exact Host/Origin checks, a per-startup bearer token, a restrictive CSP, no CORS and no HTTP request logging. Native stdout/stderr are bounded to 1 MiB and discarded after result conversion.

The isolation boundary is the web API: paths and command arguments necessarily exist in the Python/native processes on your computer. The application does not claim protection against a compromised OS or trusted executable. Selected basenames and public signing metadata are the intentional browser-visible data. The system file dialog itself shows local paths as part of the explicit local selection.

## Development verification

Keep all scratch data under the repository's `.tmp/`, with private permissions on the test directory and its parents. Tests never build the executable. Run them inside a 64 GiB, zero-swap cgroup, for example:

```sh
umask 077
mkdir -p .tmp/webgui
systemd-run --user --wait --pipe --collect \
  --property=MemoryMax=64G --property=MemorySwapMax=0 \
  --property=TasksMax=512 --property=CPUQuota=200% \
  --working-directory="$PWD" \
  /usr/bin/env PYTHONDONTWRITEBYTECODE=1 TMPDIR="$PWD/.tmp/webgui" \
  python3 webgui/tests/integration.py \
  --binary /absolute/path/to/cosign --require-cgroup
```

- `test_server.py`: argument boundaries, session authentication, file capability roles, removed endpoints, path/key/diagnostic non-disclosure, strict JSON, process limits and safe follow-up operations.
- `integration.py`: real native signing/verification for all 13 algorithms, mixed multisignatures, policy changes, permissions, tampering and TLS. Requires local OpenSSL. Reports and fresh test PKI go to a new `.tmp/webgui/integration-*` directory. Native help is read privately for command coverage and never sent to the page.
- `run_frontend.py --binary PATH --fixtures PATH --require-cgroup`: runs `test_frontend.js` against a disposable server using the integration fixtures. Requires Node.js. Exercises the real UI state/HTTP code, bilingual form state, file identifiers, the two-step flow and mixed 3-of-3 signing. Desktop selection and DOM objects are test substitutes; this does **not** verify native-dialog rendering, browser layout or keyboard behavior. Perform a separate browser check when browser access is available.

Use the same cgroup wrapper for each command. Test fixtures, session links, reports, logs and generated keys must never be committed or released.
