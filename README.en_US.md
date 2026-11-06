# wasm-cosign: WebAssembly signing with WSEA v2

[简体中文](README.zh_CN.md) | English

wasm-cosign signs and verifies **WebAssembly modules only**. Its native command,
WASIp1 SDK and JavaScript SDK use the frozen `uwvm.wsea.v2` signature container
accepted by uwvm2-ros. HTTPS downloads, TLS authentication, certificate chains,
CRLs and protected local policy administration support that purpose.

The legacy custom section named `wasm-cosign` is **deprecated**. This describes
the old signature container, not the project name. Renaming a section does not
convert a signature. New signatures must use `cosign wasm secure` or the WSEA SDK.
OCI/container signing, arbitrary-blob signing and upstream keyless commands are
excluded from the production dependency graph.

## Documentation

The following guides are maintained in complete `en_US` and `zh_CN` pairs. The
language-neutral files are navigation pages, not an additional document version.

1. [Security and interoperability](doc/wasm-secure-execution.en_US.md): exact
   algorithms, trust boundary, multi-signatures, revocation and rollback.
2. [Native command reference and deployment](doc/wsea-cli.en_US.md): bootstrap,
   signing, verification, HTTPS fetch, key rotation and actual VM authorization.
3. [WASIp1 and JavaScript SDK](wasm/README.en_US.md): protected-file adapter,
   Worker integration, JSON protocol, integer precision and resource limits.
4. [Build and dependency requirements](doc/wsea-build.en_US.md): pinned OpenSSL,
   paired UWVM revision, native/cross builds and portable WASM builds.
5. [Testing and qualification](doc/wsea-testing.en_US.md): local 64 GiB cgroup,
   runtime matrix, failure cases and release evidence.
6. [CI/CD and releases](doc/wsea-release.en_US.md): pull-request checks, tag
   publication, packaging allowlists, checksums, reruns and maintenance.

## Choose a distribution

Get archives and `SHA256SUMS` from
[GitHub Releases](https://github.com/UlteSoft/wasm-cosign/releases). Choose by the
actual host and architecture; a target omitted from a release is not qualified
by that release. Older release assets remain available at their own tags.

- **Native `cosign`**: operator CLI on a supported POSIX target. It manages policy
  and supports authenticated HTTPS module downloads.
- **`wasm32-wasip1`**: two core WASM modules, for Wasmtime or a compatible UWVM
  preloader. Only WASI Preview 1 is used; Preview 2 is not produced.
- **`wasm32-js`**: Go frontend, the same crypto reactor, Go support script and ES
  module loader for Node.js or a browser Worker. A browser application must
  provide trusted policy/state provisioning and secure randomness.

The WASM modules pass MVP instruction validation and run on WebAssembly 2.0
engines. The JavaScript host additionally requires BigInt integration and modern
Web APIs; MVP bytecode compatibility alone does not qualify an old browser.

After downloading, verify the archives before extraction:

```sh
sha256sum -c SHA256SUMS
# On macOS: shasum -a 256 -c SHA256SUMS
```

A checksum obtained from the same release detects corrupted or mixed downloads;
it is not an independent publisher signature. `RELEASE.json` in a WASM archive
binds its source revision, shared-verifier revision and packaged file digests.
Read the release notes for the exact targets and checks that ran.

## First deployment

Prepare a private, administrator-controlled directory containing an independently
trusted CA, signer certificate, protected signer key and fresh complete CRLs.
Do not use generated test keys as production trust. Follow the
[command guide](doc/wsea-cli.en_US.md) to initialize policy and state before signing.

```sh
./cosign version
./cosign wasm secure --help
./cosign wasm secure verify release.wasm --policy /protected/policy
uwvm2-ros --secure module /absolute/release.wasm /protected/policy \
  --run /absolute/release.wasm
```

Verification by cosign is a deployment check. It does not authorize a future VM
execution. UWVM's second gate is selected explicitly for each module using
`--secure`; the embedded verifier remains offline and checks again near execution.
Ordinary execution without that selection does not imply a signature check.

## Security contract

All 13 exact profiles are supported: `ES256`, `ESP256`, `ES384`, `ESP384`, `ES512`,
`ESP512`, `Ed25519`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`.
A bundle may carry one through eight signatures. Every present contribution must
verify, and the policy quorum counts distinct authorized public keys. Pure
Ed25519 is supported; Ed25519ph/ctx and Ed448 are not.

The shared UWVM verifier header, pinned OpenSSL source and algorithm IDs are
checked during builds. Matching source does not eliminate the need to test the
actual target. Browser and WASI memory-only results authenticate a supplied
snapshot; trusted storage, revocation completeness and clock freshness remain
host responsibilities. See the security and SDK guides before embedding the API.

## Develop and contribute

Build prerequisites and exact commands are in the
[build guide](doc/wsea-build.en_US.md). Run product tests, not upstream-wide
`go test ./...`, which compiles unrelated retained source. Keep generated keys,
fixtures, logs, compiler caches and temporary output under the ignored project
`.tmp`. Local Linux builds and tests run in the authorized 64 GiB zero-swap cgroup.
Do not weaken filesystem checks to accommodate a writable checkout.

When changing behavior, update both language versions together, add meaningful
regression coverage and preserve the frozen WSEA format. Run
`python3 scripts/check_wsea_docs.py` for document pairing and local-link checks.
Do not report private signing material in public issues. The project and bundled
components retain their respective licenses; see `LICENSE` and archive licenses.
