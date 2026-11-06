# WSEA WebAssembly SDK

[简体中文](README.zh_CN.md) | [Documentation](../README.en_US.md)

These ports sign and verify **WebAssembly modules only**, using the existing
`uwvm.wsea.v2` custom section. The WSEA payload, COSE IDs, X.509/CRL rules and
quorum interpretation are unchanged. The deprecated `wasm-cosign` container and
non-WASM signing interfaces are excluded.

The same `wsea-crypto.wasm` is included in both packages. It compiles the pinned
OpenSSL 3.5.9 source and the WSEA header shared with UWVM. Go implements the same
signing, module parsing, protected-policy and rollback rules as native cosign.
Verification never falls back to Go X.509, WebCrypto verification or a different
host OpenSSL. WebCrypto supplies secure randomness to the JavaScript host only.

Supported profiles are `ES256`, `ESP256`, `ES384`, `ESP384`, `ES512`, `ESP512`,
`Ed25519`, `PS256`, `PS384`, `PS512`, `RS256`, `RS384`, `RS512`. Up to eight
contributions are supported. Quorums count distinct authorized SPKIs; repeated
signatures by one key count once. Every present contribution must verify, and all
contributions must authenticate the same manifest. Pure Ed25519 is supported;
Ed25519ph and Ed25519ctx are rejected, as in UWVM.

## Targets

* **wasm-wasi:** `wasm-cosign-wasi.wasm` plus `wsea-crypto.wasm`, both core WASM
  modules using **WASI Preview 1**. Wasmtime's named preload or UWVM's module
  preloader links them. No Preview 2/component-model artifact is built or shipped.
* **wasm-js:** `wasm-cosign-js.wasm`, the identical crypto reactor, `wasm_exec.js`
  and `loader.mjs`. Node.js and browser JavaScript provide the host environment.

All three modules pass strict **MVP instruction-set validation** after lowering
Go's bulk-memory, sign-extension and nontrapping conversion operations. They also
run on WebAssembly 2.0 engines. No SIMD, threads, atomics, shared memory, reference
types, GC, exception-handling, multi-memory or memory64 proposal is required.
There are two separate instances, each with its own ordinary wasm32 memory.
JavaScript hosts additionally need modern WebAssembly BigInt integration,
`BigInt`, `TextEncoder`/`TextDecoder`, timers and a real WebCrypto CSPRNG. This is
not a claim of support for every browser that shipped the original 2017 MVP.

The browser interface is intended for a dedicated Worker in an HTTPS secure
context. Load one SDK per Worker. Terminate the Worker after a signing operation
if its private-key lifetime must end; JavaScript/Go strings cannot promise
complete erasure of every private-key copy. Enforce an application timeout and
memory budget. This SDK does not create a website, provision trust, or download
keys. HTTPS downloads and TLS validation can be performed by the trusted host's
`fetch` API, then supplied as bytes. Downloaded certificates never become local
trust anchors automatically.

## Protected local files

Use `run.py` (Python 3.10+ on POSIX) for operator-selected protected policy,
roots, rollback state and private keys. Select the package matching the runtime:

```sh
python3 run.py --runtime wasmtime verify module.wasm --policy /protected/policy
python3 run.py --runtime uwvm --engine /trusted/uwvm2-ros verify module.wasm --policy /protected/policy
python3 run.py --runtime node verify module.wasm --policy /protected/policy
```

The adapter resolves security paths through descriptors, rejects symlinks,
foreign owners, group/other writable ancestors and hard-linked security files,
requires state directory mode 0700 and state file mode 0600, and takes the same
`.lock` used by UWVM. It checks the complete protected revocation snapshot,
rechecks policy/roots/state and the earliest evidence expiry before returning.
A root-owned sticky directory may be an ancestor, as with native WSEA.

Signing uses the same protected policy and accepts PEM PKCS#8/PKCS#1/EC keys as
the native implementation. The output must be a **new absolute filename**;
existing files are never silently overwritten.

```sh
python3 run.py --runtime node sign unsigned.wasm \
  --policy /protected/policy --key /protected/signer.key \
  --certificate signer-chain.pem --crl fresh-crls.pem \
  --module-id vendor.module --algorithm Ed25519 --version 1 \
  --not-before "$VALID_FROM_UTC" --not-after "$VALID_UNTIL_UTC" \
  --output /protected/release.wasm
```

Supply validity times appropriate to the actual release. `--append-signature`
adds a contribution; `--replace-signature` explicitly replaces the existing
bundle. To collect a quorum across signers, use `--allow-partial` only during
signing. Such a result is labelled `SIGNED_PARTIAL` until the distinct-key
threshold is met. Ordinary verification and UWVM execution always require the
protected quorum. Signing metadata, including validity times, must match across
all contributions.

Policy/bootstrap administration remains a native cosign or administrator task.
The WASM ports never reset missing state, advance VM rollback floors or issue
an execution receipt. Like native `cosign wasm secure verify`, successful local
verification is a check; UWVM separately authorizes execution immediately before
running a selected module with `--secure`. The UWVM launcher explicitly grants
only the required Preview 1 clocks, CSPRNG, argument/empty-environment access,
standard I/O, readiness, monotonic timer and process-exit operations. It grants
no filesystem preopens, host environment inheritance or networking.

## Memory-only browser/Node interface

The trusted application supplies **independently authenticated** policy, roots,
current protected rollback state, and the complete permanent-revocation list.
These are never extracted from the signed module or chosen by an untrusted HTTP
request. WASI/browser storage cannot authenticate POSIX ownership on its own.
A server deployment must obtain this snapshot from its protected storage; a web
application must define an equally trusted provisioning and freshness mechanism.
If it cannot, it must not report trusted deployment authorization.

```js
// Run in a dedicated module Worker.
import './wasm_exec.js';
import {createWsea} from './loader.mjs';
const sdk = await createWsea({
  cryptoBytes: await (await fetch('./wsea-crypto.wasm')).arrayBuffer(),
  frontendBytes: await (await fetch('./wasm-cosign-js.wasm')).arrayBuffer(),
  go: new globalThis.Go(),
});
const responseJSON = sdk.requestJSON(trustedRequestJSON);
```

Use the `wasm_exec.js` shipped in the same archive, not a different Go version.
For Node.js, `node run-json.mjs /absolute/package < trusted-request.json` is the
low-level transport. For direct Wasmtime use:

```sh
wasmtime run --preload wsea_crypto=./wsea-crypto.wasm \
  ./wasm-cosign-wasi.wasm < trusted-request.json
```

The low-level transport accepts one UTF-8 JSON object. `--stream` processes
newline-delimited requests with one response per line; in stream mode expected
rejections are represented by `status`, not process exit. The host must inspect
every response. Default one-request mode exits nonzero on rejection.

The JSON transport schema is `wsea-sdk-1`; **it is not a new signature container**.
Binary fields use standard base64. All member names are exact, lowercase and
case-sensitive. Duplicate/unknown members, trailing JSON and invalid UTF-8 are
rejected. For verification:

```json
{
  "schema": "wsea-sdk-1",
  "operation": "verify",
  "module": "BASE64_WASM_BYTES",
  "trust": {
    "policy": "BASE64_PROTECTED_POLICY_BYTES",
    "roots": "BASE64_PROTECTED_ROOT_PEM",
    "state": "BASE64_CURRENT_PROTECTED_STATE_BYTES",
    "revoked_spkis": []
  }
}
```

`revoked_spkis` is mandatory, including an explicitly empty list. Omitting it
must never mean “assume no key is revoked”. State is never implicitly bootstrapped.
For signing, set `operation` to `sign` and add `signing` with `key`,
`certificates`, `crls` (base64 bytes), `manifest`, `append`, `replace`, and
`allow_partial`. Manifest fields are `embedded: true`, `algorithm`, `module_id`,
`version`, `security_epoch`, `not_before`, `not_after`, `abi: "uwvm2"` and
`capabilities`. Validity uses unsigned Unix seconds. Size and digest are computed
from the actual unsigned WASM prefix.

The response is `REJECTED` with an error, `SIGNED_PARTIAL`, or
`VERIFIED_SNAPSHOT` with authenticated `manifest`, `checked_at` and exclusive
`valid_until`. Signing also returns the resulting module as base64. The host
must recheck current protected trust/state, clock rollback and `valid_until`
immediately before using the result. `VERIFIED_SNAPSHOT` is never a UWVM
execution receipt. On runtime traps, entropy failure, missing imports or
malformed responses, reject the operation; there is no successful fallback.

Versions, epochs, capabilities and timestamps are uint64 integers. Preserve JSON
text or use a lossless integer-aware JSON library. Ordinary JavaScript
`JSON.parse`/`JSON.stringify` rounds integers above 2^53-1; do not use that round
trip for security counters. All three runtimes are tested at uint64 maximum.

Operational SDK bounds are 32 MiB for the whole module, 96 MiB for JSON transport,
64 KiB for policy/COSE, 4 MiB per PEM bundle, 1 MiB for state and 8192 revocation
pins. The protected policy can set stricter limits. These resource limits do not
relax any native WSEA acceptance rule; larger native deployment sizes are not
supported by this browser-oriented SDK. Ordinary native CLI HTTPS features are
unchanged; this portable entry point exposes only sign/verify.

## Build and qualification

The release uses Go 1.26.8, WASI SDK 34.0 (LLVM 23.1.0-wasi-sdk), Binaryen 133 and
unmodified vendored OpenSSL 3.5.9. Emscripten and third-party prebuilt OpenSSL
WASM libraries are not required. OpenSSL's existing `__wasi__` entropy path calls
`random_get`; no fixed seeds, RAND_status bypasses or host crypto substitutions
are used. The SDK's emulated process ID is only nonce personalization, not entropy.
Only `libcrypto.a` is built and linked; applications, libssl, engines, dynamic
providers, sockets and OpenSSL config loading are not in the crypto reactor.

Download the official archives and verify these SHA-256 digests before use:

* [WASI SDK 34.0 x86_64 Linux](https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz):
  `b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4`
* [Binaryen 133 x86_64 Linux](https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-linux.tar.gz):
  `2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489`

Run local Linux builds and qualification in a verified 64 GiB, zero-swap cgroup; keep
`TMPDIR`, `GOTMPDIR`, caches, keys and results inside the project's ignored `.tmp`.
Do not disable protected-path checks to accommodate a group-writable checkout.

```sh
python3 scripts/build_wsea_wasm.py --wasi-sdk /trusted/wasi-sdk-34.0 \
  --wasm-opt /trusted/binaryen-version_133/bin/wasm-opt \
  --uwvm-root ../uwvm2-ros --output .tmp/wsea-wasm
```

The builder checks the shared verifier, frozen algorithm IDs, source manifest,
compiler identity, OpenSSL archive/generated-header cache hashes, WASM dependency
surface and MVP validation. Requalify new toolchain versions explicitly.

Generate the existing UWVM `algorithm_matrix.py` corpus with its real OpenSSL
Ed25519ph/ctx producer, then run `test/wsea/wasm_interop.py` and
`test/wsea/wasm_signing.py --help` for the required arguments. The first driver
preserves grouped policy/rollback/revocation history and checks all 277 cases
against native UWVM and the selected WASM runtimes. The second signs all 13
profiles in all three runtimes, checks native cosign and UWVM acceptance,
eight-key mixed quorums, partial/duplicate-key rejection, rotation, rollback,
full-width counters and actual secure VM execution. Production source tests
also check native/snapshot state parity and ambiguous JSON rejection.

Release archives contain only the selected WASM modules, host adapters,
complete bilingual product documentation and licenses, with archive checksums. Toolchains, private keys,
fixtures, logs, test reports and build receipts are excluded.

After committing the reviewed source, use `scripts/package_wsea_wasm.py` with
`--artifacts .tmp/wsea-wasm/artifacts --output .tmp/release-assets`, the explicit
`--version`, and `--uwvm-root`. It checks source/artifact hashes against the build
receipt and packages an exact file allowlist. `RELEASE.json` records the two
committed verifier revisions and production file digests; it contains no test
inputs or results.

## Integration lifecycle and troubleshooting

Serve the archive's JavaScript and WASM files from your own authenticated origin;
check fetch response status before reading bytes. Use `application/wasm` for WASM
responses and a JavaScript MIME type for `.mjs`. The example uses `arrayBuffer`,
so streaming compilation MIME rules are not required for correctness. Configure
CSP to permit your own Worker and WebAssembly compilation without loading an
untrusted third-party script. No SharedArrayBuffer or cross-origin-isolation
requirement is introduced by these single-threaded modules.

Perform SDK initialization once per dedicated Worker, serialize requests and
terminate a worker that traps or times out. Do not reuse a trapped reactor. Both
WASM instances have independent memories; the loader copies bounded values and
does not hand one instance's pointers to the other. Treat an empty/malformed
response or unexpected status as rejection. Host application code must avoid
logging requests that contain private keys.

A browser cache or IndexedDB record is not independently trusted rollback
storage. If an attacker can choose roots, policy, state or JavaScript, valid
cryptography alone cannot establish the publisher you intended to authorize.
Define provisioning, freshness and compromise recovery before deploying a web
interface. TLS can authenticate a chosen server but cannot make arbitrary
server-provided keys authorized by your local WSEA policy.

If imports cannot be resolved, use the matching files from one archive and its
supported runtime; never add permissive file/network imports. If randomness is
unavailable, restore a real CSPRNG instead of substituting a deterministic seed.
If large inputs hit a resource limit, reject or choose a separately qualified
native deployment; changing a limit needs review and renewed testing.

The [native command guide](../doc/wsea-cli.en_US.md) explains bootstrap and
rotation. The [CI/CD guide](../doc/wsea-release.en_US.md) explains automated
builds and publication. No Emscripten runtime or downloaded third-party OpenSSL
WASM binary is required by this implementation.
