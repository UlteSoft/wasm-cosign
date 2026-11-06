# WSEA testing and qualification

[简体中文](wsea-testing.zh_CN.md) | [Documentation](../README.en_US.md)

## Scope and evidence

Qualification applies to the exact recorded source, compiler, crypto dependency,
runtime and archive bytes. A historical pass does not automatically qualify a
new compiler or ABI. Production tests cover only WSEA's WASM product graph;
retained upstream OCI/blob tests are not substituted for WSEA checks.
A crash, signal, timeout, missing producer or unavailable runtime is a failure,
not a successful negative verification result.

The native and WASM implementations use the same frozen WSEA container and
13 profiles. Independent OpenSSL-produced fixtures and the native UWVM verifier
provide cross-implementation checks. Both signing directions are exercised:
native cosign to WASM, and each WASM runtime to the other runtimes/native tools.
The real guest-executing UWVM CLI is required, not a loader-only mock.

## Local resource admission

Run local Linux tests in the authorized **64 GiB zero-swap cgroup**. The process
must actually belong to the admitted leaf, whose effective ancestor limit also
matches 68719476736 bytes. Record the leaf/boot identity and OOM counters before
and after testing. A changed cgroup or increased OOM counter invalidates the run.
Do not create a less constrained subprocess or adjust the limit to make a test pass.

Keep `TMPDIR`, `GOTMPDIR`, Go/Python caches, generated private keys, fixtures,
reports and logs in project `.tmp`, mode 0700 with umask 077. Bound compiler jobs,
process counts and timeouts. The CI driver additionally disables core dumps.
macOS hosted native tests are identified as such; they do not claim Linux cgroup
coverage. Release archives and tracked source exclude generated test material.

## Native tests and documentation checks

Inside the admitted environment:

```sh
bash scripts/test_wsea_native.sh
python3 scripts/check_wsea_docs.py
```

The native script builds the pinned OpenSSL source, checks the product packages,
runs race tests on Linux, and compares generated CLI help with `doc/wsea-cli`.
Unit tests exercise strict PKI/CRLs, algorithms, multi-signatures, malformed
containers, state/snapshot parity, authenticated HTTPS publication, JSON member
ambiguity and full-width counters. The document checker requires both locales,
matching section/example counts, closed fences and valid local links/anchors.
It detects structural drift; human review must still check translation accuracy.

For a focused parser campaign, use Go's existing fuzz target under the same
resource boundary, with a finite time limit and one worker. Do not interpret a
short fuzz run as exhaustive cryptographic verification.

```sh
go test ./pkg/wasmsecure -run='^$' -fuzz=FuzzEmbeddedSectionParser \
  -fuzztime=30s -parallel=1
```

The direct Go invocation requires the bundled-OpenSSL environment described in
the [build guide](wsea-build.en_US.md).

## Complete portable qualification

`ci_wsea.py` is the shared local/CI entry point. Provide the clean UWVM checkout
at `scripts/wsea_uwvm_revision.txt`, pinned tools and a new output directory.
Run the command from inside the admitted cgroup; the script does not silently
change its own resource boundary.

```sh
python3 scripts/ci_wsea.py --uwvm-root .tmp/uwvm --tools .tmp/tools \
  --work .tmp/qualification
```

`--fetch-tools` downloads/checks pinned tools into `.tmp/tools` first (safe
extraction requires Python 3.12+ or its data-filter backport). `--uwvm-cxx` may
name an explicit qualified LLVM 22.1.8 compiler. `--version v0.2.1` additionally
requires a committed clean product tree, creates the release archives, extracts
the exact allowed bytes and runs qualification against those extracted modules.
Do not reuse a completed work directory or mutate its receipts.

The driver builds native cosign, the full interpreter, the actual native verifier
and genuine Ed25519ph/ctx producer, then generates fresh fixtures. Its checks are:

- **277 corpus cases** in UWVM, Wasmtime, Node and the native verifier. This
  includes all 13 profiles, RSA3072/4096/8192, PSS parameters, EC scalars,
  canonical pure Ed25519 and real unsupported ph/ctx signatures, certificate/CRL
  failures, malformed/legacy containers, policy rollback and permanent revocation.
- **76 signing/interoperability checks**: every profile in all signing directions,
  an eight-key mixed-family quorum, rejected partial/duplicate votes, publisher
  rotation, version rollback, uint64 maximum and epochs above 2^53, real
  `--secure` execution and invalid-contribution refusal, all three file adapters.
- **13 host-security checks**: mutable paths, symlink/hardlink substitution,
  bad or absent state, incomplete revocation marker, ambient Node option injection,
  policy replacement during verification and failure of both signing and OpenSSL
  verification entropy sources.

The matrix preserves each group's learned policy/version/revocation history.
WASM snapshot checks happen before the native verifier commits the next step.
Do not reset a floor or erase a marker between related negative cases.

## Browser and additional targets

The JavaScript SDK is also suitable for a dedicated browser Worker. The v0.2.0
qualification included a real Firefox verification smoke test; this is narrower
than the complete Node matrix and is not a claim that every browser/profile was
tested. A web application's provisioning, storage, CSP, permissions and key
lifetime require their own integration tests. Test positive/negative responses,
worker termination and secure randomness in the application's actual environment.

Native cross-target campaigns use `test/wsea/run_go_targets.py` with explicit
`--native-toolchains`, matching target UWVM and actual QEMU execution. HTTPS
and multi-module suites exist in the paired UWVM security test directory.
Only targets whose real builds and tests succeed may be released; absent target
evidence is not replaced with another architecture's binary or a pure-Go build.

## Retention and interpreting failures

`.tmp/qualification` keeps per-stage logs, private fixtures and local JSON
results for diagnosis. Only the final allowlisted production archives are uploaded
by release jobs. Never upload the whole work directory, a dated test project,
private keys, browser profiles or compiler crash reproducers.

If a tool download or resource admission fails, fix that infrastructure and rerun
in a fresh work directory. If cryptographic results differ, stop publication,
compare exact source/tool/fixture identities and fix the cause in both products
where necessary. Updating an expected result or suppressing a failing test is not
qualification. Old release files remain immutable; a correction receives a new tag.
