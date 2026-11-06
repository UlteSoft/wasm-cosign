# Embedded WSEA v2 qualification

The default product now uses the shared native UWVM core. Build with CGO and
a matching bundled OpenSSL 3.5.9 toolchain; see [build requirements](../../doc/wsea-build.md).
The cross-target driver now requires explicit `--native-toolchains`; there is no pure-Go fallback.
Local qualification uses the project's ignored `.tmp` directory when explicitly authorized.

Run candidate builds and tests only inside the authorized 64 GiB, zero-swap Linux cgroup,
with bounded process ownership, memory, temporary storage and execution time.

The portable SDK is described in [wasm/README.md](../../wasm/README.md).
`wasm_interop.py` runs the full shared corpus in Wasmtime, Node.js and UWVM;
`wasm_signing.py` exercises all profiles in both signing directions, eight-key
quorums and real secure execution; `wasm_host_security.py` checks protected file
paths, concurrent policy replacement and CSPRNG failure with real WASM.
Keep all generated fixtures, keys, logs and reports under `.tmp`; they are never
release inputs. Native and WASM code paths share the frozen WSEA wire profile.

```sh
make bundled-openssl
export PKG_CONFIG_PATH="$PWD/.wsea-build/openssl/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"
export PKG_CONFIG_SYSROOT_DIR=
export CGO_CPPFLAGS="$(cat .wsea-build/openssl/cgo-cppflags)"
go test ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure
go test ./pkg/wasmsecure -run=^$ -fuzz=FuzzEmbeddedSectionParser -fuzztime=30s -parallel=1
go build -o /private/build/cosign ./cmd/cosign
/private/build/cosign wasm secure --help
```

The WASM-only product registers the production command as `cosign wasm secure`. The
small `cli_main.go` entry point invokes the same Cobra command directly and is
also available for focused command tests with the same native backend.
Reports distinguish that executable from the complete cosign executable.

The current sign/verify/fetch commands consume one WASM with a final
`uwvm.wsea.v2` custom section. Signing authenticates every original prefix byte;
the COSE manifest uses the `uwvm-wsea-v2` domain. The embedded certificate and CRL
signatures are independently verified against protected local roots and policy.
The VM receipt additionally hashes the complete final image. Detached-v1 files,
old `interop.py`, and earlier result directories are historical migration
artifacts and do not qualify the current format.

`algorithm_interop.py` imports the explicitly supplied current UWVM matrix
driver and frozen embedded-v2 fixtures. It checks all thirteen OpenSSL-produced
algorithms in Go, then uses the production Go command to sign genuine guests
and submits them to the real target C++ verifier and guest-executing VM. Forged
or changed guests must be rejected without reaching their fd_write marker.
RSA4096/8192, strict RSA-PSS, curve/scalar bounds, canonical pure Ed25519,
certificate/CRL profiles and embedded-container rejection are independently
covered by the matrix. Weak and unsupported profiles are deliberate refusals.

Go state checks remain read-only. In cross-layer rollback and revocation groups,
the actual target explicitly commits policy transitions or learns authenticated
revocation before later Go replay checks. Each run has new private state; no
previous floor or tombstone is reset to obtain a passing result.

Use `--go-subcommands-json '["wasm","secure"]'` for the full CLI; direct secure
entry points use the default empty subcommand list. A cross-built static Go
entry point can use `--go-exec-prefix-json` with the actual target QEMU. The
report records both executable hashes and ELF identities, argv, runtime/loader
hashes, guest witnesses, exact expected exit codes, fixture/driver hashes and
cgroup identity/OOM evidence. A signal, timeout or unavailable producer cannot
pass as a negative result. Native Go production is not labeled target-QEMU
execution. Go lacks Linux big-endian ARM ports; host-Go-to-big-endian-VM
interoperability is reported separately.

`embedded_usage.py` in the UWVM repository runs real private HTTPS download
simulation, first-gate refusal without publication, direct-download bypass and
VM second-gate refusal, post-verification mutation and startup measurements.
TLS uses a disposable CA scoped to child environment variables, without system
trust changes. `TestFetchHTTPSAuthenticatedTLS` also checks authenticated TLS,
redirects, declared/streamed bounds, plaintext downgrade, loops and status/body
validation through the production downloader.


`run_go_targets.py --full-cosign` builds the complete static `./cmd/cosign`
executable, including the real `cosign wasm secure` registration, for each
supported target. It runs the same interoperability and private HTTPS suites
through the actual target QEMU and connects them to the matching UWVM verifier
and guest-executing VM. The default mode instead builds the small entry point;
reports state which executable was qualified. `--cohort` selects an immutable
UWVM code snapshot, while `--workspace` retains providers, fixtures and results.
`--cg-limit-mib` sets an early-stop ceiling within the existing authorized cgroup;
it does not change that cgroup. Optional `--dependency-proxy` uses HTTPS CONNECT
for Go module downloads with checksum verification enabled. It does not affect
WSEA roots, private HTTPS test trust, or VM network behavior.

Generated reports and evidence archives belong in a separate qualification
workspace. They are not committed to this repository; `results/` and generated
source checksum inventories are ignored. Continued campaigns retain resource
stops as failed attempts in that external workspace. Only complete target rows
with matching sources/binaries, 482 interoperability checks, 42 HTTPS checks and
closed successful build/execution guards can contribute to the final result.
The UWVM `startup_sizes.py` suite additionally exercises native 1/16/64 MiB
modules, then changes their last authenticated prefix byte and requires both
the complete cosign command and VM to refuse them.

The separate UWVM `backend_disabled.py` suite exercises complete x86_64 VMs
without OpenSSL/WSEA. The consumer keeps its explicit `--secure` selection:
an unavailable backend reports `SIG_005` and refuses before guest entry.
Ordinary execution remains available
when explicitly chosen. Supplemental reports are retained in the external qualification workspace.

The clock-commit/TLS supplement in the external qualification workspace
records rebuilt full static Go executable hashes and actual target Go
interoperability/HTTPS tests against the updated TLS-enabled VM products.
The VM samples the clock under its state lock and checks authenticated expiry.
Production Go commands use `CheckCurrentState` to observe the actual clock after
reading state, while `CheckState` retains its explicit-time API for deterministic
evaluation. Both reject a real protected future floor without clamping or grace.
The existing single-signature encoding remains compatible. A bounded new list
encoding in the same custom section supports two through eight contributions.
`multisig_test.go` covers all thirteen algorithms, maximum distinct-key quorums,
forgeries, duplicate votes and policy parsing. `policy-init`/`policy-update`
accept repeated `--additional-certificate` and `--signature-threshold` flags;
`sign --append-signature` authenticates and retains existing contributions.
`--allow-partial` reports `SIGNED_PARTIAL` during signing only. Verify and fetch
always require the protected quorum; every present contribution must be valid.
The VM `multisig_usage.py` suite adds 461 genuine CLI/guest/network checks per
qualified product or actual target-Go pair, including RSA4096/8192 and eight keys.
