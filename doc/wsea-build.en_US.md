# Building the WSEA product

[简体中文](wsea-build.zh_CN.md) | [Documentation](../README.en_US.md)

## Product boundary and prerequisites

The default native entry point is `./cmd/cosign`; the portable entry point is
`./cmd/wasmcosign`. Both sign/verify only embedded WSEA v2 WASM. Historical
Sigstore source remains in the repository, but OCI, containers, blobs, legacy
`wasm-cosign` sections and unrelated upstream commands are not compiled into
these products. Do not replace the product test list with `go test ./...`.

Native builds need Go 1.26.8 for release qualification, C/C++20 compilers,
Python 3.10+, Perl 5, make, ar, ranlib and pkg-config. The portable build pins
Go 1.26.8, WASI SDK 34.0 (LLVM 23.1.0-wasi-sdk) and Binaryen 133. CI additionally
builds a real UWVM interpreter using LLVM 22.1.8 and tests Wasmtime 42.0.1 and
Node.js 22.22.3. Pinned download URLs/digests live in `scripts/wsea_toolchains.json`.
A version change requires qualification, not just a successful compiler invocation.

## Work directories and resource protection

Use the project's ignored `.tmp` for **all** generated files: build trees,
toolchains downloaded for this task, caches, keys, fixtures, logs and reports.
Keep the checkout and its ancestors protected against group/other writes.
The following environment is useful inside an already admitted local Linux
64 GiB zero-swap cgroup; setting variables alone does not establish that cgroup.

```sh
umask 077
mkdir -p .tmp/work/tmp .tmp/work/go-cache .tmp/work/go-modules
export TMPDIR="$PWD/.tmp/work/tmp" GOTMPDIR="$PWD/.tmp/work/tmp"
export GOCACHE="$PWD/.tmp/work/go-cache" GOMAXPROCS=2 WSEA_OPENSSL_JOBS=3
export GOMODCACHE="$PWD/.tmp/work/go-modules"
export PYTHONDONTWRITEBYTECODE=1
export WSEA_OPENSSL_ROOT="$PWD/.tmp/work/openssl"
```

Validate actual process membership, effective `memory.max=68719476736`,
`memory.swap.max=0` and OOM counters. Run child commands inside the same cgroup,
with bounded jobs and timeouts. Do not increase a host limit or disable checks
when admission fails. CI provisions a disposable Linux systemd unit with the
same hard cap; macOS native jobs use isolated GitHub-hosted runners and are not
reported as Linux cgroup tests. See the [test guide](wsea-testing.en_US.md).

## Shared verifier and pinned OpenSSL

`internal/wseanative/wsea.h` is byte-identical to the paired UWVM
`src/uwvm2/utils/security/wsea.h`; `wsea.sha256` pins it. Go creates canonical
COSE and performs module/policy/state checks. Every signature contribution's
COSE/PKI validation uses the shared C++ implementation, with no Go X.509 fallback.
The exact 13 profile names and COSE IDs are checked against the Go table.

`third_party/openssl` contains the unmodified OpenSSL 3.5.9 source, license,
provenance and file manifest. `tools/dependencies/build_openssl.py` is pinned
against UWVM's recipe. Native configuration is `no-shared no-tests no-apps
no-module`; it builds libcrypto and libssl, but cosign links only static libcrypto.
Native HTTPS uses Go TLS. WASM builds only libcrypto with its documented
single-threaded, no-socket/no-dynamic-provider configuration and real WASI entropy.

A unique `wsea-libcrypto.pc` points to the **absolute static archive**. Missing
bundled crypto cannot silently resolve to system `-lcrypto`. Reuse validates
source, compiler, generated headers and archive identity. A receipt digest in
`CGO_CPPFLAGS` forces Go's CGO cache to account for crypto configuration changes.
These receipts are internal build inputs, never release attachments.

Always pass the exact counterpart checkout for release qualification. Core or
crypto changes require both repositories to be synchronized and the full runtime
matrix repeated. A matching header alone does not qualify another OpenSSL or ABI.
The WASM-only macro excludes POSIX state/receipt APIs, is forbidden on non-WASM
or atomic/threaded builds, and does not change the native default implementation.

## Native build and direct Go commands

```sh
make cosign UWVM2_ROOT=../uwvm2-ros
make test UWVM2_ROOT=../uwvm2-ros
./cosign wasm secure --help
```

Use the environment above to keep OpenSSL and test temporaries in `.tmp`.
For explicit Go commands after `make bundled-openssl`:

```sh
export PKG_CONFIG_PATH="$WSEA_OPENSSL_ROOT/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH" PKG_CONFIG_SYSROOT_DIR=
export CGO_CPPFLAGS="$(cat "$WSEA_OPENSSL_ROOT/cgo-cppflags")"
CGO_ENABLED=1 go build -p=2 -trimpath -o .tmp/work/cosign ./cmd/cosign
CGO_ENABLED=1 go test -p=2 ./cmd/cosign ./cmd/wasmcosign \
  ./internal/wasmcli ./internal/wasmsdk ./internal/wseanative \
  ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure
```

For Linux static releases use `netgo,osusergo,wsea_static` and external static
linking, as implemented in `scripts/build_wsea_release.py`. `CGO_ENABLED=0` for
the native product fails; it does not select a weaker verifier. The inherited
Go module name is still `github.com/sigstore/cosign/v3`: a module-proxy build of
that upstream path is not a build of this reviewed fork. Build from this checkout.

## Cross compilation and platform qualification

Supply target `CC`, `CXX`, `PKG_CONFIG` and `WSEA_OPENSSL_SPEC`. The JSON spec
uses UWVM's compiler/ABI fields: `platform`, `arch`, `cc`, `ar`, `ranlib`, `cflags`,
`ldflags`, with optional `configure_target`/`float_abi`. It must match target
`GOOS`/`GOARCH`; use a separate OpenSSL/work directory for every target.
`make cross WSEA_GOOS=linux WSEA_GOARCH=arm64` builds one selected target, not
an implied all-platform release.

The native release builder requires an actual execution prefix for cross builds,
for example `--exec-prefix-json '["/trusted/qemu-aarch64"]'`, and runs product
test binaries plus the resulting CLI. A compiler success without target execution
does not qualify an archive. `run_go_targets.py` requires explicit native
toolchains and matching UWVM evidence for broader QEMU campaigns.

Windows/DOS currently lack the protected native WSEA backend. Go has no powerpc32
or sparc64 port and CGO does not support Linux big-endian powerpc64. Do not rename
another target's executable or substitute pure Go to fill a missing platform.
The automatic release matrix is documented separately from the broader native
builder's possible target list.

## Build WASIp1 and JavaScript

Download and verify tools using `scripts/fetch_wsea_toolchains.py --output
.tmp/tools`, or supply the exact pinned official tools yourself. The fetcher
checks archive SHA-256 before safe extraction; the builder itself never downloads.
No Emscripten or third-party prebuilt OpenSSL WASM is required.

```sh
python3 scripts/build_wsea_wasm.py \
  --wasi-sdk .tmp/tools/wasi-sdk --wasm-opt .tmp/tools/binaryen/bin/wasm-opt \
  --uwvm-root ../uwvm2-ros --output .tmp/wsea-wasm --jobs 3
```

Outputs are `wasm-cosign-wasi.wasm`, `wasm-cosign-js.wasm` and one common
`wsea-crypto.wasm`. Only `wasm32-wasip1` and Go `js/wasm` are compiled. Binaryen
lowers required operations and validates strict MVP; threads, SIMD, GC, memory64
and WASIp2 are not enabled. The WASM import graph is restricted to the four
product packages and Go's standard library. Runtime glue must match the Go version.

A changed compiler, recipe or crypto identity cannot reuse the old crypto cache;
choose a fresh output directory. Do not edit receipts to force cache acceptance.
After committing the source, package using `scripts/package_wsea_wasm.py` with an
explicit version, artifact directory, new output directory and counterpart root.
It checks both committed header snapshots, source hashes and every selected
artifact before creating archives. See [CI/CD](wsea-release.en_US.md) for the
qualification gates that must run before publication.
