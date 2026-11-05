# Building the WASM signing product

The default `./cmd/cosign` executable exposes `cosign wasm secure` and `version`.
`sign`, `verify`, `fetch`, `policy-init` and `policy-update` use embedded WSEA v2,
the same format accepted by UWVM. The thirteen algorithm profiles and existing
multisignature wire format are unchanged. The legacy Sigstore `wasm-cosign`
signature container is **deprecated**; use `uwvm.wsea.v2` for new signatures.
Legacy container commands, OCI/container operations and arbitrary blob commands
are not exposed.
Historical upstream source remains in the checkout; it is outside the product
import graph. `go test ./...` explicitly builds that historical source as well;
use `make test` for the product.

HTTPS module fetching, TLS authentication, certificate-chain and CRL validation
remain supported. The runtime verification gate is offline. No downloaded root
can become trusted without independently protected local policy provisioning.

## Shared verifier

`internal/wseanative/wsea.h` is an exact pinned copy of
`uwvm2-ros/src/uwvm2/utils/security/wsea.h`. Go signing produces the existing
canonical COSE bytes; every verification contribution calls the shared native
COSE decoder and crypto/PKI verifier. Public `Sign` requires `Embedded: true`;
`Parse` and `Verify` reject the retired v1 domain. There is no Go X.509 fallback. This covers strict root
self-signatures, issuer identifiers, name/policy constraints, CRLs and signature
parameters with the same code as the execution gate.

Go still checks the exact module digest, signed manifest, protected policy,
distinct-key threshold and rollback state. The native deployment adapter does
not read/write state or create execution receipts. Only the VM's ordinary
execution path consults/advances its state and issues a receipt. Partial signing
does not authorize deployment or execution.
The deployment state gate also rechecks the minimum authenticated manifest,
certificate and CRL expiry after verification; each multisignature contribution
can shorten that bound.

Changes to the core require updating **both** repositories, updating
`internal/wseanative/wsea.sha256`, and repeating cross-tool qualification. Release
qualification must specify `UWVM2_ROOT` so a missing counterpart fails the build;
a standalone checkout checks the pinned snapshot. Qualify both products against
the same OpenSSL release/configuration; a matching header alone does not qualify
a different crypto library or platform.

## Native build and checks

Requirements: Go 1.26+, a C++20 compiler, a C compiler, `ar`, `ranlib`,
Python 3.9+, Perl5, make and `pkg-config`. The complete unmodified OpenSSL 3.5.9
release source, license, provenance and per-file SHA-256 manifest are copied from
UWVM into `third_party/openssl`. `tools/dependencies/build_openssl.py` is an exact
pinned copy of UWVM's recipe: `no-shared no-tests no-apps no-module`. No download,
system OpenSSL installation or trust-store change is performed during this build.

```sh
make cosign UWVM2_ROOT=../uwvm2-ros
make test UWVM2_ROOT=../uwvm2-ros
./cosign wasm secure --help
```

`make` builds the dependency under `.wsea-build/openssl` (override with the
absolute `WSEA_OPENSSL_ROOT` path). It checks all source files and the compiler,
headers and archive receipt on reuse. `WSEA_OPENSSL_JOBS` controls build jobs
(default at most four). Both the normal and static Go build tags use the unique
`wsea-libcrypto.pc` module with an **absolute static archive**; a missing bundled
library cannot resolve to the host's `-lcrypto`. The bridge also pins the OpenSSL
header version. `libssl.a` is built by the shared recipe but is not linked into
wasm-cosign: HTTPS continues to use Go TLS. The ordinary executable can still
require the system C/C++ runtime, but does not require a shared OpenSSL library.
The checked receipt digest is also exported through `CGO_CPPFLAGS` so Go's CGO
cache cannot silently reuse a package built with a previous crypto configuration.

`scripts/check_wsea_build.py` checks the full source manifest, recipe pin,
shared WSEA core and thirteen algorithm IDs. With `UWVM2_ROOT` it also checks
both source trees and recipe equality. The default and release import graphs
allow only WSEA packages, Cobra and its argument-parsing dependencies.
`CGO_ENABLED=0` and unsupported targets fail to build without a weaker fallback.

For direct Go commands, prepare the library and explicitly select its metadata:

```sh
make bundled-openssl UWVM2_ROOT=../uwvm2-ros
export PKG_CONFIG_PATH="$PWD/.wsea-build/openssl/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"
export PKG_CONFIG_SYSROOT_DIR=
export CGO_CPPFLAGS="$(cat .wsea-build/openssl/cgo-cppflags)"
CGO_ENABLED=1 go build -tags netgo,osusergo,wsea_static -trimpath \
  -ldflags '-s -w -linkmode external -extldflags "-static -fuse-ld=lld"' \
  -o cosign-static ./cmd/cosign
```

Cross compilation needs target C/C++ compilers and `WSEA_OPENSSL_SPEC`, a JSON
file using the same compiler/ABI spec as UWVM's bundled recipe. The spec's
platform/arch must match `GOOS`/`GOARCH`; use a separate output directory per
target. It carries `cc`, `ar`, `ranlib`, `cflags`, `ldflags` and optional
`configure_target`/`float_abi` fields. `run_go_targets.py` requires
`--native-toolchains`, a JSON map from target to explicit `CC`, `CXX`,
`PKG_CONFIG` and `WSEA_OPENSSL_SPEC` values (plus optional CGO flags). It builds
this source for each target and requires actual matching UWVM test evidence.
Old pure-Go reports cannot qualify the native product. The default GoReleaser manifest is restricted to Linux amd64 and statically
links the qualified crypto backend. Add another release target only with its
explicit native toolchain and passing matching UWVM tests. Container targets
build the same bundled library. Release signing of distribution archives is done by
an independently installed upstream signer, never by reintroducing unrelated
commands into this executable.
GoReleaser module-proxy builds are disabled: release builds must use this
checked-out fork. Its inherited module name still points to upstream Sigstore;
fetching that module's release would not build the checked WSEA command graph.

`make cross WSEA_GOOS=linux WSEA_GOARCH=arm64` builds one explicitly selected
native/cross toolchain; supply target `CC`, `CXX`, `PKG_CONFIG` and
`WSEA_OPENSSL_SPEC`. `make ko`
defaults to `KO_PLATFORM=linux/amd64`, not an unqualified all-platform build.
Release validation checks the UWVM revision selected by `WSEA_UWVM_REVISION`
(or `main`); publish both matching core snapshots before enabling that paired
release. CloudBuild selects its counterpart with `_UWVM_REVISION` and extracts
its independent distribution signer from the already pinned upstream image.
`COSIGN_RELEASE_SIGNER` must name that separate executable for local releases.
