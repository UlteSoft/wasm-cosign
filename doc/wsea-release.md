# WSEA releases

The release repository is `UlteSoft/wasm-cosign`. Release archives contain the
WASM-only executable, licenses and command documentation. Build directories,
test fixtures, dated qualification projects, logs, reports and toolchains are
never release assets or repository inputs. Preserve the unmodified vendored
OpenSSL source, including upstream test **source and reference fixtures**.

Build and test one native target, entirely outside the checkout:

```sh
python3 scripts/build_wsea_release.py --version v0.1.0 \
  --target x86_64-linux-gnu --work /tmp/wsea-release-linux \
  --output /tmp/wsea-release-assets
```

The script verifies the pinned shared core and crypto sources, builds bundled
OpenSSL, executes product tests (all 13 signature profiles, strict PKI,
multisignatures, malformed input and CLI checks), and then packages the final
binary. A failed command stops packaging. Linux executables are static;
macOS executables use system C/C++ libraries and statically linked OpenSSL.
The native macOS release workflow targets macOS 15 or later on both CPU types.

Cross builds additionally require target `CC`, `CXX`, `WSEA_OPENSSL_SPEC` and
`--exec-prefix-json '["/path/to/qemu-target"]'`. The executable and the product
test binaries must actually run on the selected target, natively or emulated.
Use a separate work directory per target. Downloaded compilers and sysroots
belong outside the repository. See [build requirements](wsea-build.md).

Only upload archives whose target tests succeeded. Never rename another
architecture's binary to fill a missing platform. Windows and DOS currently
have no supported WSEA protected-storage/native-verification backend. Go CGO
does not support Linux powerpc64 big endian, and Go has no powerpc32 or sparc64
port. Other missing targets require their own compatible toolchain, bundled
recipe and actual target qualification; omission is not a fallback to pure Go.

The `WSEA release assets` workflow builds and tests native macOS assets on an
explicit source revision. It does not publish automatically. Publish the
reviewed successful archives and a combined `SHA256SUMS` using `gh release`;
verify that the release tag points to the exact source used by every build.
