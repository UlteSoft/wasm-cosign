# OpenSSL source dependency

This directory contains the **complete, unmodified OpenSSL 3.5.9 release source**
in `upstream/`, including its build system, algorithms, tests, documentation,
Apache-2.0 `LICENSE.txt`. It is not a header-only placeholder.

The official LTS release was published on 29 September 2026. The archive SHA-256
is `603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a`.
The detached release signature was verified in an isolated GnuPG home. Its
signing subkey `C46ED3F2CBEFDA1FDAADA44264ED7B1DCCE71CB2` is certified by the
OpenSSL primary `B146647E45A7B33947AB226B2A2C87D161692D40`, compared with the
fingerprint published on the official HTTPS source page. This authenticates the
release against that explicit website-published key, rather than a local
GnuPG owner-trust setting. See `provenance.json`, retained checksum/signature and
public certificates in `provenance/`, and `sources.sha256` for every upstream
file. No upstream source patches have been applied.

Primary sources:

- [Official release and signing-key information](https://www.openssl-library.org/source/)
- [Release archive](https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz)
- [OpenSSL signing certificates](https://www.openssl-library.org/source/pubkeys.asc)

This copy is imported from `uwvm2-ros/third-parties/openssl` byte for byte,
including provenance and the per-file source manifest. The wasm-cosign adapter
uses the identical pinned `tools/dependencies/build_openssl.py` recipe. Run
`make bundled-openssl` or `make`; system OpenSSL is not a fallback. With
`UWVM2_ROOT`, the build guard checks both copies and recipes for drift.
See [`doc/wsea-build.md`](../../doc/wsea-build.md) for build and qualification
requirements. The provenance above records the original UWVM import validation;
copying it does not claim a fresh download or signing-key verification.

Only source is vendored. Build outputs, generated headers, archives, logs and
receipts live under the configured build directory; no binaries belong here.
The source manifest intentionally includes upstream dotfiles. When importing
this directory into a repository with broad dotfile ignore rules, retain those
files as well.
