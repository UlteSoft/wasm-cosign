# CI/CD and release maintenance

[简体中文](wsea-release.zh_CN.md) | [Documentation](../README.en_US.md)

## Versions and compatibility

Releases belong to [UlteSoft/wasm-cosign](https://github.com/UlteSoft/wasm-cosign/releases).
A release tag is an explicit `vMAJOR.MINOR.PATCH` on reviewed `main` history.
The tag and published attachments are immutable: use a new patch release for a
correction. The WSEA wire format is independently frozen as `uwvm.wsea.v2`;
changing the tool version does not authorize a format, algorithm-ID or security
semantics change. `wsea-sdk-1` names the memory transport, not another signature
container. The old `wasm-cosign` container remains deprecated.

v0.2.1 adds complete bilingual product documentation, automated portable/native
qualification and gated GitHub publication. Every new archive contains both
languages. Earlier native and portable releases retain their original files.
The matching UWVM revision includes a small interpreter-only diagnostics build
fix; it does not change the shared verifier. The exact counterpart commit lives
in `scripts/wsea_uwvm_revision.txt`, not a moving branch name.

## Continuous integration

Checks run on pushes to `main` and pull requests, with read-only repository tokens
and checkout credentials disabled. External actions in the WSEA workflows use full commit SHAs.
Toolchain archive downloads are pinned by URL and SHA-256; new versions require
an explicit source change and renewed qualification.

- **Bilingual documentation** checks all language pairs, section/example counts,
  local links and anchors, and rejects tracked `.tmp` material.
- **CI-Tests** runs native product tests on Linux and macOS, Linux race tests,
  bundled-OpenSSL checks and generated CLI-help comparison.
- **WSEA CI** builds the shared crypto reactor and both frontends, validates MVP,
  builds the pinned real UWVM interpreter and executes the complete matrix,
  signing and host-security suites. Its source guard compares both repositories.
- The product linter and whitespace checks remain separate checks. Retained
  upstream container/conformance jobs do not become WSEA release evidence.

Generated files stay in `.tmp`. Linux build/test jobs use disposable systemd
units with a 64 GiB hard memory limit, zero swap, bounded CPU/processes and job
timeouts; memory pressure throttling adds a lower soft limit. The portable
qualification checks the actual leaf and OOM counters. macOS uses separate native
hosted runners. There is no fallback that changes crypto or skips failed tests.

## Automatic release targets

The automatic release builds fifteen archives from one immutable source tag:

- Static GNU/Linux: `aarch64-linux-gnu`, `armv7-linux-gnueabihf`, `i686-linux-gnu`,
  `loongarch64-linux-gnu`, `mips64-linux-gnu`, `mips64el-linux-gnu`,
  `powerpc64le-linux-gnu`, `riscv64-linux-gnu`, `x86_64-linux-gnu`.
- Static musl Linux: `x86_64-linux-musl`.
- Native FreeBSD: `x86_64-freebsd15`, requiring FreeBSD 15.1 or newer.
- Native macOS: `aarch64-apple-darwin` and `x86_64-apple-darwin`, requiring macOS 15+.
- Portable SDK: `wasm32-wasip1` and `wasm32-js`, with the identical crypto reactor
  and strict MVP modules. There is no WASIp2 build.

The i686 build requires SSE2; ARMv7 uses the hard-float ABI; PowerPC64 LE targets
POWER8 or newer; MIPS64 uses the n64 hardware-floating-point ABI. macOS and FreeBSD
statically link the bundled OpenSSL and use their system C/C++ libraries.

`wsea-cross-assets.yml` runs nine Linux configurations through actual QEMU 10.2+
and builds/tests FreeBSD inside a disposable QEMU guest. The FreeBSD VM has 4 GiB
RAM and two CPUs and inherits the host's 64 GiB zero-swap cgroup. Its official
15.1 image and Go 1.26.8 archive are pinned by SHA-256. Guest dependencies are
installed only inside its disposable overlay. The guest build uses an unprivileged
account and SSH binds to host loopback. No persistent VM or persistent self-hosted
runner is required.

Linux compiler/sysroot packages are SHA-256-pinned in
`scripts/wsea_cross_toolchains.json`. Debian/Ubuntu packages are extracted into
private directories without installing them on the host. The musl SDK retains
its unsafe-host-path guard; a private copy of the same Go tree avoids host `/usr`
include paths. The shared OpenSSL assembly/algorithm configuration is unchanged.
Each target executes the full product tests, including signatures, certificate
admission, mixed-key multisignatures, protected state and CLI boundaries, before
an archive is created. The extracted executable is also checked through its
actual target runner. Windows, DOS and other unqualified ABIs are not substituted.

## Publish a new tag

Review both language versions and the fixed UWVM counterpart, then run the local
checks under the authorized cgroup. Commit only production source, documentation
and test source. Before tagging, verify that no generated key, fixture, dated
qualification directory, log or result has been staged.

```sh
git diff --check
python3 scripts/check_wsea_docs.py
git status --short
# After committing and successful checks:
git push origin main
git tag -a v0.2.1 -m 'wasm-cosign v0.2.1'
git push origin v0.2.1
```

Use the next unused version instead of reusing this example. Pushing the tag
starts **WSEA release** (`cut-release.yml`). Admission requires a semantic tag
on `main` history. The workflow calls native unit/race and generated-help checks, bilingual/workflow
checks, the native three-target builder, ten QEMU targets and portable qualification. For portable releases, tests execute the exact
bytes extracted from the packaged archives, not just an earlier build tree.

Only after all required jobs succeed does the isolated publication job receive
`contents: write`. It downloads production archives from that same run, validates
the complete fifteen-target set, every file allowlist/digest, source/counterpart
revisions and bilingual docs, and generates `SHA256SUMS`. It creates a draft,
uploads the verified files and publishes the release. It does not execute
artifact binaries in the token-bearing publication job or overwrite an existing
release. No extra cloud credential, OIDC signing service or registry is required.

## Completing an existing release

An explicitly authorized platform supplement must use the existing tag's exact
product commit and its pinned UWVM counterpart. Do not move the tag or rebuild
from a newer branch under the old version. The QEMU workflow can be dispatched
from the current workflow branch with the older `version` input: it checks out
that product tag separately from the current orchestration scripts.

Qualify each missing target, retain the original executable archives, and
validate the combined fifteen-target set with `validate_wsea_release.py` using
`--source-root` for the clean original checkout. Add only the missing archives;
update the aggregate `SHA256SUMS` and bilingual release notes after checking that
all existing archive hashes are unchanged. Download the final attachments and
verify them again. This supplement updates assets and notes, not the immutable
tag's source documents or historical workflow. Future tags use the expanded
matrix in the current branch. Never publish a failed or unexecuted target.

## Archive contract and provenance

Native archives include the executable, command documentation, complete bilingual
guides, licenses and `RELEASE.json`. Portable archives include only the selected
WASM frontend, common reactor, necessary host glue, the same bilingual guides,
licenses and `RELEASE.json`. Packaging uses an explicit source-owned allowlist,
not a recursive sweep of a work directory. File modes, owner fields and timestamps
are normalized. Logs, test keys, fixtures, results, toolchains and private build
receipts are not archive members or uploaded CI artifacts.

`RELEASE.json` binds the release version, target, product commit, paired UWVM
commit, WSEA container, OpenSSL version and each packaged production-file hash.
Portable metadata additionally records strict MVP and source crypto digests.
`SHA256SUMS` covers the compressed archives. These checksums and provenance are
integrity information, not independent cryptographic release attestation.
The workflow does not use the WASM-only product to sign non-WASM archives.

## Failure recovery and repository settings

The release workflow can be manually dispatched **on an existing tag** to rerun
failed infrastructure, without retagging. A missing target or failed test blocks
publication. Correct code failures with a new reviewed commit and new tag.
Do not use `continue-on-error`, downgrade tool pins or manually upload files that
bypassed target tests.

If failure occurs after draft creation, inspect that draft and its run first.
The workflow intentionally refuses any existing release. Remove only the known
unpublished failed draft after confirming its identity, then rerun the same tag;
never delete or replace a published release to make a retry work.

GitHub Actions must be enabled and allowed to grant the publication job
`contents: write`. Maintainers need tag-push permission. Configure protected-branch
required checks against the actual job names after the first successful run;
repository rules are administrator settings, not granted by YAML alone. Pull
requests never enter the publication path. No persistent self-hosted runner is
needed by these workflows.

## Maintaining documents and dependencies

Update `.en_US.md` and `.zh_CN.md` together; language-neutral files only select
a language. `scripts/wsea_documents.py` is the package/check allowlist. Generated
English CLI help is the mechanical flag reference; both full prose guides explain
the same behavior. Run document and generated-help checks before publishing.

When upgrading OpenSSL or the WSEA header, synchronize and commit both repositories,
update pins and repeat all relevant native/portable qualification. When changing a
compiler/runtime/action, review its official upstream release and digest, update
the explicit pin and test actual artifacts. CI passing is evidence of its stated
coverage; do not describe it as proof that all possible security defects are absent.
