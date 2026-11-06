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

The current automatic release builds these five archives from one source tag:

- `x86_64-linux-gnu`: native static Linux executable, tested on Linux x86_64.
- `aarch64-apple-darwin`: native macOS executable, tested on an ARM runner.
- `x86_64-apple-darwin`: native macOS executable, tested on an Intel runner.
- `wasm32-wasip1`: WASI Preview 1, with strict MVP modules.
- `wasm32-js`: Node/browser SDK, with the identical crypto reactor.

Native macOS targets require macOS 15 or newer and statically link OpenSSL while
using system C/C++ libraries. There is no WASIp2 build. Other previously published
architectures remain available in earlier releases; this automated matrix does
not claim to requalify them. Add a target only when its explicit toolchain and
actual native/QEMU tests are wired into both build and publication validation.
Never substitute an untested executable for a missing platform.

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
checks, the native three-target builder and portable qualification. For portable releases, tests execute the exact
bytes extracted from the packaged archives, not just an earlier build tree.

Only after all required jobs succeed does the isolated publication job receive
`contents: write`. It downloads production archives from that same run, validates
the complete five-target set, every file allowlist/digest, source/counterpart
revisions and bilingual docs, and generates `SHA256SUMS`. It creates a draft,
uploads the verified files and publishes the release. It does not execute
artifact binaries in the token-bearing publication job or overwrite an existing
release. No extra cloud credential, OIDC signing service or registry is required.

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
