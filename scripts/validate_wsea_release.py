#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Validate the complete release matrix without executing downloaded artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
from package_wsea_wasm import TARGETS as WASM_TARGETS
from build_wsea_release import TARGETS as NATIVE_TARGETS
from wsea_documents import DOCUMENTS, ROOT

NATIVE_FILES = {'cosign', 'LICENSE', 'LICENSE-OpenSSL.txt', 'LICENSE-UWVM.md', 'COMMANDS.md', 'README.txt', *DOCUMENTS}
TARGETS = {**{k: NATIVE_FILES for k in NATIVE_TARGETS}, **{k: set(v) for k, v in WASM_TARGETS.items()}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assets', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--source-root', type=Path, default=ROOT, help='exact source checkout for a previously published tag')
    a = p.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', a.version) or not re.fullmatch(r'[a-f0-9]{40}', a.revision):
        p.error('explicit semantic version and full source revision required')
    expected_names = {f'{target}-wasm-cosign-{a.version}.tar.xz' for target in TARGETS}
    if {v.name for v in a.assets.iterdir()} != expected_names:
        raise ValueError('missing, duplicate or unapproved release assets')
    partner = (a.source_root / 'scripts/wsea_uwvm_revision.txt').read_text().strip()
    sums = []
    for target, allowed in TARGETS.items():
        archive = a.assets / f'{target}-wasm-cosign-{a.version}.tar.xz'
        if archive.is_symlink():
            raise ValueError('release archive cannot be a symlink')
        prefix = f'wasm-cosign-{a.version}-{target}' if target in WASM_TARGETS else archive.name.removesuffix('.tar.xz')
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            expected = {prefix + '/' + name for name in allowed | {'RELEASE.json'}}
            if (len(members) != len(expected) or {m.name for m in members} != expected or
                    any(not m.isfile() or m.size > 128 << 20 for m in members)):
                raise ValueError('archive contains unexpected files or sizes: ' + target)
            metadata = json.load(tar.extractfile(prefix + '/RELEASE.json'))
            if (metadata['version'] != a.version or metadata['target'] != target or
                    metadata['source_revision'] != a.revision or metadata['uwvm_wsea_revision'] != partner or
                    metadata['signature_container'] != 'uwvm.wsea.v2' or metadata['openssl'] != '3.5.9' or
                    set(metadata['files']) != allowed):
                raise ValueError('release provenance mismatch: ' + target)
            for name, digest in metadata['files'].items():
                data = tar.extractfile(prefix + '/' + name).read()
                if hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('packaged file digest mismatch: ' + name)
                if name in DOCUMENTS and data != (a.source_root / name).read_bytes():
                    raise ValueError('packaged documentation differs from release commit: ' + name)
        sums.append(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name)
    (a.assets / 'SHA256SUMS').write_text('\n'.join(sorted(sums)) + '\n')
    print(f'PASS: {len(TARGETS)} qualified target archives, exact production allowlists, paired provenance and bilingual documentation')


if __name__ == '__main__':
    main()
