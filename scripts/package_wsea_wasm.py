#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Package only reviewed production WASM SDK files; never sweep a build directory."""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
from build_wsea_wasm import source_hashes
from wsea_documents import DOCUMENTS

ROOT = Path(__file__).resolve().parents[1]
COMMON = ('wsea-crypto.wasm', 'run.py', 'LICENSE', 'LICENSE-Go', 'LICENSE-OpenSSL') + DOCUMENTS
TARGETS = {
    'wasm32-wasip1': COMMON + ('wasm-cosign-wasi.wasm',),
    'wasm32-js': COMMON + ('wasm-cosign-js.wasm', 'wasm_exec.js', 'loader.mjs', 'run-json.mjs'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--artifacts', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--uwvm-root', type=Path, required=True)
    a = p.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', a.version):
        p.error('explicit semantic release version required')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT):
        p.error('commit the reviewed source before packaging')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    partner = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=a.uwvm_root, text=True).strip()
    header = (ROOT / 'internal/wseanative/wsea.h').read_bytes()
    partner_header = subprocess.check_output(['git', 'show', 'HEAD:src/uwvm2/utils/security/wsea.h'], cwd=a.uwvm_root)
    if header != partner_header or sha(header) != (ROOT / 'internal/wseanative/wsea.sha256').read_text().strip():
        p.error('committed shared verifier sources differ')
    # Source-owned adapters/docs/licenses must match this exact commit. Go's
    # wasm_exec.js and binaries are checked against the qualified build receipt.
    for name in ('loader.mjs', 'run-json.mjs', 'run.py', 'LICENSE-Go'):
        if (a.artifacts / name).read_bytes() != (ROOT / 'wasm' / name).read_bytes():
            p.error('stale source-owned artifact: ' + name)
    for name in DOCUMENTS:
        if (a.artifacts / name).read_bytes() != (ROOT / name).read_bytes():
            p.error('stale documentation artifact: ' + name)
    receipt = json.loads((a.artifacts.parent / 'wasm-receipt.json').read_text())
    if receipt['source_files'] != source_hashes():
        p.error('SDK source changed since artifact creation')
    if receipt['identity']['recipe_sha256'] != sha((ROOT / 'scripts/build_wsea_wasm.py').read_bytes()):
        p.error('build recipe changed since artifact creation')
    for name, expected in receipt['artifacts'].items():
        if sha((a.artifacts / name).read_bytes()) != expected:
            p.error('artifact changed after build receipt: ' + name)
    a.output.mkdir(parents=True, exist_ok=False)
    sums = []
    for target, names in TARGETS.items():
        contents = {name: (a.artifacts / name).read_bytes() for name in names}
        if any(sha(data) != receipt['artifacts'][name] for name, data in contents.items()):
            p.error('artifact changed during packaging')
        prefix = 'wasm-cosign-' + a.version + '-' + target
        metadata = {'version': a.version, 'source_revision': revision, 'uwvm_wsea_revision': partner,
                    'target': target, 'wasm_features': 'mvp', 'signature_container': 'uwvm.wsea.v2',
                    'wsea_source_sha256': sha(header), 'openssl': '3.5.9',
                    'openssl_source_sha256': receipt['identity']['source'],
                    'files': {name: sha(contents[name]) for name in names}}
        archive = a.output / (target + '-wasm-cosign-' + a.version + '.tar.xz')
        with tarfile.open(archive, 'w:xz', preset=6) as tar:
            for name in (*names, 'RELEASE.json'):
                data = (json.dumps(metadata, indent=2) + '\n').encode() if name == 'RELEASE.json' else contents[name]
                entry = tarfile.TarInfo(prefix + '/' + name)
                entry.size = len(data)
                entry.mode = 0o755 if name == 'run.py' else 0o644
                entry.mtime = 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = 'root'
                tar.addfile(entry, io.BytesIO(data))
        with tarfile.open(archive) as tar:
            members = tar.getmembers()
            if ({v.name for v in members} != {prefix + '/' + name for name in (*names, 'RELEASE.json')}
                    or len(members) != len(names) + 1 or not all(v.isfile() for v in members)):
                raise RuntimeError('release archive differs from exact production allowlist')
        sums.append(sha(archive.read_bytes()) + '  ' + archive.name)
    (a.output / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
    print('\n'.join(sums))


if __name__ == '__main__':
    main()
