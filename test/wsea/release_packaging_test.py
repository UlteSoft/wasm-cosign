#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Exercise publication refusal on mixed, incomplete or contaminated archives."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_wsea_release import TARGETS, WASM_TARGETS  # noqa: E402
from wsea_documents import DOCUMENTS  # noqa: E402


class ReleaseGateTest(unittest.TestCase):
    def build(self, directory, mutation=None):
        for target, names in TARGETS.items():
            prefix = f'wasm-cosign-v0.2.1-{target}' if target in WASM_TARGETS else f'{target}-wasm-cosign-v0.2.1'
            data = {name: (ROOT / name).read_bytes() if name in DOCUMENTS else b'synthetic gate-test data'
                    for name in names}
            metadata = {'version': 'v0.2.1', 'target': target, 'signature_container': 'uwvm.wsea.v2',
                        'openssl': '3.5.9', 'source_revision': '1' * 40,
                        'uwvm_wsea_revision': (ROOT / 'scripts/wsea_uwvm_revision.txt').read_text().strip(),
                        'files': {name: hashlib.sha256(value).hexdigest() for name, value in data.items()}}
            if target == 'wasm32-js' and mutation == 'revision':
                metadata['source_revision'] = '2' * 40
            data['RELEASE.json'] = json.dumps(metadata).encode()
            if target == 'wasm32-js':
                if mutation == 'key':
                    data['generated/private.pem'] = b'not a production artifact'
                elif mutation == 'translation':
                    del data['wasm/README.zh_CN.md']
                elif mutation == 'tamper':
                    data['wsea-crypto.wasm'] += b'tampered'
                elif mutation == 'traversal':
                    data['../outside'] = b'unexpected'
            archive = directory / f'{target}-wasm-cosign-v0.2.1.tar.xz'
            with tarfile.open(archive, 'w:xz') as tar:
                for name, value in data.items():
                    entry = tarfile.TarInfo(prefix + '/' + name)
                    entry.size = len(value)
                    tar.addfile(entry, io.BytesIO(value))

    def gate(self, directory):
        return subprocess.run([sys.executable, ROOT / 'scripts/validate_wsea_release.py',
                               '--assets', directory, '--version', 'v0.2.1', '--revision', '1' * 40],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_complete_allowlisted_set(self):
        with tempfile.TemporaryDirectory() as d:
            self.build(Path(d))
            result = self.gate(d)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(len((Path(d) / 'SHA256SUMS').read_text().splitlines()), 5)

    def test_contaminated_or_mismatched_archives_are_refused(self):
        for mutation in ('revision', 'key', 'translation', 'tamper', 'traversal', 'missing-target'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as d:
                self.build(Path(d), mutation)
                if mutation == 'missing-target':
                    next(Path(d).glob('aarch64-*.tar.xz')).unlink()
                self.assertNotEqual(self.gate(d).returncode, 0)
                self.assertFalse((Path(d) / 'SHA256SUMS').exists())


if __name__ == '__main__':
    if not Path(tempfile.gettempdir()).resolve().is_relative_to(ROOT / '.tmp'):
        sys.exit('set TMPDIR to a private directory under project .tmp')
    os.umask(0o077)
    unittest.main()
