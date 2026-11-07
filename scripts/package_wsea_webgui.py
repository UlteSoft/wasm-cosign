#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Package the independent local GUI using an exact production-file allowlist."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
TARGET = 'webgui'
FILES = ('LICENSE', 'webgui/server.py', 'webgui/native_picker.py', 'webgui/README.md',
         'webgui/README.en_US.md', 'webgui/README.zh_CN.md', 'webgui/static/index.html',
         'webgui/static/app.js', 'webgui/static/style.css', 'webgui/static/mark.svg')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', required=True)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', a.version):
        p.error('explicit semantic version required')
    if not a.output.resolve().is_relative_to(ROOT / '.tmp'):
        p.error('release output must be under project .tmp')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT):
        p.error('commit reviewed source before packaging')
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    contents = {name: (ROOT / name).read_bytes() for name in FILES}
    metadata = {'version': a.version, 'target': TARGET, 'source_revision': revision,
                'requires_existing_binary': True,
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}}
    contents['RELEASE.json'] = (json.dumps(metadata, indent=2) + '\n').encode()
    a.output.mkdir(parents=True, exist_ok=True)
    name = f'{TARGET}-wasm-cosign-{a.version}'
    archive = a.output / (name + '.tar.xz')
    with tarfile.open(archive, 'x:xz') as tar:
        for relative, data in contents.items():
            entry = tarfile.TarInfo(name + '/' + relative)
            entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = 'root'
            tar.addfile(entry, io.BytesIO(data))
    print(archive)


if __name__ == '__main__':
    main()
