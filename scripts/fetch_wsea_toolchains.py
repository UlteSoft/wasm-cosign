#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Download checksum-pinned Linux tools into project .tmp; never execute downloads."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--tools', default='wasi-sdk,binaryen,wasmtime,llvm')
    a = p.parse_args()
    out = a.output.resolve()
    if not out.is_relative_to(ROOT / '.tmp'):
        p.error('tool downloads must remain under project .tmp')
    if not hasattr(tarfile, 'data_filter'):
        p.error('safe tool extraction requires Python 3.12+ (or its data_filter backport)')
    os.umask(0o077)
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'scripts/wsea_toolchains.json').read_text())
    for name in a.tools.split(','):
        pin = manifest[name]
        archive = out / (name + '.download')
        if not archive.exists():
            part = archive.with_suffix('.partial')
            with urllib.request.urlopen(pin['url'], timeout=60) as response, part.open('wb') as stream:
                if not response.url.startswith('https://'):
                    raise ValueError('tool download redirected away from HTTPS')
                count = 0
                while chunk := response.read(1 << 20):
                    count += len(chunk)
                    if count > 3 << 30:
                        raise ValueError('tool archive exceeds bound')
                    stream.write(chunk)
            part.rename(archive)
        h = hashlib.sha256()
        with archive.open('rb') as stream:
            while chunk := stream.read(1 << 20):
                h.update(chunk)
        if h.hexdigest() != pin['sha256']:
            raise ValueError('tool archive checksum mismatch: ' + name)
        target = out / name
        if target.exists():
            raise ValueError('choose a fresh tool directory; do not trust extracted cache: ' + str(target))
        stage = out / (name + '.extract')
        stage.mkdir()
        with tarfile.open(archive) as tar:
            members = []
            roots = set()
            for member in tar:
                parts = PurePosixPath(member.name).parts
                if not parts or member.name.startswith('/') or '..' in parts:
                    raise ValueError('unsafe tool archive member')
                roots.add(parts[0])
                relative = '/'.join(parts[1:])
                if name != 'llvm' or relative in ('bin/clang', 'bin/clang++', 'bin/clang-22') or relative.startswith(
                        ('lib/clang/', 'lib/libLLVM', 'lib/libclang-cpp')):
                    members.append(member)
            if len(roots) != 1 and pin.get('layout') != 'flat':
                raise ValueError('unexpected tool archive layout')
            tar.extractall(stage, members=members, filter='data')
        if pin.get('layout') == 'flat':
            stage.rename(target)
        else:
            (stage / roots.pop()).rename(target)
            shutil.rmtree(stage)
        print('Verified and extracted', name, flush=True)


if __name__ == '__main__':
    main()
