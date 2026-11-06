#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Build, execute product tests, and package one explicitly selected WSEA target.

Cross builds require the bundled OpenSSL target spec, CC/CXX and an actual
execution prefix (for example QEMU). Failed builds/tests never produce archives.
Keep generated work under the project's ignored .tmp; package only explicit files.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from wsea_documents import DOCUMENTS

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    'x86_64-linux-gnu': ('linux', 'amd64'),
    'x86_64-linux-musl': ('linux', 'amd64'),
    'i686-linux-gnu': ('linux', '386'),
    'aarch64-linux-gnu': ('linux', 'arm64'),
    'armv7-linux-gnueabihf': ('linux', 'arm'),
    'loongarch64-linux-gnu': ('linux', 'loong64'),
    'mips64-linux-gnu': ('linux', 'mips64'),
    'mips64el-linux-gnu': ('linux', 'mips64le'),
    'powerpc64le-linux-gnu': ('linux', 'ppc64le'),
    'riscv64-linux-gnu': ('linux', 'riscv64'),
    'aarch64-apple-darwin': ('darwin', 'arm64'),
    'x86_64-apple-darwin': ('darwin', 'amd64'),
    'x86_64-freebsd15': ('freebsd', 'amd64'),
}
PACKAGES = ['./cmd/cosign', './cmd/wasmcosign', './internal/wasmsdk', './internal/wasmcli', './internal/wseanative',
            './pkg/wasmsecure', './cmd/cosign/cli/wasmsecure']


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--version', required=True)
    ap.add_argument('--target', choices=TARGETS, required=True)
    ap.add_argument('--work', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--exec-prefix-json', default='[]')
    a = ap.parse_args()
    if not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?', a.version):
        ap.error('version must be an explicit semantic release tag')
    prefix = json.loads(a.exec_prefix_json)
    if not isinstance(prefix, list) or not all(isinstance(x, str) and x for x in prefix):
        ap.error('execution prefix must be an argv array')
    work, output = a.work.resolve(), a.output.resolve()
    if not all(path.is_relative_to(ROOT / '.tmp') for path in (work, output)):
        ap.error('generated work and release output must be under project .tmp')
    os.umask(0o077)
    work.mkdir(parents=True, exist_ok=True)
    for name in ('tmp', 'go-cache', 'go-modules'):
        (work / name).mkdir(exist_ok=True)
    go = os.environ.get('GOEXE', 'go')
    host = json.loads(subprocess.check_output([go, 'env', '-json', 'GOHOSTOS', 'GOHOSTARCH']))
    goos, goarch = TARGETS[a.target]
    if (goos, goarch) != (host['GOHOSTOS'], host['GOHOSTARCH']) and not prefix:
        ap.error('cross release requires actual target execution, not just compilation')
    crypto = work / 'openssl'
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED='1',
               WSEA_TEST_EXEC_PREFIX=json.dumps(prefix),
               WSEA_OPENSSL_ROOT=str(crypto), PKG_CONFIG_PATH=str(crypto / 'pkgconfig'),
               PKG_CONFIG_LIBDIR=str(crypto / 'pkgconfig'), PKG_CONFIG_SYSROOT_DIR='',
               TMPDIR=str(work / 'tmp'), GOTMPDIR=str(work / 'tmp'),
               GOCACHE=str(work / 'go-cache'), GOMODCACHE=str(work / 'go-modules'))
    if goarch == 'arm':
        env['GOARM'] = '7'
    if goos == 'darwin':
        env.setdefault('MACOSX_DEPLOYMENT_TARGET', '15.0')

    def run(name, command):
        print(name, flush=True)
        log_path = work / (name + '.log')
        try:
            with log_path.open('w') as log:
                subprocess.run(list(map(str, command)), cwd=ROOT, env=env,
                               stdout=log, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError:
            sys.stderr.write(log_path.read_text(errors='replace')[-16000:])
            raise

    counterpart = os.environ.get('UWVM2_ROOT')
    if not counterpart:
        ap.error('release qualification requires the explicit UWVM2_ROOT counterpart')
    for tree in (ROOT, Path(counterpart)):
        if subprocess.check_output(['git', 'status', '--porcelain'], cwd=tree):
            ap.error('release source and counterpart must be committed and clean')
    if subprocess.check_output(['git', '-C', counterpart, 'rev-parse', 'HEAD'], text=True).strip() != (
            ROOT / 'scripts/wsea_uwvm_revision.txt').read_text().strip():
        ap.error('release counterpart must match the pinned UWVM revision')
    run('source-guard', ['python3', 'scripts/check_wsea_build.py', '--uwvm-root', counterpart])
    run('documents', ['python3', 'scripts/check_wsea_docs.py'])
    run('openssl', ['python3', 'scripts/prepare_wsea_openssl.py'])
    env['CGO_CPPFLAGS'] = env.get('CGO_CPPFLAGS', '') + ' ' + (crypto / 'cgo-cppflags').read_text().strip()
    flags = '-s -w -X github.com/sigstore/cosign/v3/internal/wasmcli.Version=' + a.version
    if goos == 'linux':
        flags += ' -linkmode external -extldflags=-static'
    test_args = ['-exec', shlex.join(prefix)] if prefix else []
    run('product-tests', [go, 'test', '-p=2', '-count=1', '-timeout=10m',
                         '-tags=netgo,osusergo,wsea_static', '-ldflags', flags, *test_args, *PACKAGES])
    binary = work / 'cosign'
    run('binary', [go, 'build', '-p=2', '-trimpath', '-tags=netgo,osusergo,wsea_static',
                   '-ldflags', flags, '-o', binary, './cmd/cosign'])
    version = subprocess.check_output([*prefix, str(binary), 'version'], env=env, text=True)
    if version.strip() != 'wasm-cosign ' + a.version + ' WSEA v2':
        raise RuntimeError('wrong product or release version')
    for forbidden in ('sign-blob', 'verify-blob', 'sign', 'verify', 'bundle'):
        result = subprocess.run([*prefix, str(binary), forbidden], env=env, capture_output=True)
        if result.returncode != 1 or b'unknown command' not in result.stderr:
            raise RuntimeError('unexpected non-WASM command: ' + forbidden)
    if goos == 'linux':
        info = subprocess.check_output(['readelf', '-l', str(binary)], text=True)
        if 'INTERP' in info:
            raise RuntimeError('Linux release must be static')
    else:
        info = subprocess.check_output(['otool', '-L', str(binary)] if goos == 'darwin'
                                       else ['ldd', str(binary)], text=True)
        if 'libcrypto.' in info or 'libssl.' in info:
            raise RuntimeError('release depends on an external OpenSSL library')
    name = f'{a.target}-wasm-cosign-{a.version}'
    package = work / name
    package.mkdir(exist_ok=False)
    shutil.copy2(binary, package / 'cosign')
    (package / 'cosign').chmod(0o755)
    for source, destination in [('LICENSE', 'LICENSE'),
            ('third_party/openssl/upstream/LICENSE.txt', 'LICENSE-OpenSSL.txt'),
            ('internal/wseanative/LICENSE-UWVM.md', 'LICENSE-UWVM.md'),
            ('doc/wsea-cli/cosign_wasm_secure.md', 'COMMANDS.md')]:
        shutil.copy2(ROOT / source, package / destination)
    for relative in DOCUMENTS:
        destination = package / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    (package / 'README.txt').write_text(
        f'wasm-cosign {a.version} / {a.target}\n\n'
        'Usage: ./cosign wasm secure --help\n'
        'Embedded WSEA v2 only. Bundled OpenSSL 3.5.9.\n'
        '13 profiles: ES256/384/512, ESP256/384/512, Ed25519, PS256/384/512, RS256/384/512.\n'
        'HTTPS/TLS auxiliary fetching is supported; verification uses protected local trust.\n'
        'The UWVM verifier is from UlteSoft/uwvm2-ros (Apache-2.0).\n'
        'This archive contains no generated test fixtures, logs or test reports.\n')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / (name + '.tar.xz')
    if archive.exists():
        raise RuntimeError('refusing to overwrite an existing release archive')
    files = ('cosign', 'LICENSE', 'LICENSE-OpenSSL.txt', 'LICENSE-UWVM.md', 'COMMANDS.md', 'README.txt') + DOCUMENTS
    metadata = {'version': a.version, 'target': a.target, 'signature_container': 'uwvm.wsea.v2',
                'source_revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'uwvm_wsea_revision': subprocess.check_output(['git', '-C', counterpart, 'rev-parse', 'HEAD'], text=True).strip(),
                'openssl': '3.5.9',
                'files': {v: hashlib.sha256((package / v).read_bytes()).hexdigest() for v in files}}
    (package / 'RELEASE.json').write_text(json.dumps(metadata, indent=2) + '\n')
    with tarfile.open(archive, 'w:xz') as stream:
        for relative in (*files, 'RELEASE.json'):
            entry = stream.gettarinfo(str(package / relative), arcname=name + '/' + relative)
            entry.mtime = 0
            entry.uid = entry.gid = 0
            entry.uname = entry.gname = 'root'
            entry.mode = 0o755 if relative == 'cosign' else 0o644
            with (package / relative).open('rb') as content:
                stream.addfile(entry, content)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / (archive.name + '.sha256')).write_text(digest + '  ' + archive.name + '\n')
    print(str(archive), flush=True)


if __name__ == '__main__':
    main()
