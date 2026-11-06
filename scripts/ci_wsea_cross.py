#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Build and execute a pinned static Linux target through actual QEMU."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from wsea_cross_support import ROOT, cgroup_snapshot, download, finish_cgroup, private_environment, private_path, sha


def prepare(target, directory):
    manifest = json.loads((ROOT / 'scripts/wsea_cross_toolchains.json').read_text())
    pin = manifest[target]
    directory.mkdir(parents=True, exist_ok=False)
    sdk = directory / 'sdk'
    sdk.mkdir()
    if pin['kind'] == 'deb':
        for package in pin['packages']:
            archive = download(package['url'], package['sha256'], directory / 'downloads' / package['filename'])
            subprocess.run(['dpkg-deb', '-x', str(archive), str(sdk)], check=True)
        binaries = sdk / 'usr/bin'
        libraries = sdk / 'usr/lib/x86_64-linux-gnu'
    else:
        archive = download(pin['url'], pin['sha256'], directory / 'toolchain.tar.xz')
        with tarfile.open(archive) as tar:
            tar.extractall(sdk, filter='data')
        roots = list(sdk.iterdir())
        if len(roots) != 1 or not roots[0].is_dir():
            raise ValueError('unexpected toolchain layout')
        sdk = roots[0]
        old = (sdk / 'share/buildroot/sdk-location').read_bytes().strip()
        # The vendor's relocation list includes optional, removed host tools.
        # Relocate only existing SDK files; retain its compiler's path guard.
        for name in (sdk / 'share/buildroot/sdk-relocs').read_text().splitlines():
            path = (sdk / name).resolve()
            if not path.is_relative_to(sdk):
                raise ValueError('toolchain relocation escapes SDK')
            if path.is_file():
                path.write_bytes(path.read_bytes().replace(old, str(sdk).encode()))
        (sdk / 'share/buildroot/sdk-location').write_text(str(sdk) + '\n')
        binaries, libraries = sdk / 'bin', None
    commands = {}
    for name, compiler in [('cc', 'gcc'), ('cxx', 'g++'), ('ar', 'ar'), ('ranlib', 'ranlib')]:
        argv = [str(binaries / (pin['triple'] + '-' + compiler))]
        if name in ('cc', 'cxx') and pin['kind'] == 'deb':
            argv.append('--sysroot=' + str(sdk))
        wrapper = directory / name
        wrapper.write_text('#!/bin/sh\n' +
                           ('export LD_LIBRARY_PATH=' + shlex.quote(str(libraries)) + '\n' if libraries else '') +
                           'exec ' + shlex.join(argv) + ' "$@"\n')
        wrapper.chmod(0o700)
        commands[name] = str(wrapper)
    spec = directory / 'openssl.json'
    spec.write_text(json.dumps({'platform': 'linux', 'arch': pin['arch'],
        'cc': [commands['cc']], 'ar': [commands['ar']], 'ranlib': [commands['ranlib']],
        'cflags': ['-O2', '-g0', '-fPIC'], 'ldflags': [], 'no_asm': False, 'jobs': 3}, indent=2) + '\n')
    return pin, commands, spec


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--target', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--source-root', type=Path, required=True)
    p.add_argument('--uwvm-root', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    a = p.parse_args()
    source, work = a.source_root.resolve(), private_path(a.work)
    if not work.is_relative_to(source / '.tmp') or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', a.version):
        p.error('explicit version and source-owned .tmp work directory required')
    private_environment(work)
    before = cgroup_snapshot()
    revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    tagged = subprocess.check_output(['git', '-C', str(source), 'rev-parse', a.version + '^{commit}'], text=True).strip()
    if revision != tagged:
        raise RuntimeError('product checkout must match the immutable release tag')
    pin, commands, spec = prepare(a.target, work / 'toolchain')
    qemu = shutil.which(pin['qemu'])
    if not qemu:
        raise RuntimeError('required QEMU target is unavailable: ' + pin['qemu'])
    version = subprocess.check_output([qemu, '--version'], text=True)
    match = re.search(r'version (\d+)\.(\d+)', version)
    if not match or tuple(map(int, match.groups())) < (10, 2):
        raise RuntimeError('target qualification requires QEMU 10.2 or newer')
    env = dict(os.environ, CC=commands['cc'], CXX=commands['cxx'], AR=commands['ar'],
               RANLIB=commands['ranlib'], WSEA_OPENSSL_SPEC=str(spec), UWVM2_ROOT=str(a.uwvm_root.resolve()))
    if pin['kind'] == 'tar':
        # Buildroot rejects host /usr include paths. Keep the identical Go tree
        # in private build space instead of disabling that isolation check.
        go_root = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip())
        shutil.copytree(go_root, work / 'go', symlinks=False)
        env.update(GOROOT=str(work / 'go'), GOEXE=str(work / 'go/bin/go'))
    output = work / 'assets'
    subprocess.run([sys.executable, str(source / 'scripts/build_wsea_release.py'),
        '--version', a.version, '--target', a.target, '--work', str(work / 'build'),
        '--output', str(output), '--exec-prefix-json', json.dumps([qemu])], cwd=source, env=env, check=True)
    archive = output / (a.target + '-wasm-cosign-' + a.version + '.tar.xz')
    packaged = work / 'packaged'
    packaged.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(packaged, filter='data')
    binary = packaged / archive.name.removesuffix('.tar.xz') / 'cosign'
    actual = subprocess.check_output([qemu, str(binary), 'version'], env=env, text=True).strip()
    if actual != 'wasm-cosign ' + a.version + ' WSEA v2':
        raise RuntimeError('packaged target identity differs')
    finish_cgroup(before, work / 'cgroup.json')
    (work / 'qualification.json').write_text(json.dumps({'status': 'PASS', 'target': a.target,
        'source_revision': revision, 'archive_sha256': sha(archive), 'qemu': version.strip(),
        'qemu_sha256': sha(qemu), 'toolchain_manifest_sha256': sha(ROOT / 'scripts/wsea_cross_toolchains.json')}, indent=2) + '\n')
    print('PASS:', a.target, 'actual QEMU product tests and packaged executable', flush=True)


if __name__ == '__main__':
    main()
