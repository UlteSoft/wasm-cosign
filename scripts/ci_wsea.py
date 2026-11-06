#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Qualify source-built WSEA WASM in UWVM, Wasmtime and Node before packaging is published."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = ['./cmd/cosign', './cmd/wasmcosign', './internal/wasmcli',
            './internal/wasmsdk', './internal/wseanative', './pkg/wasmsecure',
            './cmd/cosign/cli/wasmsecure']


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('uwvm-root', 'tools', 'work'):
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--version', help='package and test the extracted release archives')
    p.add_argument('--fetch-tools', action='store_true')
    p.add_argument('--uwvm-cxx', type=Path, help='explicit qualified LLVM 22.1.8 compiler')
    a = p.parse_args()
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    u, work, tools = a.uwvm_root.resolve(), a.work.resolve(), a.tools.resolve()
    if not work.is_relative_to(ROOT / '.tmp'):
        p.error('qualification output must remain under project .tmp')
    work.mkdir(parents=True, exist_ok=False)
    for name in ('tmp', 'go-cache', 'go-modules'):
        (work / name).mkdir()
    os.environ.update(TMPDIR=str(work / 'tmp'), GOTMPDIR=str(work / 'tmp'),
                      GOCACHE=str(work / 'go-cache'), GOMODCACHE=str(work / 'go-modules'),
                      GOMAXPROCS='2', WSEA_OPENSSL_JOBS='3', PYTHONDONTWRITEBYTECODE='1',
                      GOTOOLCHAIN='local')
    probe_path = u / 'test/0073.ros-tests/support/source/ros_cgroup/probe.py'
    spec = importlib.util.spec_from_file_location('wsea_cgroup_probe', probe_path)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    before = probe.probe()
    if before['status'] != 'PASS':
        raise RuntimeError('64 GiB zero-swap cgroup admission failed: ' + json.dumps(before))

    def run(name, argv, timeout=1800):
        print('RUN', name, flush=True)
        log = work / (name + '.log')
        with log.open('wb') as stream:
            try:
                subprocess.run(list(map(str, argv)), cwd=ROOT, stdout=stream,
                               stderr=subprocess.STDOUT, check=True, timeout=timeout)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                sys.stderr.write(log.read_text(errors='replace')[-16000:])
                raise
        print('PASS', name, flush=True)

    run('documents', [sys.executable, 'scripts/check_wsea_docs.py'])
    run('release-gates', [sys.executable, 'test/wsea/release_packaging_test.py'])
    if a.fetch_tools:
        run('tools', [sys.executable, 'scripts/fetch_wsea_toolchains.py', '--output', tools])
    os.environ['PATH'] = str(tools / 'wasmtime') + os.pathsep + os.environ['PATH']
    cxx = a.uwvm_cxx or tools / 'llvm/bin/clang++'
    if '22.1.8' not in subprocess.check_output([str(cxx), '--version'], text=True):
        raise RuntimeError('UWVM CI compiler must be qualified LLVM 22.1.8')
    if '42.0.1' not in subprocess.check_output(['wasmtime', '--version'], text=True):
        raise RuntimeError('Wasmtime must be 42.0.1')
    if subprocess.check_output(['node', '--version'], text=True).strip() != 'v22.22.3':
        raise RuntimeError('Node must be 22.22.3')
    expected = (ROOT / 'scripts/wsea_uwvm_revision.txt').read_text().strip()
    revision = subprocess.check_output(['git', '-C', str(u), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != expected or subprocess.check_output(['git', '-C', str(u), 'status', '--porcelain']):
        raise RuntimeError('counterpart must be the clean pinned UWVM revision')
    run('shared-source', [sys.executable, 'scripts/check_wsea_build.py', '--uwvm-root', u])
    crypto = work / 'openssl'
    os.environ.update(WSEA_OPENSSL_ROOT=str(crypto), PKG_CONFIG_PATH=str(crypto / 'pkgconfig'),
                      PKG_CONFIG_LIBDIR=str(crypto / 'pkgconfig'), PKG_CONFIG_SYSROOT_DIR='')
    run('native-openssl', [sys.executable, 'scripts/prepare_wsea_openssl.py'])
    os.environ['CGO_CPPFLAGS'] = (crypto / 'cgo-cppflags').read_text().strip()
    run('unit-tests', ['go', 'test', '-p=2', '-count=1', '-timeout=10m', *PACKAGES])
    run('native-cosign', ['go', 'build', '-p=2', '-trimpath', '-o', work / 'cosign', './cmd/cosign'])
    source = u / 'test/0073.ros-tests/support/source/security_wsea'
    for src, name in [('algorithm_matrix_runner.cpp', 'verifier'), ('algorithm_fixture_signer.cpp', 'variant-signer')]:
        run(name, ['c++', '-std=c++20', '-O2', '-DUWVM_WSEA_OPENSSL=1', '-I' + str(u / 'src'),
                   '-I' + str(crypto / 'include'), source / src, crypto / 'libcrypto.a',
                   '-pthread', '-ldl', '-o', work / name])
    common = [str(cxx), '-std=c++2c', '-O1', '-g0', '-ferror-limit=2', '-Wno-undefined-inline',
              '-Wno-braced-scalar-init', '-DUWVM=2', '-DUWVM_USE_UWVM_INT', '-DUWVM_DISABLE_JIT',
              '-DUWVM_IMPORT_WASI', '-DUWVM_WSEA_OPENSSL=1', '-DUWVM_USE_THREAD_LOCAL=1',
              '-DUWVM_VERSION_X=2', '-DUWVM_VERSION_Y=0', '-DUWVM_VERSION_Z=3', '-DUWVM_VERSION_S=0',
              '-I' + str(crypto / 'include')]
    common += ['-I' + str(u / v) for v in ('src', 'third-parties/fast_io/include',
                                         'third-parties/bizwen/include', 'third-parties/boost_unordered/include')]
    objects = []
    for name, src in [('main', 'src/uwvm2/uwvm/main.default.cpp'),
                      ('runtime', 'src/uwvm2/runtime/lib/uwvm_runtime.default.cpp'),
                      ('host', 'src/uwvm2/uwvm/host_api.default.cpp')]:
        obj = work / (name + '.o')
        run('uwvm-' + name, [*common, '-c', u / src, '-o', obj])
        objects.append(obj)
    uwvm = work / 'uwvm'
    run('uwvm-link', [cxx, *objects, crypto / 'libssl.a', crypto / 'libcrypto.a',
                      '-pthread', '-ldl', '-lm', '-o', uwvm])
    run('uwvm-version', [uwvm, '--version'])
    run('wasm-build', [sys.executable, 'scripts/build_wsea_wasm.py', '--wasi-sdk', tools / 'wasi-sdk',
                       '--wasm-opt', tools / 'binaryen/bin/wasm-opt', '--uwvm-root', u,
                       '--output', work / 'wasm', '--jobs', '3'])
    assets = work / 'wasm/artifacts'
    if a.version:
        run('package', [sys.executable, 'scripts/package_wsea_wasm.py', '--artifacts', assets,
                         '--output', work / 'release', '--version', a.version, '--uwvm-root', u])
        # Qualify the exact archived bytes; never replace them with build-tree files.
        assets = work / 'archive-runtime'
        assets.mkdir()
        for archive in sorted((work / 'release').glob('*.tar.xz')):
            with tarfile.open(archive) as tar:
                for member in tar:
                    parts = Path(member.name).parts
                    if not member.isfile() or len(parts) < 2 or '..' in parts:
                        raise RuntimeError('unexpected release member')
                    if parts[-1] == 'RELEASE.json':
                        continue
                    dest = assets.joinpath(*parts[1:])
                    data = tar.extractfile(member).read()
                    if dest.exists() and dest.read_bytes() != data:
                        raise RuntimeError('common release file differs between targets')
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(data)
    run('fixtures', [sys.executable, source / 'algorithm_matrix.py', '--prepare',
                     '--ed-variant-signer', work / 'variant-signer', '--output', work / 'fixtures', '--require-cgroup'])
    base = ['--assets', assets, '--fixtures', work / 'fixtures']
    run('matrix', [sys.executable, 'test/wsea/wasm_interop.py', *base, '--uwvm-root', u,
                   '--native-verifier', work / 'verifier', '--uwvm', uwvm, '--output', work / 'matrix'])
    run('signing', [sys.executable, 'test/wsea/wasm_signing.py', *base, '--native-verifier', work / 'verifier',
                    '--native-cosign', work / 'cosign', '--uwvm', uwvm, '--output', work / 'signing'])
    run('host-security', [sys.executable, 'test/wsea/wasm_host_security.py', *base, '--output', work / 'host-security'])
    after = probe.probe()
    if after['status'] != 'PASS' or after['cgroup_incarnation'] != before['cgroup_incarnation']:
        raise RuntimeError('cgroup changed during qualification')
    for old, new in zip(before['cgroup_ancestors'], after['cgroup_ancestors'], strict=True):
        for row in (old, new):
            row['events'] = dict(line.split() for line in (row.get('memory.events') or '').splitlines())
        if any(old['events'].get(k) != new['events'].get(k) for k in ('oom', 'oom_kill', 'oom_group_kill')):
            raise RuntimeError('OOM counters changed')
    (work / 'qualification.json').write_text(json.dumps({'status': 'PASS', 'uwvm_revision': revision,
        'version': a.version, 'cgroup_before': before, 'cgroup_after': after}, indent=2) + '\n')
    print('PASS: paired source, native tests, strict MVP, 277 matrix cases, 76 signing checks, 13 host-security checks', flush=True)


if __name__ == '__main__':
    main()
