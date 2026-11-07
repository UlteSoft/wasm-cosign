#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Build the WSEA WASIp1 and browser/Node SDKs with one pinned crypto reactor.

Toolchains are supplied explicitly; no downloads, Preview 2, emulated entropy,
system OpenSSL, or alternative verifier are permitted. Run under a resource cap.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from prepare_wsea_openssl import load_builder
from wsea_documents import DOCUMENTS

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def header_hashes(directory):
    return {str(p.relative_to(directory)): digest(p) for p in sorted(directory.rglob('*.h'))}


def source_hashes():
    paths = [ROOT / name for name in ('go.mod', 'go.sum', 'wasm/crypto.cc',
        'internal/wseanative/bridge.cc', 'internal/wseanative/bridge.h',
        'internal/wseanative/wsea.h', 'internal/wseanative/wsea.sha256')]
    for directory in ('cmd/wasmcosign', 'internal/wasmsdk', 'internal/wseanative', 'pkg/wasmsecure'):
        paths.extend(p for p in (ROOT / directory).glob('*.go') if not p.name.endswith('_test.go'))
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}


def run(argv, *, cwd=ROOT, env=None):
    print('+', ' '.join(map(str, argv)), flush=True)
    subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--wasi-sdk', type=Path, required=True)
    p.add_argument('--wasm-opt', type=Path, required=True)
    p.add_argument('--output', type=Path, default=ROOT / '.tmp/wsea-wasm')
    p.add_argument('--uwvm-root', type=Path, required=True)
    p.add_argument('--go', default='go')
    p.add_argument('--jobs', type=int, default=3)
    a = p.parse_args()
    if not 1 <= a.jobs <= 8:
        p.error('jobs must be in 1..8')
    sdk, optimizer, out = a.wasi_sdk.resolve(strict=True), a.wasm_opt.resolve(strict=True), a.output.resolve()
    if not out.is_relative_to(ROOT / '.tmp'):
        p.error('generated build output must remain under project .tmp')
    if any(c.isspace() or c in "'\"\\$#" for c in str(out) + str(sdk)):
        p.error('build paths must not contain toolchain metacharacters')
    out.mkdir(parents=True, exist_ok=True)
    scratch = out / 'tmp'
    scratch.mkdir(exist_ok=True)
    for name in ('go-cache', 'go-modules'):
        (out / name).mkdir(exist_ok=True)
    env = os.environ | {'TMPDIR': str(scratch), 'GOTMPDIR': str(scratch), 'GOMAXPROCS': '2', 'SOURCE_DATE_EPOCH': '0',
                        'GOCACHE': str(out / 'go-cache'), 'GOMODCACHE': str(out / 'go-modules')}
    builder = load_builder()
    source = builder.verify_source(ROOT / 'third_party/openssl')
    if source != builder.verify_source(a.uwvm_root / 'third-parties/openssl'):
        raise ValueError('UWVM and cosign OpenSSL sources differ')
    core = ROOT / 'internal/wseanative/wsea.h'
    if (digest(core) != core.with_name('wsea.sha256').read_text().strip() or
        core.read_bytes() != (a.uwvm_root / 'src/uwvm2/utils/security/wsea.h').read_bytes()):
        raise ValueError('UWVM and cosign WSEA cores differ')
    if (ROOT / 'tools/dependencies/build_openssl.py').read_bytes() != (a.uwvm_root / 'tools/dependencies/build_openssl.py').read_bytes():
        raise ValueError('native OpenSSL recipes differ')
    run([sys.executable, ROOT / 'scripts/check_wsea_build.py', '--uwvm-root', a.uwvm_root],
        env=env | {'GOEXE': a.go})
    tools = {name: sdk / 'bin' / name for name in ('clang', 'clang++', 'llvm-ar', 'llvm-ranlib')}
    versions = {name: subprocess.check_output([str(path), '--version'], text=True).splitlines()[0] for name, path in tools.items()}
    go_version = subprocess.check_output([a.go, 'version'], text=True).strip()
    opt_version = subprocess.check_output([str(optimizer), '--version'], text=True).strip()
    # The release toolchain is pinned in wasm/README.md. Do not silently qualify
    # new compilers/optimizers merely because they can emit a WASM binary.
    if 'go1.27.3 ' not in go_version or 'version 23.1.0-wasi-sdk' not in versions['clang'] or opt_version != 'wasm-opt version 133 (version_133)':
        raise ValueError('unqualified compiler; use the documented pinned toolchains')
    crypto = out / 'crypto-build'
    artifacts = out / 'artifacts'
    crypto.mkdir(exist_ok=True)
    artifacts.mkdir(exist_ok=True)
    config = out / 'wsea-wasip1.conf'
    config.write_text('my %targets = ("wsea-wasip1" => { inherit_from => [ "BASE_unix" ], CC => "clang", lib_cppflags => "-DL_ENDIAN", bn_ops => "THIRTY_TWO_BIT" });\n')
    flags = ['no-shared', 'no-tests', 'no-apps', 'no-module', 'no-asm', 'no-async',
             'no-threads', 'no-thread-pool', 'no-sock', 'no-posix-io', 'no-stdio',
             'no-ui-console', 'no-secure-memory', 'no-autoload-config', 'no-dso',
             'no-engine', '--with-rand-seed=getrandom']
    identity = {'source': source, 'core': digest(core), 'versions': versions,
                'tool_hashes': {n: digest(v) for n, v in tools.items()}, 'flags': flags,
                'go': go_version, 'optimizer': opt_version, 'optimizer_sha256': digest(optimizer),
                'recipe_sha256': digest(__file__)}
    receipt = out / 'crypto-receipt.json'
    archive = crypto / 'libcrypto.a'
    cached = json.loads(receipt.read_text()) if receipt.exists() else {}
    # Never reuse an unverified archive after tool/source/configuration drift.
    if (cached.get('identity') != identity or not archive.exists() or cached.get('archive') != digest(archive)
            or cached.get('headers') != header_hashes(crypto / 'include')):
        if any(crypto.iterdir()):
            raise ValueError('crypto cache does not match; choose a fresh output directory')
        crypto_env = env | {'CC': 'clang --target=wasm32-wasip1 -mcpu=mvp',
            'AR': 'llvm-ar', 'RANLIB': 'llvm-ranlib', 'PATH': str(sdk / 'bin') + os.pathsep + os.environ['PATH'],
            'CFLAGS': '-O2 -D_WASI_EMULATED_GETPID', 'LDFLAGS': '-lwasi-emulated-getpid'}
        run(['perl', ROOT / 'third_party/openssl/upstream/Configure', '--config=' + str(config),
             'wsea-wasip1', *flags, '--prefix=/wsea'], cwd=crypto, env=crypto_env)
        run(['make', '-j' + str(a.jobs), 'build_generated'], cwd=crypto, env=crypto_env)
        run(['make', '-j' + str(a.jobs), 'libcrypto.a'], cwd=crypto, env=crypto_env)
        receipt.write_text(json.dumps({'identity': identity, 'archive': digest(archive),
            'headers': header_hashes(crypto / 'include')}, indent=2) + '\n')
    run([tools['clang++'], '--target=wasm32-wasip1', '-mcpu=mvp', '-std=c++20', '-O2', '-fno-exceptions',
        '-ffile-prefix-map=' + str(ROOT) + '=.',
        '-DWSEA_BUNDLED_OPENSSL=30509', '-D_WASI_EMULATED_GETPID',
        '-I' + str(crypto / 'include'), '-I' + str(ROOT / 'third_party/openssl/upstream/include'),
        '-mexec-model=reactor', ROOT / 'wasm/crypto.cc', archive, '-lwasi-emulated-getpid',
        '-Wl,-z,stack-size=1048576', '-Wl,--max-memory=268435456',
        '-o', artifacts / 'wsea-crypto.wasm'], env=env)
    allowed = {'github.com/sigstore/cosign/v3/' + name for name in
        ('cmd/wasmcosign', 'internal/wasmsdk', 'internal/wseanative', 'pkg/wasmsecure')}
    for target, name in [('wasip1', 'wasi'), ('js', 'js')]:
        build_env = env | {'GOOS': target, 'GOARCH': 'wasm', 'CGO_ENABLED': '0'}
        deps = subprocess.check_output([a.go, 'list', '-deps', '-f', '{{if not .Standard}}{{.ImportPath}}{{end}}',
                                       './cmd/wasmcosign'], env=build_env, cwd=ROOT, text=True)
        if set(deps.split()) != allowed:
            raise ValueError('unexpected WASM production dependency graph: ' + deps)
        run([a.go, 'build', '-p=2', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o',
             artifacts / ('wasm-cosign-' + name + '.wasm'), './cmd/wasmcosign'], env=build_env)
    for name in ('wsea-crypto.wasm', 'wasm-cosign-wasi.wasm', 'wasm-cosign-js.wasm'):
        binary = artifacts / name
        lowered = scratch / name
        # Go may emit sign-extension/bulk-memory operations. Lower to MVP before
        # strict validation; no threads, reference types, SIMD, GC or EH enabled.
        run([optimizer, binary, '--enable-sign-ext', '--enable-bulk-memory-opt', '--enable-nontrapping-float-to-int',
             '--signext-lowering', '--llvm-memory-copy-fill-lowering',
             '--llvm-nontrapping-fptoint-lowering', '--strip-target-features', '-o', lowered], env=env)
        run([optimizer, lowered, '--mvp-features', '-o', binary], env=env)
    goroot = Path(subprocess.check_output([a.go, 'env', 'GOROOT'], text=True).strip())
    shutil.copyfile(goroot / 'lib/wasm/wasm_exec.js', artifacts / 'wasm_exec.js')
    shutil.copyfile(ROOT / 'wasm/LICENSE-Go', artifacts / 'LICENSE-Go')
    for name in ('loader.mjs', 'run-json.mjs', 'run.py'):
        if (ROOT / 'wasm' / name).exists():
            shutil.copyfile(ROOT / 'wasm' / name, artifacts / name)
    for name in DOCUMENTS:
        destination = artifacts / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    shutil.copyfile(ROOT / 'LICENSE', artifacts / 'LICENSE')
    shutil.copyfile(ROOT / 'third_party/openssl/upstream/LICENSE.txt', artifacts / 'LICENSE-OpenSSL')
    (out / 'wasm-receipt.json').write_text(json.dumps({'identity': identity, 'source_files': source_hashes(),
        'artifacts': {str(v.relative_to(artifacts)): digest(v) for v in sorted(artifacts.rglob('*'))
                      if v.is_file()}}, indent=2) + '\n')
    print('PASS: shared WSEA, pinned OpenSSL, WASIp1-only, strict MVP validation', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as e:
        sys.exit('WSEA WASM build: ' + str(e))
