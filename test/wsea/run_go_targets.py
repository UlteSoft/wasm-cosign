#!/usr/bin/env python3
"""Qualify static production secure commands on real Linux QEMU targets.

Run only inside the existing authorized cgroup. A completed UWVM target record
supplies the exact actual QEMU/loader/runtime contract; no host substitution,
global installation, trust modification or cgroup configuration is performed.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


PROFILES = {
    'x86_64': {'GOARCH': 'amd64', 'GOAMD64': 'v1'},
    'i686': {'GOARCH': '386', 'GO386': 'sse2'},
    'aarch64': {'GOARCH': 'arm64'},
    'arm': {'GOARCH': 'arm', 'GOARM': '5'},
    'armhf': {'GOARCH': 'arm', 'GOARM': '7'},
    'ppc64': {'GOARCH': 'ppc64', 'GOPPC64': 'power8'},
    'mips64': {'GOARCH': 'mips64', 'GOMIPS64': 'hardfloat'},
    'loongarch64': {'GOARCH': 'loong64'},
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--targets', default=','.join(PROFILES))
    parser.add_argument('--revision', required=True)
    parser.add_argument('--cohort', type=Path)
    parser.add_argument('--cg-limit-mib', type=int, default=32768)
    parser.add_argument('--full-cosign', action='store_true', help='Build and execute the full cosign command tree')
    parser.add_argument('--dependency-proxy', help='Optional HTTPS CONNECT proxy for authenticated module downloads')
    args = parser.parse_args()
    root = args.workspace.resolve(strict=True)
    code_root = (args.cohort or root).resolve(strict=True)
    if os.uname().sysname != 'Linux' or not args.revision.isidentifier():
        raise RuntimeError('Linux and an explicit simple output revision required')
    targets = args.targets.split(',')
    if not set(targets) <= PROFILES.keys():
        raise ValueError('standard Go has no armeb/aarch64_be Linux port')
    out = root / ('go-targets-' + args.revision)
    out.mkdir(mode=0o700, exist_ok=False)
    source = root / ('wasm-cosign-full' if args.full_cosign else 'wasm-cosign')
    report = {'status': 'IN_PROGRESS', 'driver_sha256': sha(__file__), 'rows': [],
              'scope': ('actual full static cosign binary and wasm secure command tree' if args.full_cosign
                        else 'actual static secure Cobra command, not full cloud-provider cosign binary'),
              'unsupported_go_targets': ['armeb', 'aarch64_be'],
              'source_sha256': {str(p.relative_to(source)): sha(p)
                  for directory in ['pkg/wasmsecure', 'cmd/cosign/cli/wasmsecure']
                  for p in (source / directory).glob('*.go') if not p.name.endswith('_test.go')}}
    report['source_sha256']['test/wsea/cli_main.go'] = sha(source / 'test/wsea/cli_main.go')
    index = out / 'report.json'

    def save():
        index.write_text(json.dumps(report, indent=2) + '\n')

    environment = dict(os.environ, GOENV='off', GOTOOLCHAIN='local', GOOS='linux',
        GOMAXPROCS='2', GOMEMLIMIT='512MiB', CGO_ENABLED='0', GOPROXY='off',
        GOCACHE=str(root / 'go-cache'), GOMODCACHE=str(root / 'full-go-mod'),
        TMPDIR=str(root / 'tmp'), GOTMPDIR=str(root / 'tmp'))
    if args.dependency_proxy:
        environment.update(HTTPS_PROXY=args.dependency_proxy, HTTP_PROXY=args.dependency_proxy,
                           NO_PROXY='localhost,127.0.0.1', GOPROXY='https://proxy.golang.org',
                           GOSUMDB='sum.golang.org')
    subcommands = ['wasm', 'secure'] if args.full_cosign else []
    go = '/home/macromodel/Documents/uwvm-test-261018/wsea/go-toolchain/go/bin/go'
    report['go_toolchain_binary_sha256'] = sha(go)

    def stage(name, command, cwd, env, timeout):
        receipt = out / (name + '.json')
        argv = ['python3', str(code_root / 'source/tests/security_wsea/run_bounded_v2.py'),
            '--disk-root', str(root), '--cg-limit-mib', str(args.cg_limit_mib), '--report', str(receipt), '--cwd', str(cwd),
            '--timeout', str(timeout), '--', *map(str, command)]
        print(json.dumps({'stage': name, 'state': 'START'}), flush=True)
        if name.startswith('build-'):
            with (root / 'build-admission.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                code = subprocess.run(argv, env=env).returncode
        else:
            code = subprocess.run(argv, env=env).returncode
        if code:
            raise RuntimeError('retained failing Go target stage: ' + str(receipt))
        return receipt

    try:
        for target in targets:
            env = dict(environment, **PROFILES[target])
            binary = out / (('cosign-' if args.full_cosign else 'wsea-') + target)
            stage('build-' + target, [go, 'build', '-p=1', '-trimpath', '-ldflags=-s -w',
                  '-o', binary, './cmd/cosign' if args.full_cosign else './test/wsea/cli_main.go'], source, env, 900)
            deadline = time.monotonic() + 21600
            chosen = None
            while chosen is None:
                for inventory in sorted(root.glob('qualification-products-*.json'), reverse=True):
                    inventory_bytes = inventory.read_bytes()
                    try:
                        data = json.loads(inventory_bytes)
                    except json.JSONDecodeError:
                        continue
                    if data.get('source_header_sha256') != sha(code_root / 'source/src/uwvm2/utils/security/wsea.h'):
                        continue
                    for row in data.get('rows', []):
                        if row['target'] == target:
                            build = json.loads(Path(row['build']).read_text())
                            if (build.get('status') != 'PASS' or Path(build['plan']['source']).resolve() !=
                                    (code_root / 'repositories' / row['repository']).resolve()):
                                continue
                            matrix = json.loads(Path(row['matrix']).read_text())
                            if (matrix.get('status') == 'PASS' and matrix['vm']['sha256'] == row['binary_sha256']
                                    and sha(matrix['vm']['path']) == row['binary_sha256']):
                                chosen = (row, matrix, inventory_bytes)
                                break
                    if chosen:
                        break
                if chosen is None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('no qualified actual UWVM target: ' + target)
                    time.sleep(10)
            row, matrix, inventory_bytes = chosen
            (out / ('product-input-' + target + '.json')).write_bytes(inventory_bytes)
            wrapper = list(matrix['exec_prefix'])
            go_wrapper = wrapper[:-3] if matrix['qemu'].get('explicit_target_loader') else wrapper
            interop = out / ('interop-' + target)
            command = ['python3', root / 'wasm-cosign/test/wsea/algorithm_interop.py',
                '--matrix-driver', code_root / 'source/tests/security_wsea/algorithm_matrix.py',
                '--fixtures', root / 'fixtures-final', '--go-cli', binary,
                '--go-exec-prefix-json', json.dumps(go_wrapper),
                '--go-subcommands-json', json.dumps(subcommands),
                '--runner', matrix['runner'], '--vm', matrix['vm']['path'], '--target', target,
                '--execution', 'qemu', '--exec-prefix-json', json.dumps(wrapper),
                '--target-sysroot', matrix['sysroot'], '--runtime-root', matrix['runtime_root'],
                '--runtime-receipt', matrix['runtime_receipt']['path'],
                '--output', interop, '--require-cgroup']
            stage('execute-' + target, command, source, environment, 1800)
            usage = out / ('usage-' + target)
            stage('usage-' + target, ['python3', code_root / 'source/tests/security_wsea/embedded_usage.py',
                '--fixtures', root / 'fixtures-final', '--go-cli', binary,
                '--go-prefix-json', json.dumps(go_wrapper),
                '--go-subcommands-json', json.dumps(subcommands), '--vm', matrix['vm']['path'],
                '--exec-prefix-json', json.dumps(wrapper), '--output', usage], source, environment, 300)
            report['rows'].append({'target': target, 'go_environment': PROFILES[target],
                'binary_sha256': sha(binary), 'product': row,
                'interop': str(interop / 'interop-report.json'), 'usage': str(usage / 'report.json')})
            save()
        report['status'] = 'PASS'
    except BaseException as error:
        report['status'] = 'FAIL'
        report['error'] = repr(error)
        raise
    finally:
        save()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
