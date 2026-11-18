#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Execute the production WSEA corpus through WASM and UWVM's native verifier.

Generated keys, state and results must be outside tracked source. Grouped state
is preserved: native UWVM commits happen only AFTER each WASM snapshot check.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from wsea_cross_support import cgroup_snapshot, finish_cgroup


def b64(data):
    return base64.b64encode(data).decode('ascii')


class Stream:
    def __init__(self, name, argv, output):
        self.name = name
        self.argv = list(argv)
        self.log = (output / (name + '.stderr.log')).open('wb')
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, bufsize=0)
        self.select = selectors.DefaultSelector()
        self.select.register(self.p.stdout, selectors.EVENT_READ)
        self.pending = b''

    def line(self, data, timeout=600):
        self.p.stdin.write(data + b'\n')
        self.p.stdin.flush()
        deadline = time.monotonic() + timeout
        while b'\n' not in self.pending:
            if not self.select.select(max(0, deadline - time.monotonic())):
                raise RuntimeError(self.name + ' timed out; inspect runtime stderr')
            chunk = os.read(self.p.stdout.fileno(), 65536)
            if not chunk:
                raise RuntimeError(self.name + ' terminated without response; inspect runtime stderr')
            self.pending += chunk
            if len(self.pending) > 96 << 20:
                raise RuntimeError('unbounded runtime response')
        result, self.pending = self.pending.split(b'\n', 1)
        return result

    def request(self, req, check_contract=False):
        request = json.dumps(req, separators=(',', ':')).encode()
        response = self.line(request)
        if check_contract:
            self.check_contract(request, response)
        return json.loads(response)

    def check_contract(self, request, response):
        def envelope(q, r):
            return json.dumps({'request': b64(q), 'response': b64(r)}, separators=(',', ':')).encode()
        invalid_time = json.loads(response)
        invalid_time['valid_until'] = invalid_time['checked_at']
        malformed_response = json.dumps(invalid_time, separators=(',', ':')).encode()
        cases = [('--validate-request', request, True),
                 ('--validate-request', b'{"schema":"wsea-sdk-1","schema":"wsea-sdk-1"}', False),
                 ('--validate-response', response, True),
                 ('--validate-response', malformed_response, False),
                 ('--validate-exchange', envelope(request, response), True),
                 ('--validate-exchange', envelope(request + b' ', response), False)]
        for mode, data, expected in cases:
            result = subprocess.run(self.argv[:-1] + [mode], input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=120)
            if result.stdout or (result.returncode == 0) != expected:
                raise RuntimeError(f'{self.name} {mode}: unexpected validator result: {result.stderr!r}')
            if not expected and (result.returncode != 1 or
                    (self.name == 'node' and result.stderr) or
                    (self.name != 'node' and b'SDK_001: invalid contract document' not in result.stderr)):
                raise RuntimeError(f'{self.name} {mode}: validator failed instead of rejecting: {result.stderr!r}')

    def close(self):
        self.p.stdin.close()
        try:
            status = self.p.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
            raise RuntimeError(self.name + ' did not exit after EOF')
        finally:
            self.log.close()
            self.select.close()
        if status:
            raise RuntimeError(self.name + ' failed at exit: ' + str(status))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('assets', 'fixtures', 'native-verifier', 'uwvm-root', 'output'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--uwvm', type=Path)
    parser.add_argument('--engines', default='wasmtime,node,uwvm')
    a = parser.parse_args()
    out = a.output.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.umask(0o077)
    temporary_receipt_dir = None
    if out.is_relative_to(ROOT / '.tmp'):
        receipt = out / 'cgroup.json'
    else:
        scratch = ROOT / '.tmp'
        scratch.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary_receipt_dir = Path(tempfile.mkdtemp(prefix='wasm-interop-cgroup-', dir=scratch))
        receipt = temporary_receipt_dir / 'cgroup.json'
    try:
        before = cgroup_snapshot()
    except BaseException:
        if temporary_receipt_dir is not None:
            temporary_receipt_dir.rmdir()
        raise
    try:
        if temporary_receipt_dir is not None:
            print('cgroup receipt:', receipt, file=sys.stderr, flush=True)
        cases = execute(a, out)
    finally:
        finish_cgroup(before, receipt)
    print(json.dumps({'status': 'PASS', 'cases': cases, 'engines': a.engines.split(',')}), flush=True)


def execute(a, out):
    assets = a.assets.resolve()
    cmds = {'wasmtime': ['wasmtime', 'run', '--preload', 'wsea_crypto=' + str(assets / 'wsea-crypto.wasm'),
                         str(assets / 'wasm-cosign-wasi.wasm'), '--stream'],
            'node': ['node', str(ROOT / 'wasm/run-json.mjs'), str(assets), '--stream']}
    if a.uwvm:
        host_spec = importlib.util.spec_from_file_location('wsea_host', ROOT / 'wasm/run.py')
        host = importlib.util.module_from_spec(host_spec)
        host_spec.loader.exec_module(host)
        cmds['uwvm'] = host.command('uwvm', str(a.uwvm.resolve()), assets) + ['--stream']
    with ExitStack() as streams:
        def managed_stream(name, argv):
            stream = Stream(name, argv, out)
            streams.callback(stream.close)
            return stream

        engines = [managed_stream(n, cmds[n]) for n in a.engines.split(',')]
        native = managed_stream('native', [str(a.native_verifier.resolve()), '--batch'])
        fixtures = json.loads((a.fixtures / 'fixtures.json').read_text())
        if (fixtures.get('schema') != 'uwvm-wsea-algorithm-matrix-v2' or fixtures.get('source_revision') != 'embedded-v2'
                or fixtures.get('producer_constraints') or len(fixtures['algorithms']) != 13 or len(fixtures['cases']) < 277):
            raise RuntimeError('complete algorithm corpus with all adversarial producers required')
        for key, filename in [('source_sha256', 'algorithm_matrix.py'), ('runner_source_sha256', 'algorithm_matrix_runner.cpp')]:
            source = a.uwvm_root / 'test/0073.ros-tests/support/source/security_wsea' / filename
            if hashlib.sha256(source.read_bytes()).hexdigest() != fixtures[key]:
                raise RuntimeError('fixture producer or native runner differs from qualified source')
        for path, expected in fixtures['files_sha256'].items():
            if hashlib.sha256((a.fixtures / path).read_bytes()).hexdigest() != expected:
                raise RuntimeError('fixture content differs from producer manifest: ' + path)
        groups = {}
        records = []
        for case in fixtures['cases']:
            group = case['group']
            if group not in groups:
                directory = out / ('state-' + hashlib.sha256(group.encode()).hexdigest()[:20])
                directory.mkdir(mode=0o700)
                (directory / 'state').write_text('UWVM-WSEA-STATE-1\n0 0 -\n')
                (directory / 'state').chmod(0o600)
                groups[group] = directory
            directory = groups[group]
            policy = case['policy'].replace('@STATE_DIR@', str(directory))
            path = directory / 'policy'
            path.write_text(policy)
            path.chmod(0o600)
            root = next((v[11:] for v in policy.splitlines() if v.startswith('trust_root=')), case['pki']['root'])
            # Invalid paths are rejected by ParsePolicy; do not let a fixture
            # supply ambient trust if its actual policy path points elsewhere.
            roots = Path(root).read_bytes() if Path(root).is_file() else b'invalid root'
            req = {'schema': 'wsea-sdk-1', 'operation': 'verify', 'module': b64(Path(case['module']).read_bytes()),
                   'trust': {'policy': b64(policy.encode()), 'roots': b64(roots), 'state': b64((directory / 'state').read_bytes()),
                             'revoked_spkis': sorted(v.name[8:] for v in directory.glob('revoked-*'))}}
            answers = {}
            start = time.monotonic()
            for engine in engines:
                answer = engine.request(req)
                allowed = answer['status'] == 'VERIFIED_SNAPSHOT'
                if allowed != (case['expected'] == 'ALLOW'):
                    raise RuntimeError(f'{engine.name}: {case["name"]}: expected {case["expected"]}, got {answer}')
                answers[engine.name] = answer
            result = native.line((str(path) + '\t' + case['module'] + '\t').encode()).decode()
            expected = result == '0\tALLOW'
            if expected != (case['expected'] == 'ALLOW'):
                raise RuntimeError(f'native: {case["name"]}: {result}')
            records.append({'case': case['name'], 'expected': case['expected'], 'answers': answers,
                            'native': result, 'elapsed': time.monotonic() - start})
            (out / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
            print('PASS', len(records), case['name'], flush=True)
    (out / 'artifacts.json').write_text(json.dumps({v.name: hashlib.sha256(v.read_bytes()).hexdigest()
        for v in assets.iterdir() if v.is_file()}, indent=2) + '\n')
    return len(records)


if __name__ == '__main__':
    main()
