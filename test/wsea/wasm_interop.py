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
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]


def b64(data):
    return base64.b64encode(data).decode('ascii')


class Stream:
    def __init__(self, name, argv, output):
        self.name = name
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

    def request(self, req):
        return json.loads(self.line(json.dumps(req, separators=(',', ':')).encode()))

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
    probe_file = a.uwvm_root / 'test/0073.ros-tests/support/source/ros_cgroup/probe.py'
    spec = importlib.util.spec_from_file_location('cgroup_probe', probe_file)
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    before = probe.probe()
    if before['status'] != 'PASS':
        raise RuntimeError('64 GiB zero-swap cgroup is required: ' + json.dumps(before))
    assets = a.assets.resolve()
    cmds = {'wasmtime': ['wasmtime', 'run', '--preload', 'wsea_crypto=' + str(assets / 'wsea-crypto.wasm'),
                         str(assets / 'wasm-cosign-wasi.wasm'), '--stream'],
            'node': ['node', str(ROOT / 'wasm/run-json.mjs'), str(assets), '--stream']}
    if a.uwvm:
        host_spec = importlib.util.spec_from_file_location('wsea_host', ROOT / 'wasm/run.py')
        host = importlib.util.module_from_spec(host_spec)
        host_spec.loader.exec_module(host)
        cmds['uwvm'] = host.command('uwvm', str(a.uwvm.resolve()), assets) + ['--stream']
    engines = [Stream(n, cmds[n], out) for n in a.engines.split(',')]
    native = Stream('native', [str(a.native_verifier.resolve()), '--batch'], out)
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
    try:
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
    finally:
        for engine in [*engines, native]:
            engine.close()
    after = probe.probe()
    (out / 'cgroup.json').write_text(json.dumps({'before': before, 'after': after}, indent=2) + '\n')
    (out / 'artifacts.json').write_text(json.dumps({v.name: hashlib.sha256(v.read_bytes()).hexdigest()
        for v in assets.iterdir() if v.is_file()}, indent=2) + '\n')
    if after['status'] != 'PASS':
        raise RuntimeError('lost required cgroup')
    print(json.dumps({'status': 'PASS', 'cases': len(records), 'engines': a.engines.split(',')}), flush=True)


if __name__ == '__main__':
    main()
