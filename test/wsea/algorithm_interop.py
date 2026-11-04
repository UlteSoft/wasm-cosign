#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Real multi-algorithm OpenSSL -> Go -> C++/VM interoperability on Linux.

Imports only the supplied matrix-driver source; it never builds a candidate.
The C++/VM argv wrapper, ELF identity, byte order, pointer width, sysroot and
runtime receipt are checked by the shared matrix Execution class. A native Go
CLI remains a host-side independent verifier and signature producer, not a
substitute for executing the target C++ binary under QEMU.
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--matrix-driver', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--go-cli', type=Path, required=True)
    parser.add_argument('--go-exec-prefix-json', default='[]', help='Actual target QEMU argv for a cross-built static Go CLI')
    parser.add_argument('--go-subcommands-json', default='[]', help='[] for cli_main.go; ["wasm","secure"] for full cosign')
    parser.add_argument('--runner', type=Path, required=True)
    parser.add_argument('--vm', type=Path, help='actual full guest-executing target VM, not a loader probe')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--execution', choices=['qemu', 'native'], default='qemu')
    parser.add_argument('--exec-prefix-json', default='[]')
    parser.add_argument('--target-sysroot', type=Path, required=True)
    parser.add_argument('--runtime-root', type=Path, required=True)
    parser.add_argument('--runtime-receipt', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--require-cgroup', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    if sys.platform != 'linux':
        print('BLOCKED: execute only inside the authorized SSH Linux cgroup', file=sys.stderr)
        return 77
    spec = importlib.util.spec_from_file_location('wsea_matrix_contract', args.matrix_driver.resolve(strict=True))
    matrix = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(matrix)
    if args.target not in matrix.TARGETS:
        parser.error('target must be one of ' + ','.join(matrix.TARGETS))
    before = matrix.cgroup_snapshot(args.require_cgroup)
    execution = matrix.Execution(args)
    execution.report.update(interop_driver_sha256=matrix.sha(__file__), go_cli_sha256=matrix.sha(args.go_cli),
        scope='Host Go CLI independent verification/signing plus actual target C++/optional guest-executing VM',
        started_unix=int(time.time()))
    subcommands = json.loads(args.go_subcommands_json)
    if not isinstance(subcommands, list) or not all(isinstance(x, str) for x in subcommands):
        parser.error('--go-subcommands-json must be a string argv array')
    go_wrapper = json.loads(args.go_exec_prefix_json)
    if not isinstance(go_wrapper, list) or not all(isinstance(x, str) for x in go_wrapper):
        parser.error('--go-exec-prefix-json must be a string argv array')
    go_elf = matrix.elf_identity(args.go_cli)
    if go_wrapper:
        expected = matrix.TARGETS[args.target]
        if (go_elf['machine'], go_elf['bits'], go_elf['byte_order']) != expected[:3]:
            raise RuntimeError('Go CLI ELF does not match the emulated target')
        qemu = execution.report.get('qemu')
        if not qemu or qemu['path'] not in [str(Path(x).resolve()) for x in go_wrapper if x.startswith('/') and Path(x).is_file()]:
            raise RuntimeError('Go CLI must execute through the same recorded target QEMU')
        if go_elf.get('interpreter'):
            raise RuntimeError('cross Go CLI qualification requires its actual static executable')
    execution.report['go_cli_execution'] = {'elf': go_elf, 'exec_prefix': go_wrapper,
        'scope': 'actual target static Go secure command' if go_wrapper else 'host Go secure command'}
    go_prefix = [*go_wrapper, str(args.go_cli.resolve(strict=True)), *subcommands]
    manifest_path = args.fixtures.resolve(strict=True) / 'fixtures.json'
    fixtures = json.loads(manifest_path.read_text())
    records = execution.records

    def record(name, command, *, expect='ALLOW', codes=(), cpp=False, vm=False, guest_marker=None):
        process = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=args.timeout)
        output = process.stdout + process.stderr
        expected_exit_codes = [0] if expect == 'ALLOW' else [126, 127] if vm else [2] if cpp else [1]
        passed = process.returncode in expected_exit_codes and (not cpp or process.stdout.strip() == 'ALLOW') if expect == 'ALLOW' else (
            process.returncode in expected_exit_codes and (not codes or any(code in output for code in codes)) and
            (not cpp or process.returncode == 2 and process.stdout.startswith('DENY ')))
        if guest_marker:
            passed = passed and (guest_marker in process.stdout if expect == 'ALLOW' else matrix.GUEST_PREFIX not in output)
        row = {'name': name, 'argv': list(map(str, command)), 'expected': expect, 'codes': list(codes),
               'returncode': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr, 'passed': passed,
               'expected_exit_codes': expected_exit_codes,
               'required_guest_marker': guest_marker}
        records.append(row)
        print('PASS' if passed else 'FAIL', name, flush=True)
        return passed

    def cpp(name, policy, module, allow=True, codes=(), guest_marker=None):
        record(name, [*execution.prefix, execution.runner, policy, module], expect='ALLOW' if allow else 'DENY', codes=codes, cpp=True)
        if args.vm:
            record(name + ' target VM', [*execution.prefix, args.vm, '--secure', 'module', module, policy, '--run', module],
                   expect='ALLOW' if allow else 'DENY', codes=codes, vm=True, guest_marker=guest_marker)

    def policy_rule(path):
        rules = [line.removeprefix('module=').split('|') for line in path.read_text().splitlines() if line.startswith('module=')]
        if len(rules) != 1:
            raise RuntimeError('expected exactly one scoped policy rule')
        return rules[0]

    def go_policy(name, fixture, algorithm=None):
        directory = execution.out / 'go-policies' / name
        directory.mkdir(mode=0o700, parents=True)
        policy = directory / 'policy'
        ca = fixture['pki']
        command = [*go_prefix, 'policy-init', '--output', policy, '--trust-root', ca['root'],
            '--state-dir', directory / 'state', '--certificate', ca['certificate'], '--module-id', 'matrix.app',
            '--minimum-version', '1', '--minimum-epoch', '0', '--capabilities', str(fixture.get('capabilities', 0))]
        if algorithm is not None:
            command += ['--algorithms', algorithm]
        if not record(name + ' Go policy-init', command):
            raise RuntimeError('policy initialization fixture failed')
        return policy

    try:
        if fixtures['schema'] != matrix.SCHEMA:
            raise RuntimeError('wrong matrix fixture schema')
        if (fixtures.get('source_revision') != 'embedded-v2' or set(fixtures['algorithms']) != set(matrix.ALGORITHMS) or
                set(fixtures.get('guest_algorithms', {})) != set(matrix.ALGORITHMS) or not fixtures['cases']):
            raise RuntimeError('fixture manifest is missing required algorithm coverage')
        for rel, expected in fixtures['files_sha256'].items():
            if matrix.sha(args.fixtures / rel) != expected:
                raise RuntimeError('frozen fixture changed: ' + rel)
        execution.report['fixtures_sha256'] = matrix.sha(manifest_path)
        execution.report['fixture_generator_sha256'] = fixtures['source_sha256']
        # Go independently verifies the cryptography, while CheckState remains
        # read-only by design. State-transition groups start fresh and explicitly
        # learn/commit through the actual target between successive Go checks.
        # They never borrow state left by a standalone matrix execution.
        seeded_revocations = set()
        execution.report['go_state_contract'] = ('Go checks are read-only. Actual target C++ commits successful policy upgrades '
            'and learns authenticated revocations in fresh interop-only groups before subsequent Go rollback/replay checks.')
        for case in fixtures['cases']:
            go_case = dict(case, group='go-adversarial-' + case['group'])
            policy = execution.policy(go_case)
            record('OpenSSL -> Go: ' + case['name'], [*go_prefix, 'verify', case['module'], '--policy', policy],
                   expect=case['expected'], codes=case['codes'])
            group = case['group']
            if group == 'policy-upgrade' and case['expected'] == 'ALLOW':
                cpp('cross-layer target commits: ' + case['name'], policy, case['module'])
            elif group in ('ed-chain-revocation', 'pss-chain-revocation') and group not in seeded_revocations:
                cpp('cross-layer target learns: ' + case['name'], policy, case['module'], False, ['CERT_004'])
                seeded_revocations.add(group)
        now = dt.datetime.now(dt.timezone.utc)
        stamp = lambda value: value.strftime('%Y-%m-%dT%H:%M:%SZ')
        produced = {}
        for algorithm, original in fixtures['guest_algorithms'].items():
            # Native OpenSSL signatures enter the actual target candidate too.
            openssl_policy = go_policy('openssl-' + algorithm, original, algorithm)
            record(algorithm + ' OpenSSL -> Go positive', [*go_prefix, 'verify', original['module'], '--policy', openssl_policy])
            cpp(algorithm + ' OpenSSL -> target C++', openssl_policy, original['module'], guest_marker=original['guest_marker'])
            policy = go_policy('go-' + algorithm, original, algorithm)
            directory = execution.out / 'go-modules'
            directory.mkdir(mode=0o700, exist_ok=True)
            module = directory / (algorithm + '.wasm')
            module.write_bytes(Path(original['module']).read_bytes())
            ca = original['pki']
            sign = [*go_prefix, 'sign', module, '--replace-signature', '--algorithm', algorithm, '--policy', policy, '--key', ca['key'],
                '--certificate', ca['certificate'], '--crl', ca['crl'], '--module-id', 'matrix.app',
                '--module-version', '100', '--security-epoch', '0', '--capabilities', str(original['capabilities']),
                '--not-before', stamp(now - dt.timedelta(minutes=1)), '--not-after', stamp(now + dt.timedelta(hours=12))]
            if not record(algorithm + ' real Go signature producer', sign):
                continue
            # Inspect the canonical protected-header octets independently of
            # either candidate implementation. No key-type-based alg inference.
            envelope = matrix.embedded_parts(module.read_bytes())[1]
            protected = matrix.cbor({1: matrix.ALGORITHMS[algorithm][0]})
            expected_prefix = b'\xd2\x84' + matrix.cbor(protected) + b'\xa0'
            wire_ok = envelope.startswith(expected_prefix)
            records.append({'name': algorithm + ' canonical explicit COSE algorithm', 'passed': wire_ok,
                            'protected_hex': protected.hex(), 'signature_sha256': hashlib.sha256(envelope).hexdigest()})
            record(algorithm + ' Go -> Go', [*go_prefix, 'verify', module, '--policy', policy])
            cpp(algorithm + ' Go -> target C++', policy, module, guest_marker=original['guest_marker'])
            produced[algorithm] = {'module': str(module), 'policy': str(policy), 'signature_sha256': hashlib.sha256(envelope).hexdigest()}
            # Generic tamper checks are repeated for every family and encoding.
            original_bytes = module.read_bytes()
            try:
                module.write_bytes(original_bytes + b'\x00')
                record(algorithm + ' Go artifact full-file tamper -> Go', [*go_prefix, 'verify', module, '--policy', policy],
                       expect='DENY', codes=['SIG_002', 'SIG_004'])
                cpp(algorithm + ' Go artifact full-file tamper -> target', policy, module, False, ['SIG_002', 'SIG_004'], original['guest_marker'])
            finally:
                module.write_bytes(original_bytes)
        # CLI defaults must not broaden a policy merely because the key supports
        # more than one COSE algorithm. Marshal/update checks inspect saved files.
        ec = fixtures['algorithms']['ES256']
        default_sign_policy = go_policy('default-sign', ec)
        default_module = execution.out / 'go-modules' / 'default-sign.wasm'
        default_module.write_bytes(Path(ec['module']).read_bytes())
        default_ca = ec['pki']
        record('Go sign default algorithm is explicit ES256', [*go_prefix, 'sign', default_module, '--replace-signature',
            '--policy', default_sign_policy, '--key', default_ca['key'], '--certificate', default_ca['certificate'],
            '--crl', default_ca['crl'], '--module-id', 'matrix.app', '--module-version', '1', '--security-epoch', '0',
            '--capabilities', '0', '--not-before', stamp(now - dt.timedelta(minutes=1)),
            '--not-after', stamp(now + dt.timedelta(hours=12))])
        default_wire = matrix.embedded_parts(default_module.read_bytes())[1]
        records.append({'name': 'Go default sign protected-header bytes are ES256',
                        'passed': default_wire.startswith(b'\xd2\x84' + matrix.cbor(matrix.cbor({1: -7})) + b'\xa0')})
        cpp('Go default sign -> target C++', default_sign_policy, default_module)
        default_policy = go_policy('default-six-fields', ec)
        default_rule = policy_rule(default_policy)
        default_ok = len(default_rule) == 6 or len(default_rule) == 7 and default_rule[6] == 'ES256'
        records.append({'name': 'Go policy-init default remains ES256 only', 'passed': default_ok, 'rule': default_rule})
        other = fixtures['algorithms']['ESP256']
        record('Go legacy default denies ESP256', [*go_prefix, 'verify', other['module'], '--policy', default_policy],
               expect='DENY', codes=['SIG_005'])
        cpp('target legacy default denies ESP256', default_policy, other['module'], False, ['SIG_005'])
        record('Go explicit policy algorithm broadening', [*go_prefix, 'policy-update', '--policy', default_policy,
            '--module-id', 'matrix.app', '--policy-version', '2', '--algorithms', 'ESP256,ES256'])
        record('Go explicitly broadened policy accepts ESP256', [*go_prefix, 'verify', other['module'], '--policy', default_policy])
        cpp('target explicitly broadened policy accepts ESP256', default_policy, other['module'])
        before_rule = policy_rule(default_policy)
        record('Go policy update without algorithms preserves set', [*go_prefix, 'policy-update', '--policy', default_policy,
            '--module-id', 'matrix.app', '--policy-version', '3'])
        after_rule = policy_rule(default_policy)
        records.append({'name': 'Go policy-update no implicit algorithm reset', 'passed': before_rule[6:] == after_rule[6:],
                        'before': before_rule, 'after': after_rule})
        record('Go algorithm change requires module identity', [*go_prefix, 'policy-update', '--policy', default_policy,
            '--policy-version', '4', '--algorithms', 'Ed25519'], expect='DENY')
        record('Go algorithm update requires increasing policy version', [*go_prefix, 'policy-update', '--policy', default_policy,
            '--module-id', 'matrix.app', '--policy-version', '3', '--algorithms', 'ES256'], expect='DENY', codes=['POL_002'])
        for number, invalid in enumerate(['', 'ES256,ES256', 'ES256,unknown', 'ES256,', 'es256', 'EdDSA', 'Ed448', 'DSA', 'SHA1', 'MD5']):
            directory = execution.out / 'invalid-go-policy' / str(number)
            directory.mkdir(mode=0o700, parents=True)
            record('Go policy CLI rejects algorithm set ' + repr(invalid), [*go_prefix, 'policy-init', '--output', directory / 'policy',
                '--state-dir', directory / 'state', '--trust-root', ec['pki']['root'], '--certificate', ec['pki']['certificate'],
                '--module-id', 'matrix.app', '--algorithms', invalid], expect='DENY')
        execution.report['go_produced'] = produced
        execution.report['producer_constraints'] = fixtures['producer_constraints']
        execution.report['status'] = 'FAIL' if not all(row['passed'] for row in records) else 'BLOCKED' if fixtures['producer_constraints'] else 'PASS'
    except Exception as error:
        execution.report.update(status='FAIL', error=str(error))
    finally:
        execution.report['finished_unix'] = int(time.time())
        if before is not None:
            after = matrix.cgroup_snapshot(True)
            execution.report.update(cgroup_before=before, cgroup_after=after)
            if before['cgroup_incarnation'] != after['cgroup_incarnation']:
                execution.report['status'] = 'FAIL'
            for old, new in zip(before['cgroup_ancestors'], after['cgroup_ancestors']):
                if old.get('memory.events') is None:
                    continue
                left = dict(line.split() for line in old['memory.events'].splitlines())
                right = dict(line.split() for line in new['memory.events'].splitlines())
                if any(left.get(key) != right.get(key) for key in ['oom', 'oom_kill']):
                    execution.report['status'] = 'FAIL'
        report = execution.out / 'interop-report.json'
        report.write_text(json.dumps(execution.report, indent=2) + '\n')
        print(json.dumps({'status': execution.report['status'], 'checks': len(records), 'report': str(report)}))
    return 0 if execution.report['status'] == 'PASS' else 77 if execution.report['status'] == 'BLOCKED' else 1


if __name__ == '__main__':
    raise SystemExit(main())
