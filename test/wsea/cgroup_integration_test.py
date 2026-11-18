#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Exercise real Linux limits and OOM in disposable, explicitly delegated cgroups."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True,
                        help='writable cgroup v2 parent with memory already delegated')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('Linux is required')
    parent = args.parent.resolve(strict=True)
    if 'memory' not in (parent / 'cgroup.subtree_control').read_text().split():
        parser.error('parent must already delegate the memory controller')
    root = parent / ('wsea-resources-' + uuid.uuid4().hex)
    root.mkdir()
    groups = []
    scratch = ROOT / '.tmp'
    scratch.mkdir(exist_ok=True)
    try:
        # Bound the entire test independently of the smaller per-case caps.
        (root / 'memory.max').write_text(str(256 * 1024**2))
        (root / 'memory.swap.max').write_text('0')
        (root / 'cgroup.subtree_control').write_text('+memory')
        with tempfile.TemporaryDirectory(prefix='resource-integration-', dir=scratch) as temporary:
            output = Path(temporary)

            def run(name, maximum, swap, source, *, timeout=10, parent_cgroup=root):
                group = parent_cgroup / name
                group.mkdir()
                groups.append(group)
                (group / 'memory.max').write_text(str(maximum))
                (group / 'memory.swap.max').write_text(str(swap))
                receipt = output / (name + '.json')

                def enter():
                    (group / 'cgroup.procs').write_text(str(os.getpid()))

                result = subprocess.run([sys.executable, str(ROOT / 'scripts/wsea_cross_support.py'),
                    '--receipt', str(receipt), '--timeout', str(timeout), '--', sys.executable, '-c', source],
                    preexec_fn=enter, capture_output=True, text=True, timeout=timeout + 15,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
                return result, json.loads(receipt.read_text()), group

            for size in (64, 128):
                result, record, _ = run('bounded-' + str(size), size * 1024**2, 0,
                                       'data = bytearray(8 * 1024**2); print(len(data))')
                assert result.returncode == 0, result.stderr
                assert record['status'] == 'PASS', record
                assert record['before']['effective_memory_max'] == size * 1024**2
                assert record['after']['ancestors'][0]['memory.peak'] > 0
                print('PASS: actual', size, 'MiB limit, zero swap and peak record', flush=True)

            result, record, _ = run('inherited', 'max', 'max', 'pass')
            assert result.returncode == 0, result.stderr
            assert record['before']['effective_memory_max'] == 256 * 1024**2
            assert record['before']['effective_swap_max'] == 0
            print('PASS: actual finite parent limit and inherited zero swap', flush=True)

            sibling = root / 'sibling-oom'
            sibling.mkdir()
            groups.append(sibling)
            (sibling / 'memory.max').write_text(str(64 * 1024**2))
            (sibling / 'memory.swap.max').write_text('0')
            source = ('import os, subprocess, sys\nfrom pathlib import Path\n'
                      f'def enter(): Path({str(sibling / "cgroup.procs")!r}).write_text(str(os.getpid()))\n'
                      'child = subprocess.run([sys.executable, "-c", "data = bytearray(128 * 1024**2)"], preexec_fn=enter)\n'
                      'assert child.returncode != 0\n')
            result, record, _ = run('unrelated-oom', 64 * 1024**2, 0, source)
            assert result.returncode == 0 and record['status'] == 'PASS', (record, result.stderr)
            assert record['after']['ancestors'][1]['events']['oom_kill'] > record['before']['ancestors'][1]['events']['oom_kill']
            print('PASS: sibling private-limit OOM does not invalidate this workload', flush=True)

            result, record, _ = run('timeout', 64 * 1024**2, 0, 'import time; time.sleep(30)', timeout=0.2)
            assert result.returncode != 0 and record['status'] == 'FAIL', record
            assert 'timed out' in record['error'], record
            print('PASS: timeout is a recorded failure', flush=True)

            result, record, group = run('descendant', 64 * 1024**2, 0,
                'import subprocess, sys; subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])')
            assert result.returncode == 0, result.stderr
            deadline = time.monotonic() + 5
            while (group / 'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not (group / 'cgroup.procs').read_text().strip()
            print('PASS: surviving command descendants are stopped', flush=True)

            result, record, _ = run('command-failure', 64 * 1024**2, 0, 'raise SystemExit(7)')
            assert result.returncode != 0 and record['returncode'] == 7 and record['status'] == 'FAIL', record
            print('PASS: command failure is not converted to success', flush=True)

            result, record, group = run('oom', 64 * 1024**2, 0, 'data = bytearray(128 * 1024**2)')
            assert result.returncode != 0 and record['status'] == 'FAIL', record
            assert record['after']['ancestors'][0]['events']['oom_kill'] > record['before']['ancestors'][0]['events']['oom_kill']
            assert 'OOM counters changed' in record['error'], record
            print('PASS: actual child OOM is rejected and retained in resource record', flush=True)

            # A new sibling group has no local OOM, while its ancestor retains
            # the historical event. Only changes during each run must fail.
            result, record, _ = run('after-oom', 64 * 1024**2, 0, 'pass')
            assert result.returncode == 0, result.stderr
            print('PASS: historical OOM does not invalidate a later clean run', flush=True)

            (root / 'memory.swap.max').write_text(str(64 * 1024**2))
            result, record, _ = run('swap-allowed', 64 * 1024**2, 4 * 1024**2,
                                    'raise RuntimeError("must not run")')
            assert result.returncode != 0 and record['status'] == 'FAIL', record
            assert 'zero-swap' in record['error'], record
            print('PASS: actual nonzero swap allowance is refused before execution', flush=True)
    finally:
        for group in reversed(groups):
            for pid in (group / 'cgroup.procs').read_text().splitlines():
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 5
            while (group / 'cgroup.procs').read_text().strip() and time.monotonic() < deadline:
                time.sleep(0.05)
            group.rmdir()
        root.rmdir()


if __name__ == '__main__':
    main()
