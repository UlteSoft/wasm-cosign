#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Resource admission, ancestor limits, OOM and durable diagnostic regressions."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
import wsea_cross_support as resources


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name).resolve()
        self.proc = self.base / 'proc'
        self.mount = self.base / 'cgroup'
        self.parent = self.mount / 'builds'
        self.leaf = self.parent / 'job'
        for path in (self.proc / 'self', self.proc / 'sys/kernel/random', self.leaf):
            path.mkdir(parents=True)
        self.write(self.proc / 'self/cgroup', '0::/builds/job\n')
        self.write(self.proc / 'self/mountinfo', f'23 1 0:27 / {self.mount} rw - cgroup2 cgroup2 rw\n')
        self.write(self.proc / 'sys/kernel/random/boot_id', 'test-boot-id\n')
        self.write(self.proc / 'meminfo', 'MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n')
        self.write(self.leaf / 'cgroup.procs', f'{os.getpid()}\n')
        for path in (self.parent, self.leaf):
            for name, value in {'memory.max': 'max', 'memory.high': 'max', 'memory.swap.max': 'max',
                                'memory.current': '4096', 'memory.peak': '8192', 'memory.swap.current': '0',
                                'memory.events': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0',
                                'memory.events.local': 'low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0'}.items():
                self.write(path / name, value + '\n')
        self.write(self.leaf / 'memory.max', str(8 * 1024**3))
        self.write(self.leaf / 'memory.swap.max', '0')

    @staticmethod
    def write(path, value):
        path.write_text(value, encoding='utf-8')

    def capture(self):
        return resources._capture_cgroup(self.proc)

    def test_finite_budgets_are_not_tied_to_64_gib_or_host_ram(self):
        for budget in (64 * 1024**2, 8 * 1024**3, 32 * 1024**3, 128 * 1024**3):
            with self.subTest(budget=budget):
                self.write(self.leaf / 'memory.max', str(budget))
                snapshot = self.capture()
                resources._admit_cgroup(snapshot)
                self.assertEqual(snapshot['effective_memory_max'], budget)
                self.assertEqual(snapshot['ancestors'][0]['memory.peak'], 8192)
                self.assertEqual(snapshot['host_memory_bytes']['MemTotal'], 16000000 * 1024)

    def test_effective_parent_limits_and_swap_are_enforced(self):
        self.write(self.leaf / 'memory.max', 'max')
        self.write(self.leaf / 'memory.swap.max', 'max')
        self.write(self.parent / 'memory.max', str(2 * 1024**3))
        self.write(self.parent / 'memory.swap.max', '0')
        snapshot = self.capture()
        resources._admit_cgroup(snapshot)
        self.assertEqual(snapshot['effective_memory_max'], 2 * 1024**3)
        self.assertEqual(snapshot['effective_swap_max'], 0)

    def test_unbounded_zero_or_invalid_memory_is_rejected(self):
        for value in ('max', '0', '-1', '1.5', 'unlimited'):
            with self.subTest(value=value):
                self.write(self.leaf / 'memory.max', value)
                with self.assertRaises(RuntimeError):
                    resources._admit_cgroup(self.capture())

    def test_swap_limit_and_existing_swapped_pages_are_rejected(self):
        for limit, current in (('max', '0'), ('4096', '0'), ('0', '4096')):
            with self.subTest(limit=limit, current=current):
                self.write(self.leaf / 'memory.swap.max', limit)
                self.write(self.leaf / 'memory.swap.current', current)
                with self.assertRaisesRegex(RuntimeError, 'swap'):
                    resources._admit_cgroup(self.capture())

    def test_real_membership_and_required_counters_cannot_be_missing(self):
        self.write(self.leaf / 'cgroup.procs', '0\n')
        with self.assertRaisesRegex(RuntimeError, 'member'):
            self.capture()
        self.write(self.leaf / 'cgroup.procs', f'{os.getpid()}\n')
        self.write(self.parent / 'memory.events', 'high 0\n')
        with self.assertRaisesRegex(RuntimeError, 'OOM counters'):
            self.capture()

    def test_ancestor_oom_and_identity_or_limit_changes_fail(self):
        before = self.capture()
        changes = [lambda s: s.update(boot_id='another-boot'),
                   lambda s: s['ancestors'][0].update(inode=0),
                   lambda s: s['ancestors'][1].update({'memory.max': 1024}),
                   lambda s: s['ancestors'][0].update({'memory.high': 1024})]
        changes += [lambda s, key=key: s['ancestors'][1]['events_local'].update({key: 1})
                    for key in resources.OOM_EVENTS]
        for change in changes:
            with self.subTest(change=change):
                after = copy.deepcopy(before)
                change(after)
                with self.assertRaises(RuntimeError):
                    resources.check_cgroup(before, after)

    def test_reclaim_events_and_usage_growth_are_recorded_without_becoming_oom(self):
        before = self.capture()
        after = copy.deepcopy(before)
        after['ancestors'][0]['events'].update(high=5, max=1)
        after['ancestors'][0]['memory.peak'] = 65536
        resources.check_cgroup(before, after)

    def test_sibling_private_oom_does_not_invalidate_this_workload(self):
        before = self.capture()
        after = copy.deepcopy(before)
        after['ancestors'][1]['events'].update(oom=1, oom_kill=1)
        resources.check_cgroup(before, after)

    def test_command_cleanup_failure_still_records_failure_and_actual_resources(self):
        snapshot = self.capture()
        receipt = self.base / '.tmp/resource.json'
        process = Mock(pid=123, wait=Mock(return_value=0))
        argv = ['resource-guard', '--receipt', str(receipt), '--timeout', '1', '--', 'test-command']
        with patch.object(resources, 'ROOT', self.base), patch.object(resources, '_capture_cgroup', return_value=snapshot), \
             patch.object(resources.sys, 'platform', 'linux'), patch.object(resources.sys, 'argv', argv), \
             patch.object(resources.subprocess, 'Popen', return_value=process), \
             patch.object(resources.signal, 'SIGKILL', 9, create=True), \
             patch.object(resources.os, 'killpg', side_effect=PermissionError('cleanup denied'), create=True):
            self.assertEqual(resources.main(), 1)
        saved = json.loads(receipt.read_text())
        self.assertEqual(saved['status'], 'FAIL')
        self.assertIn('cleanup failed', saved['error'])
        self.assertEqual(saved['after']['effective_memory_max'], snapshot['effective_memory_max'])

    def test_failure_receipt_preserves_actual_oom_and_limit(self):
        before = self.capture()
        after = copy.deepcopy(before)
        after['ancestors'][0]['events']['oom_kill'] = 1
        after['ancestors'][0]['memory.max'] = None
        after['effective_memory_max'] = None
        receipt = self.base / '.tmp/resource.json'
        with patch.object(resources, 'ROOT', self.base), patch.object(resources, '_capture_cgroup', return_value=after):
            with self.assertRaises(RuntimeError):
                resources.finish_cgroup(before, receipt)
        saved = json.loads(receipt.read_text())
        self.assertEqual(saved['status'], 'FAIL')
        self.assertEqual(saved['after']['ancestors'][0]['events']['oom_kill'], 1)
        self.assertIsNone(saved['after']['effective_memory_max'])

    def test_capture_failure_is_not_a_success_or_empty_result(self):
        before = self.capture()
        receipt = self.base / '.tmp/resource.json'
        with patch.object(resources, 'ROOT', self.base), patch.object(resources, '_capture_cgroup', side_effect=OSError('gone')):
            with self.assertRaises(OSError):
                resources.finish_cgroup(before, receipt)
        self.assertEqual(json.loads(receipt.read_text())['status'], 'FAIL')

    def test_guard_retains_task_failure_even_with_clean_resource_counters(self):
        snapshot = self.capture()
        receipt = self.base / '.tmp/resource.json'
        with patch.object(resources, 'ROOT', self.base), patch.object(resources, 'cgroup_snapshot', return_value=snapshot), \
             patch.object(resources, '_capture_cgroup', return_value=snapshot):
            with self.assertRaisesRegex(RuntimeError, 'build failed'):
                with resources.cgroup_guard(receipt):
                    raise RuntimeError('build failed')
        saved = json.loads(receipt.read_text())
        self.assertEqual(saved['status'], 'FAIL')
        self.assertEqual(saved['operation_error'], 'build failed')
        self.assertIsNotNone(saved['after'])

    def test_optional_non_qualification_is_explicit(self):
        with patch.object(resources, '_capture_cgroup', side_effect=AssertionError('must not probe')):
            self.assertIsNone(resources.cgroup_snapshot(False))
            self.assertIsNone(resources.finish_cgroup(None, self.base / 'unused'))


if __name__ == '__main__':
    if not Path(tempfile.gettempdir()).resolve().is_relative_to(ROOT / '.tmp'):
        sys.exit('set TMPDIR to a private directory under project .tmp')
    unittest.main()
