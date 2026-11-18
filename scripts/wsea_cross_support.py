#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Private, checksum-pinned tooling and resource admission for native releases."""
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def private_path(path):
    path = Path(path).resolve()
    if not path.is_relative_to(ROOT / '.tmp'):
        raise ValueError('generated material must remain under project .tmp')
    return path


def sha(path):
    with Path(path).open('rb') as stream:
        h = hashlib.sha256()
        while chunk := stream.read(1 << 20):
            h.update(chunk)
        return h.hexdigest()


def download(url, digest, path, maximum=1 << 30):
    if not url.startswith('https://') or len(digest) != 64:
        raise ValueError('HTTPS and an explicit SHA-256 pin are required')
    path = private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        part = path.with_name(path.name + '.partial')
        with urllib.request.urlopen(url, timeout=60) as response, part.open('xb') as stream:
            if not response.url.startswith('https://'):
                raise ValueError('download redirected away from HTTPS')
            count = 0
            while chunk := response.read(1 << 20):
                count += len(chunk)
                if count > maximum:
                    raise ValueError('download exceeds size bound')
                stream.write(chunk)
        part.rename(path)
    if not path.is_file() or path.stat().st_size > maximum or sha(path) != digest:
        raise ValueError('download checksum mismatch: ' + str(path))
    return path


OOM_EVENTS = ('oom', 'oom_kill', 'oom_group_kill')


def _unescape_mount(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def _number(text, *, unlimited=False):
    if unlimited and text == 'max':
        return None
    if not re.fullmatch(r'[0-9]+', text):
        raise RuntimeError('invalid cgroup resource value: ' + repr(text))
    return int(text)


def _capture_cgroup(proc=Path('/proc'), pid=None):
    """Read kernel facts; the optional proc root is used by boundary tests."""
    pid = os.getpid() if pid is None else pid
    rows = (proc / 'self/cgroup').read_text().splitlines()
    memberships = [row[3:] for row in rows if row.startswith('0::')]
    if len(memberships) != 1:
        raise RuntimeError('a unified cgroup v2 membership is required')
    membership = PurePosixPath(memberships[0])
    if not membership.is_absolute() or '..' in membership.parts:
        raise RuntimeError('invalid cgroup membership')
    candidates = []
    for row in (proc / 'self/mountinfo').read_text().splitlines():
        left, separator, right = row.partition(' - ')
        if not separator or right.split()[0] != 'cgroup2':
            continue
        fields = left.split()
        root, mount = PurePosixPath(_unescape_mount(fields[3])), Path(_unescape_mount(fields[4]))
        if membership.is_relative_to(root):
            candidates.append((len(root.parts), fields[0], root, mount))
    if not candidates:
        raise RuntimeError('cgroup v2 mount for this process is unavailable')
    _, mount_id, root, mount = max(candidates, key=lambda item: item[0])
    path = mount / membership.relative_to(root)
    if path.resolve() != path or mount.resolve() != mount:
        raise RuntimeError('cgroup paths must not contain symlinks')
    members = (path / 'cgroup.procs').read_text().splitlines()
    if str(pid) not in members:
        raise RuntimeError('process is not a member of the recorded cgroup')
    ancestors = []
    current = path
    while True:
        info = current.stat()
        entry = {'path': str(current), 'device': info.st_dev, 'inode': info.st_ino}
        # The hierarchy root can omit memory-controller files. Every other
        # ancestor must expose them, so a missing controller cannot pass.
        for name in ('memory.max', 'memory.high', 'memory.swap.max', 'memory.current',
                     'memory.peak', 'memory.swap.current'):
            file = current / name
            entry[name] = (_number(file.read_text().strip(), unlimited=name in
                                  ('memory.max', 'memory.high', 'memory.swap.max'))
                           if file.exists() or current != mount else None)
        for filename, field in (('memory.events', 'events'), ('memory.events.local', 'events_local')):
            events = current / filename
            entry[field] = {}
            if events.exists() or current != mount or (current / 'memory.max').exists():
                for event in events.read_text().splitlines():
                    key, value = event.split()
                    if key in entry[field]:
                        raise RuntimeError('duplicate cgroup memory event')
                    entry[field][key] = _number(value)
                if not all(key in entry[field] for key in ('oom', 'oom_kill')):
                    raise RuntimeError('cgroup OOM counters are unavailable')
        ancestors.append(entry)
        if current == mount:
            break
        current = current.parent
    limits = [row['memory.max'] for row in ancestors if row['memory.max'] is not None]
    swaps = [row['memory.swap.max'] for row in ancestors if row['memory.swap.max'] is not None]
    if (proc / 'self/cgroup').read_text().splitlines() != rows:
        raise RuntimeError('cgroup membership changed while recording resources')
    host_memory = {}
    for row in (proc / 'meminfo').read_text().splitlines():
        key, value = row.split(':', 1)
        if key in ('MemTotal', 'MemAvailable', 'SwapTotal', 'SwapFree'):
            amount, unit = value.split()
            if unit != 'kB':
                raise RuntimeError('invalid host memory units')
            host_memory[key] = _number(amount) * 1024
    return {'version': 1, 'captured_at_ns': time.time_ns(),
            'boot_id': (proc / 'sys/kernel/random/boot_id').read_text().strip(),
            'membership': str(membership), 'mount_id': mount_id, 'mount_root': str(root),
            'mount_path': str(mount), 'ancestors': ancestors,
            'effective_memory_max': min(limits) if limits else None,
            'effective_swap_max': min(swaps) if swaps else None,
            'host_memory_bytes': host_memory}


def _admit_cgroup(snapshot):
    if snapshot['version'] != 1:
        raise RuntimeError('unsupported cgroup snapshot version')
    limit = snapshot['effective_memory_max']
    if limit is None or limit <= 0:
        raise RuntimeError('a finite positive cgroup memory limit is required')
    if snapshot['effective_swap_max'] != 0:
        raise RuntimeError('a zero-swap cgroup is required')
    if snapshot['ancestors'][0]['memory.swap.current'] != 0:
        raise RuntimeError('the qualification cgroup still has swapped memory')


def cgroup_snapshot(required=True):
    """Admit the actual finite memory budget, without imposing a fixed size."""
    if not required:
        return None
    if sys.platform != 'linux':
        raise RuntimeError('a Linux cgroup v2 is required')
    snapshot = _capture_cgroup()
    _admit_cgroup(snapshot)
    return snapshot


def check_cgroup(before, after):
    _admit_cgroup(before)
    _admit_cgroup(after)
    identity = ('boot_id', 'membership', 'mount_id', 'mount_root', 'mount_path')
    if any(before[key] != after[key] for key in identity) or len(before['ancestors']) != len(after['ancestors']):
        raise RuntimeError('qualification cgroup changed')
    for index, (old, new) in enumerate(zip(before['ancestors'], after['ancestors'])):
        if any(old[key] != new[key] for key in ('path', 'device', 'inode')):
            raise RuntimeError('qualification cgroup identity changed')
        if any(old[key] != new[key] for key in ('memory.max', 'memory.high', 'memory.swap.max')):
            raise RuntimeError('cgroup resource limits changed during qualification')
        # Descendant OOM belongs to this workload. At ancestors only local
        # events indicate pressure at that shared limit; a sibling's private
        # limit must not invalidate this run.
        field = 'events' if index == 0 else 'events_local'
        if any(old[field].get(key) != new[field].get(key) for key in OOM_EVENTS):
            raise RuntimeError('OOM counters changed during qualification')


def _write_receipt(receipt, value):
    receipt = private_path(receipt)
    receipt.parent.mkdir(parents=True, exist_ok=True)
    temporary = receipt.with_name(receipt.name + '.partial')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(receipt)


def finish_cgroup(before, receipt, *, failure=None):
    if before is None:
        return None
    after = None
    try:
        # Capture before validation, retaining the actual new limit/OOM facts
        # even when the environment no longer qualifies.
        after = _capture_cgroup()
        check_cgroup(before, after)
    except Exception as error:
        _write_receipt(receipt, {'version': 1, 'status': 'FAIL', 'before': before,
                                'after': after, 'error': str(error), 'operation_error': failure})
        raise
    _write_receipt(receipt, {'version': 1, 'status': 'PASS' if failure is None else 'FAIL',
                             'before': before, 'after': after, 'operation_error': failure})
    return after


@contextmanager
def cgroup_guard(receipt, required=True):
    before = cgroup_snapshot(required)
    if before is not None:
        _write_receipt(receipt, {'version': 1, 'status': 'RUNNING', 'before': before})
    failure = None
    try:
        yield before
    except BaseException as error:
        failure = str(error) or type(error).__name__
        raise
    finally:
        finish_cgroup(before, receipt, failure=failure)


def private_environment(work):
    os.umask(0o077)
    work = private_path(work)
    for name in ('tmp', 'go-cache', 'go-modules'):
        (work / name).mkdir(parents=True, exist_ok=True)
    os.environ.update(TMPDIR=str(work / 'tmp'), GOTMPDIR=str(work / 'tmp'),
                      GOCACHE=str(work / 'go-cache'), GOMODCACHE=str(work / 'go-modules'),
                      GOMAXPROCS='2', WSEA_OPENSSL_JOBS='3', GOTOOLCHAIN='local',
                      GOENV='off', PYTHONDONTWRITEBYTECODE='1')


def main():
    """Run a bounded command inside an already configured cgroup."""
    import argparse
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--timeout', type=float, required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or not 0 < args.timeout < float('inf'):
        parser.error('a command and a finite positive timeout are required')
    os.umask(0o077)
    receipt = private_path(args.receipt)
    before = None
    try:
        if sys.platform != 'linux':
            raise RuntimeError('a Linux cgroup v2 is required')
        before = _capture_cgroup()
        _admit_cgroup(before)
    except (OSError, RuntimeError) as cause:
        _write_receipt(receipt, {'version': 1, 'status': 'FAIL', 'before': before,
                                 'after': None, 'error': str(cause)})
        print(str(cause), file=sys.stderr)
        return 1
    _write_receipt(receipt, {'version': 1, 'status': 'RUNNING', 'before': before,
                             'command': command, 'timeout_seconds': args.timeout})
    process = None
    error = None
    code = None
    handlers = {}

    def interrupted(signum, frame):
        raise InterruptedError('resource-guarded command interrupted by signal ' + str(signum))

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.signal(signum, interrupted)
        process = subprocess.Popen(command, start_new_session=True)
        code = process.wait(timeout=args.timeout)
    except (OSError, subprocess.TimeoutExpired) as cause:
        error = str(cause)
    finally:
        # Terminate this command's process group even when its direct child
        # has exited, so surviving descendants cannot escape the resource run.
        for signum, handler in handlers.items():
            signal.signal(signum, signal.SIG_IGN)
        try:
            if process is not None:
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired) as cause:
                    error = (error + '; ' if error else '') + 'command cleanup failed: ' + str(cause)
            after = None
            try:
                after = _capture_cgroup()
                check_cgroup(before, after)
            except Exception as cause:
                error = (error + '; ' if error else '') + str(cause)
            _write_receipt(receipt, {'version': 1, 'status': 'PASS' if code == 0 and error is None else 'FAIL',
                                     'before': before, 'after': after, 'command': command,
                                     'returncode': code, 'error': error, 'timeout_seconds': args.timeout})
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
    if error:
        print(error, file=sys.stderr)
    return 0 if code == 0 and error is None else 1


if __name__ == '__main__':
    sys.exit(main())
