#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Private, checksum-pinned tooling and resource admission for native releases."""
import hashlib
import json
import os
from pathlib import Path
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


def cgroup_snapshot():
    rows = Path('/proc/self/cgroup').read_text().splitlines()
    membership = next(row.removeprefix('0::') for row in rows if row.startswith('0::'))
    path = Path('/sys/fs/cgroup') / membership.lstrip('/')
    if ((path / 'memory.max').read_text().strip() != '68719476736' or
            (path / 'memory.swap.max').read_text().strip() != '0'):
        raise RuntimeError('run inside a 64 GiB, zero-swap cgroup')
    info = path.stat()
    return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
            'memory_max': 68719476736, 'swap_max': 0,
            'memory_peak': int((path / 'memory.peak').read_text()),
            'events': dict(line.split() for line in (path / 'memory.events').read_text().splitlines())}


def finish_cgroup(before, receipt):
    after = cgroup_snapshot()
    if any(before[k] != after[k] for k in ('path', 'device', 'inode')):
        raise RuntimeError('qualification cgroup changed')
    if any(before['events'][k] != after['events'][k] for k in ('oom', 'oom_kill', 'oom_group_kill')):
        raise RuntimeError('OOM counters changed during qualification')
    Path(receipt).write_text(json.dumps({'before': before, 'after': after}, indent=2) + '\n')


def private_environment(work):
    os.umask(0o077)
    work = private_path(work)
    for name in ('tmp', 'go-cache', 'go-modules'):
        (work / name).mkdir(parents=True, exist_ok=True)
    os.environ.update(TMPDIR=str(work / 'tmp'), GOTMPDIR=str(work / 'tmp'),
                      GOCACHE=str(work / 'go-cache'), GOMODCACHE=str(work / 'go-modules'),
                      GOMAXPROCS='2', WSEA_OPENSSL_JOBS='3', GOTOOLCHAIN='local',
                      GOENV='off', PYTHONDONTWRITEBYTECODE='1')
