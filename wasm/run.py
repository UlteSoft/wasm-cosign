#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Protected POSIX file adapter for the WSEA WASIp1 / Node SDK.

Policy is selected by the local operator, never by the downloaded module. The
SDK performs all WSEA parsing and cryptography; this adapter authenticates host
files and serializes rollback/revocation reads with the VM's existing lock.
Verification does not advance VM state or grant permission to execute a module.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import time

MAX_MODULE = 32 << 20
MAX_EVIDENCE = 4 << 20
O_READ = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK


def clean(path):
    path = os.fspath(path)
    if not path.startswith('/') or os.path.normpath(path) != path or path.startswith('//') or any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise ValueError('POL_002: clean absolute security path required')
    return path


def authenticate(st, *, directory=False, private=False, ancestor=False):
    mode = stat.S_IMODE(st.st_mode)
    if st.st_uid not in (0, os.geteuid()):
        raise ValueError('POL_002: security path must belong to root or effective user')
    sticky = ancestor and stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and bool(st.st_mode & stat.S_ISVTX)
    if mode & 0o022 and not sticky:
        raise ValueError('POL_002: security path is writable by group or others')
    if directory:
        if not stat.S_ISDIR(st.st_mode):
            raise ValueError('POL_002: directory required')
        if private and (st.st_uid != os.geteuid() or mode != 0o700):
            raise ValueError('POL_002: state directory requires effective-user ownership and mode 0700')
    elif not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ValueError('POL_002: regular security file without hard links required')
    elif private and (st.st_uid != os.geteuid() or mode != 0o600):
        raise ValueError('POL_002: state file requires effective-user ownership and mode 0600')


@contextmanager
def protected_open(path, *, directory=False, private=False):
    """Resolve every ancestor via pinned descriptors, rejecting all symlinks."""
    parts = [name for name in clean(path).split('/')[1:] if name]
    fd = os.open('/', O_READ | os.O_DIRECTORY)
    try:
        authenticate(os.fstat(fd), directory=True if parts else directory,
                     private=False if parts else private, ancestor=bool(parts))
        for i, name in enumerate(parts):
            if not name:
                continue
            last = i == len(parts) - 1
            flags = O_READ | (os.O_DIRECTORY if not last or directory else 0)
            child = os.open(name, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            authenticate(os.fstat(fd), directory=directory if last else True,
                         private=private if last else False, ancestor=not last)
        yield fd
    finally:
        os.close(fd)


def identity(st):
    return st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def read_fd(fd, limit):
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError('POL_002: bounded regular file required')
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit or identity(before) != identity(os.fstat(fd)) or len(data) != before.st_size:
        raise ValueError('POL_002: file changed while reading or exceeds limit')
    return bytes(data)


def protected_read(path, limit, *, key=False):
    with protected_open(path) as fd:
        if key and stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise ValueError('POL_002: private key is accessible to group or others')
        return read_fd(fd, limit)


def input_read(path, limit):
    fd = os.open(path, O_READ)
    try:
        return read_fd(fd, limit)
    finally:
        os.close(fd)


def policy_paths(policy):
    # Only extract the two host paths here. The WASM SDK parses the complete
    # policy, including duplicate/unknown fields, algorithms and quorum rules.
    if not policy.endswith(b'\n') or b'\r' in policy or b'\0' in policy:
        raise ValueError('POL_002: invalid policy encoding')
    # POSIX filenames may contain non-UTF-8 bytes. Preserve them exactly, as the
    # shared native policy parser does, and split only the wire's ASCII newline.
    lines = policy.decode('utf-8', errors='surrogateescape').split('\n')[:-1]
    if not lines or lines[0] != 'UWVM-WSEA-POLICY-1':
        raise ValueError('POL_002: invalid policy header')
    result = {}
    for line in lines[1:]:
        name, sep, value = line.partition('=')
        if not sep:
            raise ValueError('POL_002: invalid policy field')
        if name in ('trust_root', 'state_dir'):
            if name in result:
                raise ValueError('POL_002: duplicate host path')
            result[name] = clean(value)
    if len(result) != 2:
        raise ValueError('POL_002: missing protected host paths')
    return result['trust_root'], result['state_dir']


def state_snapshot(fd):
    state = os.open('state', O_READ, dir_fd=fd)
    try:
        authenticate(os.fstat(state), private=True)
        data = read_fd(state, 1 << 20)
    finally:
        os.close(state)
    revoked = []
    # Presence is denial, even for a partial marker left by a crashed writer.
    for name in os.listdir(fd):
        if name.startswith('revoked-'):
            pin = name[8:]
            if not re.fullmatch('[0-9a-f]{64}', pin) or len(revoked) >= 8192:
                raise ValueError('CERT_004: malformed or excessive protected revocation markers')
            revoked.append(pin)
    return data, sorted(revoked)


@contextmanager
def state_lock(path):
    with protected_open(path, directory=True, private=True) as directory:
        fd = os.open('.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        try:
            authenticate(os.fstat(fd), private=True)
            # Same lock name and inode protocol as UWVM's commit_state and
            # revocation_memory. A bounded wait cannot hang on a stale owner.
            deadline = time.monotonic() + 30
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ValueError('POL_001: protected state lock timed out')
                    time.sleep(0.02)
            yield directory
        finally:
            os.close(fd)


def command(runtime, engine, assets):
    found = shutil.which(engine or {'node': 'node', 'wasmtime': 'wasmtime', 'uwvm': 'uwvm2-ros'}[runtime])
    if not found:
        raise ValueError('runtime executable not found')
    exe = str(Path(found).absolute())
    if runtime == 'node':
        return [exe, str(assets / 'run-json.mjs'), str(assets)]
    core, frontend = str(assets / 'wsea-crypto.wasm'), str(assets / 'wasm-cosign-wasi.wasm')
    if runtime == 'wasmtime':
        return [exe, 'run', '--preload', 'wsea_crypto=' + core, frontend]
    argv = [exe, '--runtime-int', '--wasm-set-main-module-name', 'wsea_frontend']
    for name in ('wsea_frontend', 'wsea_crypto'):
        argv += ['--wasip1-single-create', name, '--wasip1-single-enable', name,
                 '--wasip1-single-noinherit-system-environment', name]
        permissions = ['random', 'realtime-clock', 'monotonic-clock', 'environ', 'proc-exit', 'stderr.write']
        if name == 'wsea_frontend':
            permissions += ['args', 'stdin.read', 'stdout.write', 'stdio.metadata', 'stdio.readiness', 'monotonic-timer']
        for permission in permissions:
            argv += ['--wasip1-single-grant', name, permission]
    return argv + ['--wasm-preload-library', core, 'wsea_crypto', '--run', frontend]


def call_sdk(argv, request):
    raw = json.dumps(request, separators=(',', ':'), ensure_ascii=True).encode()
    if len(raw) > 96 << 20:
        raise ValueError('SDK_001: request exceeds SDK limit')
    # No host filesystem preopens, ambient NODE_OPTIONS, loader injection or
    # downloaded executable arguments are forwarded to either WASM module.
    process = subprocess.run(argv, input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env={'PATH': os.defpath, 'TZ': 'UTC'}, timeout=600)
    if len(process.stdout) > 96 << 20:
        raise ValueError('SDK_001: oversized runtime response')
    try:
        response = json.loads(process.stdout)
    except (ValueError, UnicodeDecodeError):
        raise ValueError('SDK_001: runtime failed without a valid SDK response') from None
    if process.returncode != 0 or response.get('status') == 'REJECTED':
        raise ValueError(response.get('error', 'SDK_001: runtime failed'))
    if response.get('status') not in ('VERIFIED_SNAPSHOT', 'SIGNED_PARTIAL'):
        raise ValueError('SDK_001: unexpected runtime response')
    return response


def b64(data):
    return base64.b64encode(data).decode('ascii')


def write_new(path, data, recheck):
    path = clean(path)
    parent, name = os.path.split(path)
    with protected_open(parent, directory=True) as directory:
        temporary = '.wsea-' + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            recheck()
            os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.fsync(directory)
        finally:
            os.unlink(temporary, dir_fd=directory)


def timestamp(text):
    d = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if d.tzinfo is None or d.microsecond or d.timestamp() < 0:
        raise argparse.ArgumentTypeError('whole-second RFC3339 timestamp required')
    return int(d.timestamp())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runtime', choices=['wasmtime', 'uwvm', 'node'], required=True)
    p.add_argument('--engine', help='trusted runtime executable')
    p.add_argument('--assets', type=Path, default=Path(__file__).absolute().parent)
    sub = p.add_subparsers(dest='operation', required=True)
    for operation in ('verify', 'sign'):
        s = sub.add_parser(operation)
        s.add_argument('module')
        s.add_argument('--policy', required=True, help='operator-selected protected absolute path')
        if operation == 'sign':
            for name in ('key', 'certificate', 'crl', 'module-id', 'algorithm', 'output'):
                s.add_argument('--' + name, required=True)
            s.add_argument('--version', type=int, required=True)
            s.add_argument('--security-epoch', type=int, default=0)
            s.add_argument('--capabilities', type=int, default=0)
            s.add_argument('--not-before', type=timestamp, required=True)
            s.add_argument('--not-after', type=timestamp, required=True)
            m = s.add_mutually_exclusive_group()
            m.add_argument('--append-signature', action='store_true')
            m.add_argument('--replace-signature', action='store_true')
            s.add_argument('--allow-partial', action='store_true')
    a = p.parse_args()
    os.umask(0o077)
    policy = protected_read(a.policy, 65536)
    root_path, state_path = policy_paths(policy)
    roots = protected_read(root_path, MAX_EVIDENCE)
    module = input_read(a.module, MAX_MODULE)
    request = {'schema': 'wsea-sdk-1', 'operation': a.operation, 'module': b64(module)}
    if a.operation == 'sign':
        request['signing'] = {'key': b64(protected_read(a.key, MAX_EVIDENCE, key=True)),
            'certificates': b64(input_read(a.certificate, MAX_EVIDENCE)), 'crls': b64(input_read(a.crl, MAX_EVIDENCE)),
            'append': a.append_signature, 'replace': a.replace_signature, 'allow_partial': a.allow_partial,
            'manifest': {'embedded': True, 'algorithm': a.algorithm, 'module_id': a.module_id,
                'version': a.version, 'security_epoch': a.security_epoch, 'not_before': a.not_before,
                'not_after': a.not_after, 'abi': 'uwvm2', 'capabilities': a.capabilities}}
    argv = command(a.runtime, a.engine, a.assets.absolute())
    with state_lock(state_path) as directory:
        before = int(time.time())
        state, revoked = state_snapshot(directory)
        request['trust'] = {'policy': b64(policy), 'roots': b64(roots), 'state': b64(state), 'revoked_spkis': revoked}
        response = call_sdk(argv, request)
        def recheck():
            with protected_open(state_path, directory=True, private=True) as current:
                if (os.fstat(current).st_dev, os.fstat(current).st_ino) != (os.fstat(directory).st_dev, os.fstat(directory).st_ino):
                    raise ValueError('POL_002: protected state directory changed')
            if (protected_read(a.policy, 65536) != policy or protected_read(root_path, MAX_EVIDENCE) != roots or
                    state_snapshot(directory) != (state, revoked)):
                raise ValueError('POL_002: protected trust snapshot changed')
            now = int(time.time())
            if now < before or now < response['checked_at'] or now >= response['valid_until']:
                raise ValueError('POL_004: time moved backwards or authenticated evidence expired')
        recheck()
        if a.operation == 'sign':
            signed = base64.b64decode(response.pop('module'), validate=True)
            if len(signed) > MAX_MODULE:
                raise ValueError('SIG_004: signed module too large')
            write_new(a.output, signed, recheck)
        # Same verifier semantics as native cosign: check protected state, do not
        # advance it. UWVM alone supplies the separate execution authorization.
        if response['status'] == 'VERIFIED_SNAPSHOT':
            response['status'] = 'VERIFIED'
        print(json.dumps(response, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as e:
        print(json.dumps({'status': 'REJECTED', 'error': str(e)}), file=sys.stderr)
        sys.exit(1)
