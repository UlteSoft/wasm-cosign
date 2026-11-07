#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors. Apache-2.0.
"""Real UI-state + native-command test, with desktop file selection stubbed.

This is not a browser/layout test. Use PKI fixtures from integration.py, kept
under project .tmp; nothing is added to the production server's HTTP surface.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server as gui
from integration import cgroup


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--fixtures', required=True, type=Path, help='integration.py output directory')
    p.add_argument('--require-cgroup', action='store_true')
    a = p.parse_args()
    before = cgroup(a.require_cgroup)
    os.umask(0o077)
    scratch = Path(__file__).resolve().parents[2] / '.tmp' / 'webgui'
    fixtures = a.fixtures.resolve()
    if scratch.parent not in fixtures.parents:
        p.error('Fixtures must be inside project .tmp')
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    out = Path(tempfile.mkdtemp(prefix='frontend-', dir=scratch))
    os.environ['TMPDIR'] = str(out)
    fixture = json.loads((fixtures / 'browser-fixture.json').read_text())
    binary = a.binary.resolve(strict=True)
    fields = fixture['mixed'] | {'output': str(out / 'policy'), 'state-dir': str(out / 'state')}
    result = gui.run_bounded(gui.build_argv(str(binary), 'policy-init', fields), 30)
    if result['exit_code'] != 0:
        raise RuntimeError('Test policy setup failed; check fixture freshness and directory permissions')
    choices = {
        'module': [str(fixtures / 'unsigned.wasm')],
        'policy': [str(out / 'policy')],
        'module-output': [str(out / ('signed-' + str(n) + '.wasm')) for n in (1, 2, 3)],
        **{field: [fixture['pki'][kind][field] for kind in ('P256', 'RSA', 'Ed25519')]
           for field in ('key', 'certificate', 'crl')},
    }

    def picker(role, language, stop):
        return choices[role].pop(0) if choices.get(role) else None

    app = gui.Application(binary, 30, picker=picker)
    server = gui.LocalServer(('127.0.0.1', 0), app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = out / 'session.json'
    session.write_text(json.dumps({'url': server.origin + '/#token=' + app.token,
                                   'times': fixture['times']}))
    try:
        subprocess.run(['node', str(Path(__file__).with_name('test_frontend.js')), str(session)],
                       check=True, timeout=60)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        session.unlink()  # The test token is no longer useful; keep it out of reports.
        after = cgroup(a.require_cgroup)
        if before and after and before['memory.events'] != after['memory.events']:
            raise RuntimeError('Cgroup memory events changed during the frontend test')


if __name__ == '__main__':
    main()
