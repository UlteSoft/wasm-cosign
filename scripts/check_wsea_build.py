#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Fail the WSEA build on verifier drift or unrelated compiled dependencies."""
import argparse
import hashlib
import os
import re
from pathlib import Path
import subprocess
from prepare_wsea_openssl import load_builder

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--uwvm-root', type=Path, help='required counterpart checkout for release qualification')
args = parser.parse_args()
builder = load_builder()
source_manifest = builder.verify_source(root / 'third_party/openssl')
core = root / 'internal/wseanative/wsea.h'
expected = (core.parent / 'wsea.sha256').read_text().strip()
if hashlib.sha256(core.read_bytes()).hexdigest() != expected:
    raise SystemExit('FAIL: pinned WSEA verifier digest changed; synchronize and qualify both projects')
# COSE IDs and names are part of the frozen signature contract. The Go signing
# table must not silently gain/lose a profile relative to the shared verifier.
native_profiles = dict(re.findall(r'\{"([A-Za-z0-9]+)",(-?\d+),signature_kind::', core.read_text()))
go_source = (root / 'pkg/wasmsecure/algorithms.go').read_text()
go_names = dict(re.findall(r'(Algorithm\w+)\s+Algorithm\s*=\s*"([A-Za-z0-9]+)"', go_source))
go_profiles = {go_names[name]: ident for name, ident in
               re.findall(r'\{(Algorithm\w+),\s*(-?\d+),', go_source)}
if len(native_profiles) != 13 or native_profiles != go_profiles:
    raise SystemExit('FAIL: Go signing and UWVM verification algorithm contracts differ')
counterpart = args.uwvm_root or root.parent / 'uwvm2-ros'
if args.uwvm_root or counterpart.exists():
    original = counterpart / 'src/uwvm2/utils/security/wsea.h'
    if core.read_bytes() != original.read_bytes():
        raise SystemExit('FAIL: wasm-cosign and UWVM WSEA cores differ')
    if builder.verify_source(counterpart / 'third-parties/openssl') != source_manifest:
        raise SystemExit('FAIL: wasm-cosign and UWVM OpenSSL sources differ')
    if (root / 'tools/dependencies/build_openssl.py').read_bytes() != (counterpart / 'tools/dependencies/build_openssl.py').read_bytes():
        raise SystemExit('FAIL: wasm-cosign and UWVM OpenSSL build recipes differ')

allowed = {
    'github.com/sigstore/cosign/v3/cmd/cosign',
    'github.com/sigstore/cosign/v3/cmd/cosign/cli/wasmsecure',
    'github.com/sigstore/cosign/v3/internal/wasmcli',
    'github.com/sigstore/cosign/v3/internal/wseanative',
    'github.com/sigstore/cosign/v3/pkg/wasmsecure',
    'github.com/spf13/cobra', 'github.com/spf13/pflag', 'github.com/inconshreveable/mousetrap',
}
dependencies = set()
for tags in ('', 'netgo,osusergo,wsea_static'):
    result = subprocess.run([os.environ.get('GOEXE', 'go'), 'list', '-deps', '-tags', tags,
        '-f', '{{if not .Standard}}{{.ImportPath}}{{end}}', './cmd/cosign'],
        cwd=root, check=True, text=True, capture_output=True)
    dependencies.update(result.stdout.split())
    unexpected = dependencies - allowed
    if unexpected:
        raise SystemExit('FAIL: non-WSEA compiled packages: ' + ', '.join(sorted(unexpected)))
print('PASS: pinned shared WSEA core and OpenSSL source/recipe; production nonstandard packages:', len(dependencies))
