#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Build the vendored UWVM OpenSSL recipe and expose only its static crypto archive."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / 'tools/dependencies/build_openssl.py'
BUILDER_SHA256 = '4a11742a950d82756a90588a205d94ef6ffa3f665f7c937a028ec3484a79adf0'


def load_builder():
    import hashlib
    if hashlib.sha256(BUILDER.read_bytes()).hexdigest() != BUILDER_SHA256:
        raise ValueError('bundled OpenSSL recipe changed; synchronize and qualify both projects')
    module_spec = importlib.util.spec_from_file_location('wsea_openssl_builder', BUILDER)
    builder = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(builder)
    return builder


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(os.environ.get(
        'WSEA_OPENSSL_ROOT', ROOT / '.wsea-build/openssl')))
    parser.add_argument('--spec', type=Path, default=os.environ.get('WSEA_OPENSSL_SPEC'),
                        help='explicit UWVM target/compiler JSON spec, required for cross builds')
    args = parser.parse_args()
    builder = load_builder()
    builder.verify_source(ROOT / 'third_party/openssl')
    output = args.output.resolve()
    # pkg-config expands variables and CGO tokenizes flags. Reject ambiguous
    # paths instead of allowing an archive argument to become linker options.
    if any(c.isspace() or c in "'\"\\$#" for c in str(output)):
        raise ValueError('OpenSSL build output must have no whitespace or pkg-config metacharacters')
    go = os.environ.get('GOEXE', 'go')
    target = json.loads(subprocess.check_output(
        [go, 'env', '-json', 'GOOS', 'GOARCH', 'GOHOSTOS', 'GOHOSTARCH', 'CC'], text=True))
    platform = {'linux': 'linux', 'darwin': 'macosx', 'freebsd': 'freebsd',
                'openbsd': 'openbsd', 'netbsd': 'netbsd', 'dragonfly': 'dragonflybsd'}.get(target['GOOS'])
    arch = builder.ALIASES.get(target['GOARCH'], target['GOARCH'])
    arch = {'386': 'i686', 'mips64le': 'mips64el'}.get(target['GOARCH'], arch)
    if platform is None:
        raise ValueError('unsupported WSEA OpenSSL target: ' + target['GOOS'])
    if args.spec:
        spec = json.loads(args.spec.read_text())
        spec_arch = builder.ALIASES.get(spec.get('arch'), spec.get('arch'))
        if spec.get('platform') != platform or (spec_arch != arch and not (arch == 'arm' and spec_arch == 'armhf')):
            raise ValueError('OpenSSL spec must match Go GOOS/GOARCH')
        if spec.get('no_asm'):
            raise ValueError('qualify both products before changing the bundled OpenSSL configuration')
    else:
        if (target['GOOS'], target['GOARCH']) != (target['GOHOSTOS'], target['GOHOSTARCH']):
            raise ValueError('cross builds require WSEA_OPENSSL_SPEC with the matching UWVM compiler/ABI')
        spec = {'platform': platform, 'arch': arch, 'cc': shlex.split(target['CC']),
                'ar': shlex.split(os.environ.get('AR', 'ar')),
                'ranlib': shlex.split(os.environ.get('RANLIB', 'ranlib')),
                'cflags': ['-O2', '-g0', '-fPIC'], 'ldflags': [], 'no_asm': False}
    spec['jobs'] = int(os.environ.get('WSEA_OPENSSL_JOBS', spec.get('jobs', min(os.cpu_count() or 1, 4))))
    output.mkdir(parents=True, exist_ok=True)
    # The shared recipe locks the output, validates source/header/archive hashes
    # on cache hits, and verifies the actual compiler and archive target ABI.
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', dir=output) as stream:
        json.dump(spec, stream)
        stream.flush()
        subprocess.run([sys.executable, str(BUILDER), '--source-root', str(ROOT / 'third_party/openssl'),
                        '--spec', stream.name, '--output', str(output)], check=True)
    receipt = json.loads((output / 'receipt.json').read_text())
    abi = receipt['identity']['spec']['arch']
    libs = [] if platform == 'macosx' else ['-ldl', '-pthread']
    if abi.startswith(('arm', 'mips')):
        libs.append('-latomic')
    # A unique module plus an absolute archive prevents pkg-config/-lcrypto
    # fallback to a host installation. libssl is never linked into the product;
    # HTTPS uses Go TLS. These are identical for both Go build tag variants.
    pc = output / 'pkgconfig'
    pc.mkdir(exist_ok=True)
    # Go does not reliably track changes to external C archives/headers in its
    # build cache. Bind flags to the checked receipt so a toolchain/configuration
    # or library change forces recompilation and relinking of the CGO adapter.
    import hashlib
    cache_pin = hashlib.sha256(json.dumps({'identity': receipt['identity_sha256'],
        'artifacts': receipt['artifacts']}, sort_keys=True).encode()).hexdigest()
    cppflags = f'-DWSEA_OPENSSL_RECEIPT_{cache_pin}=1'
    content = ('Name: wsea-libcrypto\nDescription: Pinned UWVM OpenSSL static crypto\n'
               f'Version: {builder.RELEASE}\n'
               f'Cflags: -I{output}/include -DWSEA_BUNDLED_OPENSSL=30509 -DWSEA_OPENSSL_RECEIPT_{cache_pin}=1\n'
               f'Libs: {output}/libcrypto.a {" ".join(libs)}\n')
    (pc / 'wsea-libcrypto.pc').write_text(content)
    # This flag must also be in the Go command environment: a cached CGO
    # package may skip pkg-config entirely, so the .pc file alone is insufficient.
    (output / 'cgo-cppflags').write_text(cppflags + '\n')
    print('WSEA bundled OpenSSL: ' + str(pc))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit('WSEA OpenSSL: ' + str(error))
