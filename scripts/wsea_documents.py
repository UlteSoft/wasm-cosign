#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Explicit product documentation allowlist shared by builders and checkers."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = (
    'README', 'doc/wasm-secure-execution', 'doc/wsea-cli',
    'doc/wsea-build', 'doc/wsea-release', 'doc/wsea-testing', 'wasm/README',
)
NAVIGATION = (
    'README.md', 'CLI.md', 'doc/README.md', 'doc/wasm-secure-execution.md',
    'doc/wsea-build.md', 'doc/wsea-release.md', 'wasm/README.md',
)
COMMANDS = (
    'cosign', 'cosign_version', 'cosign_wasm', 'cosign_wasm_secure',
    'cosign_wasm_secure_policy-init', 'cosign_wasm_secure_policy-update',
    'cosign_wasm_secure_sign', 'cosign_wasm_secure_verify', 'cosign_wasm_secure_fetch',
)
DOCUMENTS = (NAVIGATION + tuple(f'{base}.{locale}.md' for base in PAIRS
                              for locale in ('en_US', 'zh_CN'))
             + tuple(f'doc/wsea-cli/{name}.md' for name in COMMANDS))
