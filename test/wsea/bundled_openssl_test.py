#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Reject changed, incomplete or injected vendored crypto before compilation."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('prepare_wsea', ROOT / 'scripts/prepare_wsea_openssl.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class BundledOpenSSLSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='wsea-source-integrity-')
        cls.root = Path(cls.temporary.name) / 'openssl'
        shutil.copytree(ROOT / 'third_party/openssl', cls.root)
        cls.builder = prepare.load_builder()

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_source(self):
        self.assertEqual(self.builder.verify_source(self.root), self.builder.EXPECTED_MANIFEST_SHA256)

    def test_modified_crypto_source(self):
        path = self.root / 'upstream/crypto/evp/digest.c'
        original = path.read_bytes()
        try:
            path.write_bytes(original + b'\n/* changed */\n')
            with self.assertRaisesRegex(ValueError, 'source mismatch'):
                self.builder.verify_source(self.root)
        finally:
            path.write_bytes(original)

    def test_missing_source(self):
        path = self.root / 'upstream/VERSION.dat'
        original = path.read_bytes()
        try:
            path.unlink()
            with self.assertRaisesRegex(ValueError, 'source mismatch'):
                self.builder.verify_source(self.root)
        finally:
            path.write_bytes(original)

    def test_unmanifested_source(self):
        path = self.root / 'upstream/injected.c'
        try:
            path.write_text('int unexpected_crypto;\n')
            with self.assertRaisesRegex(ValueError, 'unmanifested'):
                self.builder.verify_source(self.root)
        finally:
            path.unlink()

    def test_symlink_substitution(self):
        path = self.root / 'upstream/VERSION.dat'
        original = path.read_bytes()
        try:
            path.unlink()
            path.symlink_to(ROOT / 'third_party/openssl/upstream/VERSION.dat')
            with self.assertRaisesRegex(ValueError, 'source mismatch'):
                self.builder.verify_source(self.root)
        finally:
            path.unlink()
            path.write_bytes(original)

    def test_manifest_replacement(self):
        path = self.root / 'sources.sha256'
        original = path.read_bytes()
        try:
            path.write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'manifest pin mismatch'):
                self.builder.verify_source(self.root)
        finally:
            path.write_bytes(original)

    def test_recipe_replacement(self):
        original = prepare.BUILDER
        path = Path(self.temporary.name) / 'changed-builder.py'
        try:
            path.write_bytes(original.read_bytes() + b'\n# changed recipe\n')
            prepare.BUILDER = path
            with self.assertRaisesRegex(ValueError, 'recipe changed'):
                prepare.load_builder()
        finally:
            prepare.BUILDER = original


if __name__ == '__main__':
    unittest.main()
