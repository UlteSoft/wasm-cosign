#!/usr/bin/env bash
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
set -euo pipefail
umask 077
mkdir -p .tmp/lint/tmp .tmp/lint/go-cache .tmp/lint/go-modules .tmp/lint/lint-cache
export TMPDIR="$PWD/.tmp/lint/tmp" GOTMPDIR="$PWD/.tmp/lint/tmp"
export GOCACHE="$PWD/.tmp/lint/go-cache" GOMAXPROCS=2 WSEA_OPENSSL_JOBS=3
export GOMODCACHE="$PWD/.tmp/lint/go-modules"
export GOLANGCI_LINT_CACHE="$PWD/.tmp/lint/lint-cache" PYTHONDONTWRITEBYTECODE=1
export WSEA_OPENSSL_ROOT="$PWD/.tmp/lint/openssl"
python3 scripts/fetch_wsea_toolchains.py --output .tmp/lint/tools --tools golangci-lint
make bundled-openssl
export PKG_CONFIG_PATH="$WSEA_OPENSSL_ROOT/pkgconfig" PKG_CONFIG_LIBDIR="$WSEA_OPENSSL_ROOT/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR= CGO_ENABLED=1
export CGO_CPPFLAGS="$(cat "$WSEA_OPENSSL_ROOT/cgo-cppflags")"
.tmp/lint/tools/golangci-lint/golangci-lint run ./cmd/cosign ./cmd/wasmcosign \
  ./internal/wasmsdk ./internal/wasmcli ./internal/wseanative \
  ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure
