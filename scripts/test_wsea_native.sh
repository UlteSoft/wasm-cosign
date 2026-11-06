#!/usr/bin/env bash
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
set -euo pipefail
umask 077
mkdir -p .tmp/native-ci/tmp .tmp/native-ci/go-cache
export TMPDIR="$PWD/.tmp/native-ci/tmp" GOTMPDIR="$PWD/.tmp/native-ci/tmp"
export GOCACHE="$PWD/.tmp/native-ci/go-cache" GOMAXPROCS=2 WSEA_OPENSSL_JOBS=3
export WSEA_OPENSSL_ROOT="$PWD/.tmp/native-ci/openssl" PYTHONDONTWRITEBYTECODE=1
make bundled-openssl
export PKG_CONFIG_PATH="$WSEA_OPENSSL_ROOT/pkgconfig" PKG_CONFIG_LIBDIR="$WSEA_OPENSSL_ROOT/pkgconfig"
export PKG_CONFIG_SYSROOT_DIR= CGO_ENABLED=1
export CGO_CPPFLAGS="$(cat "$WSEA_OPENSSL_ROOT/cgo-cppflags")"
python3 scripts/check_wsea_docs.py
python3 test/wsea/release_packaging_test.py
python3 test/wsea/bundled_openssl_test.py
packages=(./cmd/cosign ./cmd/wasmcosign ./internal/wasmcli ./internal/wasmsdk
          ./internal/wseanative ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure)
go test -p=2 -count=1 -timeout=10m "${packages[@]}"
if [ "$(uname -s)" = Linux ]; then
  go test -p=2 -race -timeout=10m "${packages[@]}"
fi
bash cmd/help/verify.sh
