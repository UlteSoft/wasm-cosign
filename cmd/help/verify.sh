#!/usr/bin/env bash

# Copyright 2021 The Sigstore Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

make bundled-openssl
export PKG_CONFIG_PATH="${WSEA_OPENSSL_ROOT:-$PWD/.tmp/wsea-build/openssl}/pkgconfig"
export PKG_CONFIG_LIBDIR="$PKG_CONFIG_PATH"
export PKG_CONFIG_SYSROOT_DIR=
export CGO_CPPFLAGS="${CGO_CPPFLAGS:-} $(cat "${WSEA_OPENSSL_ROOT:-$PWD/.tmp/wsea-build/openssl}/cgo-cppflags")"

# Verify that generated Markdown docs are up-to-date.
umask 077
mkdir -p .tmp
tmpdir=$(mktemp -d "$PWD/.tmp/docgen.XXXXXXXX")
trap 'rm -rf "$tmpdir"' EXIT
go run ./cmd/help --dir "$tmpdir"
echo "###########################################"
echo "If diffs are found, run: make docgen"
echo "###########################################"
diff -Naur "$tmpdir" doc/wsea-cli/
