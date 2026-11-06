#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ifeq (,$(shell echo $$DEBUG))
else
SHELL = bash -x
endif

# allow overwriting the default `go` value with the custom path to the go executable
GOEXE ?= go
.DEFAULT_GOAL := all

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell $(GOEXE) env GOBIN))
GOBIN=$(shell $(GOEXE) env GOPATH)/bin
else
GOBIN=$(shell $(GOEXE) env GOBIN)
endif

# Set version variables for LDFLAGS
PROJECT_ID ?= projectsigstore
RUNTIME_IMAGE ?= gcr.io/distroless/static
GIT_TAG ?= dirty-tag
IS_GIT_REPO := $(shell git rev-parse --is-inside-work-tree 2>/dev/null)
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "unknown")
GIT_HASH ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --no-show-signature --pretty=%ct 2>/dev/null)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
ifeq ($(IS_GIT_REPO),)
    GIT_TREESTATE = "unknown"
endif
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif
WSEA_GOOS ?= $(shell $(GOEXE) env GOOS)
WSEA_GOARCH ?= $(shell $(GOEXE) env GOARCH)
KO_PLATFORM ?= linux/amd64
COSIGNED_ARCHS?=all

LDFLAGS=-buildid= -s -w -X github.com/sigstore/cosign/v3/internal/wasmcli.Version=$(GIT_VERSION)

# Only the WSEA product graph is compiled. Source-only upstream utilities are
# not part of this binary or its default tests.
SRCS = cmd/cosign/main.go $(shell find internal/wasmcli internal/wseanative pkg/wasmsecure cmd/cosign/cli/wasmsecure -type f)
WSEA_PACKAGES = ./cmd/cosign ./cmd/wasmcosign ./internal/wasmcli ./internal/wasmsdk ./internal/wseanative ./pkg/wasmsecure ./cmd/cosign/cli/wasmsecure
export CGO_ENABLED=1
WSEA_OPENSSL_ROOT ?= $(CURDIR)/.tmp/wsea-build/openssl
export WSEA_OPENSSL_ROOT
# Both ordinary and release builds resolve only our pinned static crypto archive.
override export PKG_CONFIG_PATH := $(WSEA_OPENSSL_ROOT)/pkgconfig
override export PKG_CONFIG_LIBDIR := $(WSEA_OPENSSL_ROOT)/pkgconfig
override export PKG_CONFIG_SYSROOT_DIR :=
WSEA_USER_CPPFLAGS := $(CGO_CPPFLAGS)
# Recursive expansion reads the new receipt after bundled-openssl has finished.
override export CGO_CPPFLAGS = $(WSEA_USER_CPPFLAGS) $(shell cat "$(WSEA_OPENSSL_ROOT)/cgo-cppflags" 2>/dev/null)

.PHONY: check-wsea
check-wsea:
	GOEXE=$(GOEXE) python3 scripts/check_wsea_build.py $(if $(UWVM2_ROOT),--uwvm-root $(UWVM2_ROOT))

.PHONY: bundled-openssl
bundled-openssl: check-wsea
	GOEXE=$(GOEXE) python3 scripts/prepare_wsea_openssl.py

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)
GHCR_PREFIX ?= ghcr.io/sigstore/cosign
LATEST_TAG ?=

.PHONY: all lint test clean cosign conformance cross
all: cosign

log-%:
	@grep -h -E '^$*:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk \
			'BEGIN { \
				FS = ":.*?## " \
			}; \
			{ \
				printf "\033[36m==> %s\033[0m\n", $$2 \
			}'

cosign: bundled-openssl $(SRCS)
	CGO_ENABLED=1 $(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/cosign

cosign-pivkey-pkcs11key: bundled-openssl $(SRCS)
	CGO_ENABLED=1 $(GOEXE) build -trimpath -tags=pivkey,pkcs11key -ldflags "$(LDFLAGS)" -o cosign ./cmd/cosign

install: bundled-openssl $(SRCS)
	CGO_ENABLED=1 $(GOEXE) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/cosign

install-pivkey-pkcs11key: bundled-openssl $(SRCS)
	CGO_ENABLED=1 $(GOEXE) install -trimpath -tags=pivkey,pkcs11key -ldflags "$(LDFLAGS)" ./cmd/cosign

.PHONY: cross
# One explicit native/cross toolchain per invocation. For cross targets, the
# caller supplies CC/CXX and WSEA_OPENSSL_SPEC for the matching target recipe.
cross: export GOOS=$(WSEA_GOOS)
cross: export GOARCH=$(WSEA_GOARCH)
cross: bundled-openssl
	GOOS=$(WSEA_GOOS) GOARCH=$(WSEA_GOARCH) $(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o cosign-$(WSEA_GOOS)-$(WSEA_GOARCH) ./cmd/cosign
	shasum -a 256 cosign-$(WSEA_GOOS)-$(WSEA_GOARCH) > cosign-$(WSEA_GOOS)-$(WSEA_GOARCH).sha256

#####################
# lint / test section
#####################

lint:
	docker run -t --rm -v $(PWD):/app -w /app \
		--user $(shell id -u):$(shell id -g) \
		-v $(shell go env GOCACHE):/.cache/go-build -e GOCACHE=/.cache/go-build \
		-v $(shell go env GOMODCACHE):/go/pkg/mod -e GOMODCACHE=/go/pkg/mod \
		-v ~/.cache/golangci-lint:/.cache/golangci-lint -e GOLANGCI_LINT_CACHE=/.cache/golangci-lint \
		$(shell awk -F '[ @]' '/FROM golangci\/golangci-lint/{print $$2; exit}' Dockerfile.golangci-lint) \
		sh -c 'make bundled-openssl && PKG_CONFIG_PATH=/app/.tmp/wsea-build/openssl/pkgconfig PKG_CONFIG_LIBDIR=/app/.tmp/wsea-build/openssl/pkgconfig CGO_CPPFLAGS="$$(cat /app/.tmp/wsea-build/openssl/cgo-cppflags)" golangci-lint run -v $(WSEA_PACKAGES)'

test: bundled-openssl
	python3 test/wsea/bundled_openssl_test.py
	$(GOEXE) test $(WSEA_PACKAGES)

clean:
	rm -rf cosign
	rm -rf dist/

KOCACHE_PATH=/tmp/ko
ARTIFACT_HUB_LABELS=--image-label io.artifacthub.package.readme-url="https://raw.githubusercontent.com/sigstore/cosign/main/README.md" \
                    --image-label io.artifacthub.package.logo-url=https://raw.githubusercontent.com/sigstore/cosign/main/images/logo.svg \
                    --image-label io.artifacthub.package.license=Apache-2.0 --image-label io.artifacthub.package.vendor=sigstore \
                    --image-label io.artifacthub.package.version=0.1.0 \
                    --image-label io.artifacthub.package.name=cosign \
                    --image-label org.opencontainers.image.created=$(BUILD_DATE) \
                    --image-label org.opencontainers.image.description="WSEA WebAssembly signing and verification" \
                    --image-label org.opencontainers.image.source=https://github.com/sigstore/cosign \
                    --image-label io.artifacthub.package.alternative-locations="oci://ghcr.io/sigstore/cosign/cosign"

define create_kocache_path
  mkdir -p $(KOCACHE_PATH)
endef

###################
# conformance tests
###################

conformance:
	$(GOEXE) build -trimpath -ldflags "$(LDFLAGS)" -o $@ ./cmd/conformance

CONFORMANCE_RUNNER_PATH = sigstore-conformance
$(CONFORMANCE_RUNNER_PATH):
	git clone https://github.com/sigstore/sigstore-conformance $@

.PHONY: conformance-runner
conformance-runner:
	$(MAKE) $(CONFORMANCE_RUNNER_PATH) conformance-runner-pull conformance-runner-build

.PHONY: conformance-runner-pull
conformance-runner-pull:
	cd $(CONFORMANCE_RUNNER_PATH) && git pull

.PHONY: conformance-runner-build
conformance-runner-build:
	cd $(CONFORMANCE_RUNNER_PATH) && $(MAKE) dev

CONFORMANCE_BIN = $(shell pwd)/conformance
.PHONY: conformance-tests
conformance-tests:
	cd $(CONFORMANCE_RUNNER_PATH) && env/bin/pytest test --entrypoint=$(CONFORMANCE_BIN)

##########
# ko build
##########
.PHONY: ko
ko: ko-cosign ko-cosign-dev

.PHONY: ko-cosign
ko-cosign: bundled-openssl
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --base-import-paths \
		--platform=$(KO_PLATFORM) --tags $(GIT_VERSION) --tags $(GIT_HASH)$(LATEST_TAG) \
		$(ARTIFACT_HUB_LABELS) --image-refs cosignImagerefs \
		github.com/sigstore/cosign/v3/cmd/cosign

.PHONY: ko-cosign-dev
ko-cosign-dev: bundled-openssl
	$(create_kocache_path)
	LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DEFAULTBASEIMAGE=gcr.io/distroless/static-debian12:debug-nonroot ko build --base-import-paths \
		--platform=$(KO_PLATFORM) --tags $(GIT_VERSION)-dev --tags $(GIT_HASH)-dev$(LATEST_TAG)-dev \
		$(ARTIFACT_HUB_LABELS) --image-refs cosignDevImagerefs \
		github.com/sigstore/cosign/v3/cmd/cosign

.PHONY: ko-local
ko-local: bundled-openssl
	$(create_kocache_path)
	KO_DOCKER_REPO=ko.local LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) ko build --base-import-paths --platform=$(KO_PLATFORM) \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		$(ARTIFACT_HUB_LABELS) \
		github.com/sigstore/cosign/v3/cmd/cosign

.PHONY: ko-local-dev
ko-local-dev: bundled-openssl
	$(create_kocache_path)
	KO_DOCKER_REPO=ko.local/cosign-dev LDFLAGS="$(LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	KOCACHE=$(KOCACHE_PATH) KO_DEFAULTBASEIMAGE=gcr.io/distroless/static-debian12:debug-nonroot ko build --base-import-paths --platform=$(KO_PLATFORM) \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) \
		$(ARTIFACT_HUB_LABELS) \
		github.com/sigstore/cosign/v3/cmd/cosign

##################
# help
##################

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort

include release/release.mk
include test/ci.mk

##########################
# Documentation generation
##########################

.PHONY: docgen
docgen: bundled-openssl
	$(GOEXE) run ./cmd/help/
