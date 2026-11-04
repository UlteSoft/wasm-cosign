//go:build wsea_static

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wseanative

// #cgo pkg-config: --static wsea-libcrypto
import "C"
