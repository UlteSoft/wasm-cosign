// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"os"

	"github.com/sigstore/cosign/v3/internal/wasmcli"
)

func main() {
	if err := wasmcli.New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
