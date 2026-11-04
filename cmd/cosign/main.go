// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"github.com/sigstore/cosign/v3/internal/wasmcli"
	"os"
)

func main() {
	if err := wasmcli.New().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
