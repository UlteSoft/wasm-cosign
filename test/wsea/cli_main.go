// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.

// A lightweight test entry point for the exact secure Cobra command registered
// by cosign wasm. It avoids loading unrelated cloud signing providers in the
// constrained Linux interoperability test window.
package main

import (
	"fmt"
	"os"

	securecli "github.com/sigstore/cosign/v3/cmd/cosign/cli/wasmsecure"
)

func main() {
	cmd := securecli.Command()
	cmd.Use = "wasm-cosign-secure"
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
