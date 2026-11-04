// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmcli

import (
	"fmt"

	securecli "github.com/sigstore/cosign/v3/cmd/cosign/cli/wasmsecure"
	"github.com/spf13/cobra"
)

var Version = "devel"

// New constructs the production WASM-only command graph. Importing the old
// generic cli package would compile its unrelated OCI/cloud signing providers,
// even if their commands were subsequently hidden or removed.
func New() *cobra.Command {
	help := func(c *cobra.Command, _ []string) error { return c.Help() }
	root := &cobra.Command{Use: "cosign", Short: "WSEA WebAssembly signing and offline UWVM trust", SilenceUsage: true, SilenceErrors: true, Args: cobra.NoArgs, RunE: help}
	root.CompletionOptions.DisableDefaultCmd = true
	wasm := &cobra.Command{Use: "wasm", Short: "Manage WSEA WebAssembly modules", Args: cobra.NoArgs, RunE: help}
	secure := securecli.Command()
	secure.Args = cobra.NoArgs
	secure.RunE = help
	wasm.AddCommand(secure)
	root.AddCommand(wasm, &cobra.Command{Use: "version", Short: "Print the WASM tool version", Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(c.OutOrStdout(), "wasm-cosign", Version, "WSEA v2")
			return err
		}})
	return root
}
