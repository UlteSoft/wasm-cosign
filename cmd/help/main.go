// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"os"

	"github.com/sigstore/cosign/v3/internal/wasmcli"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func main() {
	var dir string
	root := &cobra.Command{
		Use:          "gendoc",
		Short:        "Generate cosign's help docs",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
			product := wasmcli.New()
			var stable func(*cobra.Command)
			stable = func(c *cobra.Command) {
				c.DisableAutoGenTag = true
				for _, child := range c.Commands() {
					stable(child)
				}
			}
			stable(product)
			return doc.GenMarkdownTree(product, dir)
		},
	}
	root.Flags().StringVarP(&dir, "dir", "d", "doc/wsea-cli", "Path to directory in which to generate docs")

	if err := root.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
