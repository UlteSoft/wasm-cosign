// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmcli

import (
	"bytes"
	"strings"
	"testing"
)

func TestProductionWSEACommandSurface(t *testing.T) {
	for _, command := range []string{"sign", "verify", "fetch", "policy-init", "policy-update"} {
		t.Run(command, func(t *testing.T) {
			var out bytes.Buffer
			c := New()
			c.SetOut(&out)
			c.SetArgs([]string{"wasm", "secure", command, "--help"})
			if err := c.Execute(); err != nil || !strings.Contains(out.String(), command) {
				t.Fatalf("missing production WSEA command: %v: %s", err, &out)
			}
		})
	}
	for _, args := range [][]string{{"sign", "image"}, {"sign-blob", "file"}, {"verify-blob", "file"}, {"wasm", "sign", "file"}, {"wasm", "verify", "file"}, {"wasm", "secure", "unknown"}} {
		c := New()
		c.SetArgs(args)
		if err := c.Execute(); err == nil {
			t.Fatalf("unrelated/incompatible command accepted: %v", args)
		}
	}
}
