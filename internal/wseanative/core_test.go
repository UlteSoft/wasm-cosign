// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wseanative

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPinnedUWVMCore(t *testing.T) {
	core, err := os.ReadFile("wsea.h")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := os.ReadFile("wsea.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(core)) != strings.TrimSpace(string(pin)) {
		t.Fatal("shared WSEA core changed without qualification")
	}
	root := os.Getenv("UWVM2_ROOT")
	if root == "" {
		root = "../../../uwvm2-ros"
	}
	other, err := os.ReadFile(filepath.Join(root, "src/uwvm2/utils/security/wsea.h"))
	if os.IsNotExist(err) && os.Getenv("UWVM2_ROOT") == "" {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(core, other) {
		t.Fatal("WSEA cores differ between wasm-cosign and UWVM")
	}
}
