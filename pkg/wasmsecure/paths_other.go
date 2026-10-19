//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"errors"
	"os"
)

func ProtectedPath(_ string, _ bool) error {
	return errors.New("WSEA protected policy management requires POSIX ownership checks")
}

func openSnapshot(path string) (*os.File, error) { return os.Open(path) }
