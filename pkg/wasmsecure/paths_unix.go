//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsecure

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// ProtectedPath rejects symlinks, mutable ancestors and foreign owners. A root
// owned sticky temporary directory may be an ancestor, never the target file.
func ProtectedPath(path string, stateDir bool) error {
	if !cleanSecurityPath(path) {
		return errors.New("security paths must be clean absolute paths")
	}
	target := path
	for {
		st, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return errors.New("security paths cannot contain symlinks")
		}
		raw, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot authenticate security file owner")
		}
		if raw.Uid != 0 && raw.Uid != uint32(os.Geteuid()) {
			return errors.New("security path owner must be root or effective user")
		}
		stickyAncestor := path != target && st.IsDir() && raw.Uid == 0 && st.Mode()&os.ModeSticky != 0
		if st.Mode().Perm()&0022 != 0 && !stickyAncestor {
			return errors.New("security path is writable by group or others")
		}
		if path == target {
			if stateDir {
				if !st.IsDir() || raw.Uid != uint32(os.Geteuid()) || st.Mode().Perm() != 0700 {
					return errors.New("state directory requires effective user ownership and mode 0700")
				}
			} else if raw.Nlink != 1 {
				return errors.New("security files must not have hard links")
			} else if !st.Mode().IsRegular() {
				return errors.New("security input must be a regular file")
			}
		}
		if path == string(filepath.Separator) {
			break
		}
		path = filepath.Dir(path)
	}
	return nil
}

// Nonblocking open prevents an untrusted FIFO sidecar from hanging before fstat.
func openSnapshot(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
}
