//go:build !js

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/cosign/v3/internal/wasmsdk"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--stream" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), wasmsdk.MaxRequestBytes+1)
		for scanner.Scan() {
			result := wasmsdk.Process(scanner.Bytes())
			clear(scanner.Bytes())
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				os.Exit(1)
			}
		}
		if scanner.Err() != nil {
			fmt.Fprintln(os.Stderr, "SDK_001: invalid bounded request stream")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "Usage: wasm-cosign-wasi.wasm [--stream] < trusted-request.json")
		os.Exit(1)
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, wasmsdk.MaxRequestBytes+1))
	if err != nil {
		fmt.Fprintln(os.Stderr, "SDK_001: cannot read request")
		os.Exit(1)
	}
	r := wasmsdk.Process(data)
	clear(data)
	if err = json.NewEncoder(os.Stdout).Encode(r); err != nil {
		os.Exit(1)
	}
	if r.Status == "REJECTED" {
		os.Exit(1)
	}
}
