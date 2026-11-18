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

func writeResponse(data []byte) (wasmsdk.Response, error) {
	r := wasmsdk.Process(data)
	output, err := json.Marshal(r)
	if err == nil {
		err = wasmsdk.ValidateExchangeJSON(data, output)
	}
	if err != nil {
		return r, err
	}
	output = append(output, '\n')
	n, err := os.Stdout.Write(output)
	if err == nil && n != len(output) {
		err = io.ErrShortWrite
	}
	return r, err
}

func main() {
	if len(os.Args) == 2 && (os.Args[1] == "--validate-request" || os.Args[1] == "--validate-response" || os.Args[1] == "--validate-exchange") {
		limit := wasmsdk.MaxRequestBytes
		validate := wasmsdk.ValidateRequestJSON
		if os.Args[1] == "--validate-response" {
			limit = wasmsdk.MaxResponseBytes
			validate = wasmsdk.ValidateResponseJSON
		} else if os.Args[1] == "--validate-exchange" {
			limit = wasmsdk.MaxExchangeBytes
			validate = wasmsdk.ValidateExchangeEnvelopeJSON
		}
		data, err := io.ReadAll(io.LimitReader(os.Stdin, int64(limit)+1))
		if err == nil {
			err = validate(data)
		}
		clear(data)
		if err != nil {
			fmt.Fprintln(os.Stderr, "SDK_001: invalid contract document")
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--stream" {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Buffer(make([]byte, 4096), wasmsdk.MaxRequestBytes+1)
		for scanner.Scan() {
			_, err := writeResponse(scanner.Bytes())
			clear(scanner.Bytes())
			if err != nil {
				fmt.Fprintln(os.Stderr, "SDK_001: failed to produce a valid response")
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
	r, err := writeResponse(data)
	clear(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SDK_001: failed to produce a valid response")
		os.Exit(1)
	}
	if r.Status == "REJECTED" {
		os.Exit(1)
	}
}
