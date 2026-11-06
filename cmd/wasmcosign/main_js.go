// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/sigstore/cosign/v3/internal/wasmsdk"
)

func main() {
	call := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return `{"status":"REJECTED","error":"SDK_001: request must be JSON text"}`
		}
		text := args[0].String()
		if len(text) > wasmsdk.MaxRequestBytes {
			return `{"status":"REJECTED","error":"SDK_001: oversized request"}`
		}
		data := []byte(text)
		r := wasmsdk.Process(data)
		clear(data)
		out, err := json.Marshal(r)
		if err != nil {
			return `{"status":"REJECTED","error":"SDK_001: response encoding failed"}`
		}
		return string(out)
	})
	js.Global().Set("wseaRequestJSON", call)
	select {}
}
