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
			return ""
		}
		text := args[0].String()
		data := []byte(text)
		r := wasmsdk.Process(data)
		clear(data)
		out, err := json.Marshal(r)
		if err != nil {
			return ""
		}
		return string(out)
	})
	js.Global().Set("wseaRequestJSON", call)
	validator := func(limit int, validate func([]byte) error) js.Func {
		return js.FuncOf(func(_ js.Value, args []js.Value) any {
			if len(args) != 1 || args[0].Type() != js.TypeString {
				return false
			}
			text := args[0].String()
			if len(text) > limit {
				return false
			}
			data := []byte(text)
			defer clear(data)
			return validate(data) == nil
		})
	}
	js.Global().Set("wseaValidateRequestJSON", validator(wasmsdk.MaxRequestBytes, wasmsdk.ValidateRequestJSON))
	js.Global().Set("wseaValidateResponseJSON", validator(wasmsdk.MaxResponseBytes, wasmsdk.ValidateResponseJSON))
	js.Global().Set("wseaValidateExchangeEnvelopeJSON", validator(wasmsdk.MaxExchangeBytes, wasmsdk.ValidateExchangeEnvelopeJSON))
	exchange := js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 2 || args[0].Type() != js.TypeString || args[1].Type() != js.TypeString {
			return false
		}
		request, response := args[0].String(), args[1].String()
		if len(request) > wasmsdk.MaxRequestBytes || len(response) > wasmsdk.MaxResponseBytes {
			return false
		}
		q, r := []byte(request), []byte(response)
		defer clear(q)
		return wasmsdk.ValidateExchangeJSON(q, r) == nil
	})
	js.Global().Set("wseaValidateExchangeJSON", exchange)
	select {}
}
