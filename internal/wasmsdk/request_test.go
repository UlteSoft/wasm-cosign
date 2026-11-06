// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wasmsdk

import "testing"

func TestStrictRequestRejectsAmbiguousSecurityMembers(t *testing.T) {
	for _, text := range []string{
		`null`, `[]`, `{} {}`,
		`{"operation":"verify","operation":"sign"}`,
		`{"operation":"verify","Operation":"sign"}`,
		`{"schema":"wsea-sdk-1","ſchema":"other"}`,
		`{"trust":{"state":"YQ==","state":"Yg=="}}`,
		`{"signing":{"manifest":{"version":1,"Version":0}}}`,
		`{"signing":{"manifest":{"version":1,"unknown":0}}}`,
		"{\"schema\":\"\xff\"}",
	} {
		var request Request
		if err := strictJSON([]byte(text), &request); err == nil {
			t.Errorf("accepted ambiguous or malformed security request: %q", text)
		}
	}
}

func TestStrictRequestPreservesFullWidthVersion(t *testing.T) {
	var request Request
	text := `{"schema":"wsea-sdk-1","operation":"sign","signing":{"manifest":{"version":18446744073709551615,"security_epoch":9007199254740993}}}`
	if err := strictJSON([]byte(text), &request); err != nil {
		t.Fatal(err)
	}
	if request.Signing.Manifest.Version != ^uint64(0) || request.Signing.Manifest.Epoch != 9007199254740993 {
		t.Fatal("JSON transport rounded security counters")
	}
}
