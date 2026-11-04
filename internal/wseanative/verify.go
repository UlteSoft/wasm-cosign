// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wseanative

/*
#cgo CXXFLAGS: -std=c++20
#include "bridge.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// Verify shares UWVM's actual evidence verifier. All byte views are borrowed
// synchronously; C++ retains no Go pointers and never opens policy/state files.
// There is deliberately no !cgo implementation: missing crypto fails at build.
func Verify(cose, certificates, crls, roots []byte, pin string, now int64, maxAge uint64) (string, uint64, error) {
	bytes := func(b []byte) C.struct_wsea_bytes {
		return C.struct_wsea_bytes{data: (*C.char)(unsafe.Pointer(unsafe.SliceData(b))), size: C.size_t(len(b))}
	}
	pinBytes := []byte(pin)
	result := C.wsea_verify_evidence(bytes(cose),
		bytes(certificates), bytes(crls), bytes(roots), bytes(pinBytes), C.int64_t(now), C.uint64_t(maxAge))
	runtime.KeepAlive(cose)
	runtime.KeepAlive(certificates)
	runtime.KeepAlive(crls)
	runtime.KeepAlive(roots)
	runtime.KeepAlive(pinBytes)
	if result.code != nil {
		return "", 0, fmt.Errorf("%s: %s", C.GoString(result.code), C.GoString(result.message))
	}
	return C.GoString(&result.signer[0]), uint64(result.valid_until), nil
}
