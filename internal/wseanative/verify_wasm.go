//go:build wasm

// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
package wseanative

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// Separate core modules have separate memories. Only bounded scalar values
// cross this ABI; neither module can dereference pointers in the other's heap.
// There is no JavaScript, Go-X509 or host-crypto verification fallback.
//
//go:wasmimport wsea_crypto wsea_initialize
func initialize()

//go:wasmimport wsea_crypto wsea_begin
func begin(size uint32) uint32

//go:wasmimport wsea_crypto wsea_put
func put(offset, a, b, c, d uint32) uint32

//go:wasmimport wsea_crypto wsea_verify
func verify(nowLow, nowHigh, ageLow, ageHigh uint32) uint32

//go:wasmimport wsea_crypto wsea_get
func get(offset uint32) uint32

//go:wasmimport wsea_crypto wsea_reset
func reset()

var reactorOnce sync.Once
var reactorMutex sync.Mutex

func Verify(cose, certificates, crls, roots []byte, pin string, now int64, maxAge uint64) (string, uint64, error) {
	if len(cose) == 0 || len(cose) > 65536 || len(certificates) > 4194304 || len(crls) > 4194304 || len(roots) > 4194304 || len(pin) < 64 || len(pin) > 519 || now < 1577836800 {
		return "", 0, errors.New("SIG_002: invalid WASM evidence bounds")
	}
	fields := [][]byte{cose, certificates, crls, roots, []byte(pin)}
	size := 20
	for _, field := range fields {
		size += len(field)
	}
	input := make([]byte, (size+15)&^15)
	pos := 20
	for i, field := range fields {
		binary.LittleEndian.PutUint32(input[i*4:], uint32(len(field)))
		copy(input[pos:], field)
		pos += len(field)
	}
	reactorMutex.Lock()
	defer reactorMutex.Unlock()
	reactorOnce.Do(initialize)
	defer reset()
	if begin(uint32(size)) != 1 {
		return "", 0, errors.New("SIG_005: WASM verifier buffer unavailable")
	}
	for i := 0; i < len(input); i += 16 {
		if put(uint32(i), binary.LittleEndian.Uint32(input[i:]), binary.LittleEndian.Uint32(input[i+4:]), binary.LittleEndian.Uint32(input[i+8:]), binary.LittleEndian.Uint32(input[i+12:])) != 1 {
			return "", 0, errors.New("SIG_005: WASM verifier transfer failed")
		}
	}
	n := verify(uint32(now), uint32(uint64(now)>>32), uint32(maxAge), uint32(maxAge>>32))
	if n < 9 || n > 1024 {
		return "", 0, errors.New("SIG_005: invalid WASM verifier result")
	}
	output := make([]byte, (n+3)&^3)
	for i := 0; i < len(output); i += 4 {
		binary.LittleEndian.PutUint32(output[i:], get(uint32(i)))
	}
	if output[0] != 0 {
		return "", 0, fmt.Errorf("%s", output[9:n])
	}
	if n != 73 {
		return "", 0, errors.New("SIG_005: invalid WASM signer result")
	}
	return string(output[9:n]), binary.LittleEndian.Uint64(output[1:9]), nil
}
