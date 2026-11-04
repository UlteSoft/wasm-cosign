// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct wsea_bytes { const char* data; size_t size; };
struct wsea_result { const char* code; const char* message; char signer[65]; uint64_t valid_until; };
struct wsea_result wsea_verify_evidence(struct wsea_bytes cose, struct wsea_bytes certificates,
    struct wsea_bytes crls, struct wsea_bytes roots, struct wsea_bytes pin, int64_t now, uint64_t max_age);
#ifdef __cplusplus
}
#endif
