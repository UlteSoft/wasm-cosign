// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
// WASIp1 reactor shared by WASI and JavaScript hosts. No filesystem access.
#define UWVM_WSEA_CRYPTO_ONLY 1
#include "../internal/wseanative/bridge.cc"

namespace {
    bool initialized{};
    __attribute__((constructor)) void mark_initialized() { initialized=true; }
    std::vector<unsigned char> input;
    std::array<unsigned char,1024> output{};
    std::uint32_t logical_size{}, next_offset{};
    bool ready{};
    std::uint32_t load(unsigned char const* p) {
        return std::uint32_t(p[0]) | (std::uint32_t(p[1])<<8) |
            (std::uint32_t(p[2])<<16) | (std::uint32_t(p[3])<<24);
    }
}
#define EXPORT(name) extern "C" __attribute__((export_name(#name)))

extern "C" void _initialize();
EXPORT(wsea_initialize) void wsea_initialize() {
    // Wasmtime preloads initialize reactors; plain JS instantiation does not.
    if(!initialized) { _initialize(); }
}

EXPORT(wsea_reset) void wsea_reset() {
    if(!input.empty()) { OPENSSL_cleanse(input.data(),input.size()); }
    input.clear(); output.fill(0); logical_size=0; next_offset=0; ready=false;
}
EXPORT(wsea_begin) std::uint32_t wsea_begin(std::uint32_t size) {
    wsea_reset();
    if(size<20 || size>20+65536+3*4194304+519) { return 0; }
    input.resize((size+15u)&~15u); logical_size=size; ready=true; return 1;
}
EXPORT(wsea_put) std::uint32_t wsea_put(std::uint32_t offset, std::uint32_t a,
    std::uint32_t b, std::uint32_t c, std::uint32_t d) {
    if(!ready || offset!=next_offset || offset>input.size() || input.size()-offset<16) { ready=false; return 0; }
    std::uint32_t values[]{a,b,c,d};
    for(unsigned i{};i<4;++i) for(unsigned j{};j<4;++j) { input[offset+4*i+j]=values[i]>>(8*j); }
    next_offset+=16; return 1;
}
EXPORT(wsea_verify) std::uint32_t wsea_verify(std::uint32_t now_lo, std::uint32_t now_hi,
    std::uint32_t age_lo, std::uint32_t age_hi) {
    output.fill(0);
    auto fail=[](std::string_view message) {
        output[0]=1;
        if(message.size()>output.size()-9) { message="SIG_005: oversized verifier diagnostic"; }
        std::memcpy(output.data()+9,message.data(),message.size());
        return static_cast<std::uint32_t>(9+message.size());
    };
    if(!ready || next_offset!=input.size() || now_hi>0x7fffffff) { return fail("SIG_002: incomplete verifier request"); }
    ready=false;
    wsea_bytes fields[5]{};
    std::uint32_t offset{20};
    for(unsigned i{};i<5;++i) {
        auto size{load(input.data()+i*4)};
        if(offset>logical_size || size>logical_size-offset) { return fail("SIG_002: malformed verifier request"); }
        fields[i]={reinterpret_cast<char const*>(input.data()+offset),size}; offset+=size;
    }
    if(offset!=logical_size) { return fail("SIG_002: trailing verifier request"); }
    auto result{wsea_verify_evidence(fields[0],fields[1],fields[2],fields[3],fields[4],
        static_cast<std::int64_t>((std::uint64_t(now_hi)<<32)|now_lo), (std::uint64_t(age_hi)<<32)|age_lo)};
    if(result.code) { return fail(std::string(result.code)+": "+result.message); }
    for(unsigned i{};i<8;++i) { output[1+i]=result.valid_until>>(8*i); }
    std::memcpy(output.data()+9,result.signer,64); return 73;
}
EXPORT(wsea_get) std::uint32_t wsea_get(std::uint32_t offset) {
    if(offset>output.size()-4 || offset%4) { __builtin_trap(); }
    return load(output.data()+offset);
}
