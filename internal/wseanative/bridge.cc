// Copyright 2026 The Sigstore Authors.
// Licensed under the Apache License, Version 2.0.
#include "bridge.h"
#define UWVM_WSEA_OPENSSL 1
#include "wsea.h"

#ifndef UWVM_WSEA_SUPPORTED
#error WSEA requires the POSIX OpenSSL 3 backend; no permissive fallback is supported.
#endif
#if !defined(WSEA_BUNDLED_OPENSSL) || WSEA_BUNDLED_OPENSSL != 30509 || OPENSSL_VERSION_MAJOR != 3 || OPENSSL_VERSION_MINOR != 5 || OPENSSL_VERSION_PATCH != 9
#error Build the pinned UWVM OpenSSL 3.5.9 backend using make bundled-openssl.
#endif

extern "C" wsea_result wsea_verify_evidence(wsea_bytes cose, wsea_bytes certificates,
    wsea_bytes crls, wsea_bytes roots, wsea_bytes pin, int64_t now, uint64_t max_age)
{
    namespace wsea = uwvm2::utils::security::wsea;
    try
    {
        auto view = [](wsea_bytes b) { return std::string_view{b.data ? b.data : "", b.size}; };
        if(!cose.data || cose.size>65536 ||
           (certificates.size && !certificates.data) || certificates.size>4194304 ||
           (crls.size && !crls.data) || crls.size>4194304 || (roots.size && !roots.data) || roots.size>4194304 || !pin.data || pin.size<64 || pin.size>519 ||
           now<1577836800 || static_cast<int64_t>(static_cast<std::time_t>(now))!=now)
        { return {"SIG_002","Invalid native WSEA evidence bounds"}; }
        wsea::detail::manifest m;
        if(!wsea::detail::decode(view(cose),m))
        { return {"SIG_002","Unsupported or malformed embedded WSEA v2 COSE_Sign1"}; }
        // Go authorizes the real manifest against protected policy before this
        // adapter. Native decoding enforces the exact runtime wire profile too.
        // This adapter grants no policy or execution authorization.
        wsea::detail::rule rule;
        rule.id=m.id; rule.abi=m.abi;
        rule.capabilities=m.capabilities;
        auto pins=wsea::detail::split(view(pin),',');
        if(pins.empty() || pins.size()>8) { return {"POL_002","Invalid WSEA signer set"}; }
        for(auto item : pins)
        {
            if(item.size()!=64 || item.find_first_not_of("0123456789abcdef")!=std::string_view::npos)
            { return {"POL_002","Invalid WSEA signer pin"}; }
        }
        rule.signer=pins.front();
        for(std::size_t i{1}; i<pins.size(); ++i) { rule.additional_signers.emplace_back(pins[i]); }
        rule.algorithms=wsea::detail::profile_bit(*m.algorithm);
        wsea::detail::policy policy;
        policy.root_pem=view(roots); policy.max_age=max_age; policy.rules.push_back(std::move(rule));
        std::uint64_t expiry{m.after};
        std::string signer;
        auto result=wsea::detail::verify_crypto<false>(policy,m,view(certificates),view(crls),
            static_cast<std::time_t>(now),expiry,signer);
        wsea_result output{result.code,result.message,{}};
        if(result && signer.size()==64) { std::memcpy(output.signer,signer.data(),64); output.valid_until=expiry; }
        return output;
    }
    catch(...)
    { return {"SIG_005","Native WSEA verifier failed"}; }
}
