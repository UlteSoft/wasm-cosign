#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors.
# Licensed under the Apache License, Version 2.0.
"""Generate and verify a complete signed critical-policyConstraints negative fixture.

Run inside the approved Linux cgroup. No production source or existing fixture
is modified. All keys, CA databases, CRLs and output remain in the new output dir.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def cbor(value):
    def head(major, number):
        if number < 24:
            return bytes([(major << 5) | number])
        for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if number < 1 << (8 * size):
                return bytes([(major << 5) | extra]) + number.to_bytes(size, "big")
        raise ValueError("CBOR integer out of range")
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, str):
        data = value.encode()
        return head(3, len(data)) + data
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(x) for x in value)
    if value == {}:
        return b"\xa0"
    raise ValueError("unsupported CBOR value")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--old-verifier", type=Path)
    parser.add_argument("--go-cli", required=True, type=Path)
    parser.add_argument("--full-vm", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    out = args.output.absolute()
    out.mkdir(mode=0o700)
    records = []

    def execute(command, name=None, expected=None):
        result = subprocess.run([str(x) for x in command], capture_output=True, timeout=30)
        text = (result.stdout + result.stderr).decode(errors="replace")
        if name:
            passed = result.returncode != 0 and expected in text if expected else result.returncode == 0
            records.append({"name": name, "returncode": result.returncode,
                            "output": text, "expected": expected, "passed": passed})
            if not passed:
                raise RuntimeError(name + ": " + text)
        elif result.returncode:
            raise RuntimeError("openssl fixture generation failed: " + text)
        return result

    try:
        for name in ("root", "intermediate", "signer"):
            execute(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                     "ec_paramgen_curve:P-256", "-out", out / (name + ".key")])
        execute(["openssl", "req", "-new", "-x509", "-key", out / "root.key",
                 "-out", out / "root.pem", "-sha256", "-days", "2", "-subj", "/CN=WSEA Policy Root",
                 "-addext", "basicConstraints=critical,CA:true", "-addext",
                 "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash"])
        for name in ("intermediate", "signer"):
            execute(["openssl", "req", "-new", "-key", out / (name + ".key"),
                     "-out", out / (name + ".csr"), "-subj", "/CN=WSEA Policy " + name])
        (out / "intermediate.ext").write_text("[ext]\nbasicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\npolicyConstraints=critical,requireExplicitPolicy:0\n")
        (out / "signer.ext").write_text("[ext]\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always,issuer\n")
        for name, issuer, serial in (("intermediate", "root", "2"), ("signer", "intermediate", "3")):
            execute(["openssl", "x509", "-req", "-in", out / (name + ".csr"),
                     "-CA", out / (issuer + ".pem"), "-CAkey", out / (issuer + ".key"),
                     "-set_serial", serial, "-days", "2", "-sha256", "-extfile",
                     out / (name + ".ext"), "-extensions", "ext", "-out", out / (name + ".pem")])
        (out / "certs").mkdir(mode=0o700)
        for issuer in ("root", "intermediate"):
            (out / (issuer + ".serial")).write_text("1000\n")
            (out / (issuer + ".index")).write_text("")
            (out / (issuer + ".crlnumber")).write_text("1000\n")
            config = out / (issuer + ".cnf")
            config.write_text(f"[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={out / (issuer + '.index')}\ncertificate={out / (issuer + '.pem')}\nprivate_key={out / (issuer + '.key')}\ncrlnumber={out / (issuer + '.crlnumber')}\ndefault_md=sha256\ndefault_crl_days=1\ndefault_days=2\nnew_certs_dir={out / 'certs'}\nserial={out / (issuer + '.serial')}\npolicy=policy_any\n[policy_any]\ncommonName=supplied\n")
            execute(["openssl", "ca", "-gencrl", "-batch", "-config", config,
                     "-out", out / (issuer + ".crl.pem")])
        module = out / "policy-constraint.wasm"
        module.write_bytes(b"\x00asm\x01\x00\x00\x00")
        now = int(time.time())
        protected = b"\xa1\x01\x26"
        payload = cbor(["uwvm-wsea-v1", "policy.constraint.test", 1, 0, 8,
                        hashlib.sha256(module.read_bytes()).digest(), now - 60, now + 3600, "uwvm2", 0])
        (out / "sig-structure.bin").write_bytes(cbor(["Signature1", protected, b"", payload]))
        execute(["openssl", "dgst", "-sha256", "-sign", out / "signer.key",
                 "-out", out / "signature.der", out / "sig-structure.bin"])
        der = (out / "signature.der").read_bytes()
        if der[0] != 0x30 or der[1] != len(der) - 2 or der[2] != 2:
            raise RuntimeError("unexpected P-256 DER signature")
        rlen = der[3]
        r = int.from_bytes(der[4:4+rlen], "big")
        pos = 4 + rlen
        if der[pos] != 2 or pos + 2 + der[pos+1] != len(der):
            raise RuntimeError("unexpected P-256 DER integer")
        s = int.from_bytes(der[pos+2:], "big")
        order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        s = min(s, order - s)
        Path(str(module) + ".sig.cose").write_bytes(b"\xd2" + cbor([protected, {}, payload, r.to_bytes(32,"big") + s.to_bytes(32,"big")]))
        Path(str(module) + ".signer.pem").write_bytes((out / "signer.pem").read_bytes() + (out / "intermediate.pem").read_bytes())
        Path(str(module) + ".crl.pem").write_bytes((out / "root.crl.pem").read_bytes() + (out / "intermediate.crl.pem").read_bytes())
        execute(["openssl", "x509", "-in", out / "signer.pem", "-pubkey", "-noout", "-out", out / "signer.pub.pem"])
        execute(["openssl", "pkey", "-pubin", "-in", out / "signer.pub.pem", "-outform", "DER", "-out", out / "signer.spki.der"])
        pin = hashlib.sha256((out / "signer.spki.der").read_bytes()).hexdigest()
        state = out / "state-dir"
        state.mkdir(mode=0o700)
        (state / "state").write_text("UWVM-WSEA-STATE-1\n0 0 -\n")
        (state / "state").chmod(0o600)
        policy = out / "policy"
        policy.write_text(f"UWVM-WSEA-POLICY-1\npolicy_version=1\ntrust_root={out / 'root.pem'}\nstate_dir={state}\nmax_crl_age_seconds=86400\nmax_module_bytes=104857600\nmodule=policy.constraint.test|uwvm2|{pin}|1|0|0\n")
        policy.chmod(0o600)
        if args.old_verifier:
            result = execute([args.old_verifier, policy, module])
            records.append({"name":"old-verifier-observation", "returncode":result.returncode,
                            "output":(result.stdout+result.stderr).decode(errors="replace"), "passed":True})
        execute([args.verifier, policy, module], "new-policy-check-denies", "CERT_002")
        execute([args.go_cli, "verify", module, "--policy", policy], "go-policy-check-denies", "CERT_002")
        if args.full_vm:
            execute([args.full_vm, "--secure", "module", module, policy, "--run", module],
                    "production-vm-policy-check-denies", "CERT_002")
        passed = True
    except Exception as error:
        passed = False
        records.append({"name":"failure", "passed":False, "error":str(error)})
    report = {"passed":passed, "scope":"critical requireExplicitPolicy:0 CA with missing certificatePolicies leaf, complete legitimate COSE/PKI/CRLs", "records":records}
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed":passed,"report":str(out / "report.json")}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
