#!/usr/bin/env python3
"""Cross-check existing OpenSSL fixtures, Go signatures and production VM gates.

Run only inside the authorized Linux cgroup. This script reuses the supplied
PKI, creates a small, new protected test directory and never resets existing VM
state. The loader probe exercises the production parser/loader/initializer; it
does not execute guest instructions. The caller builds the exact Go secure
command through cli_main.go and supplies the production C++ probe binaries.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--go-cli", required=True, type=Path)
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument("--loader-probe", type=Path)
    parser.add_argument("--full-vm", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.fixtures = args.fixtures.resolve(strict=True)
    for key in ("go_cli", "verifier", "loader_probe", "full_vm"):
        if getattr(args,key) is not None:
            setattr(args, key, getattr(args, key).resolve(strict=True))
    if args.full_vm is None and args.loader_probe is None:
        parser.error("--full-vm or --loader-probe is required")
    args.loader_probe = args.full_vm or args.loader_probe
    out = args.output.absolute()
    out.mkdir(mode=0o700, exist_ok=False)
    os.chmod(out, 0o700)
    records = []

    def run(name, command, *, code=None, cpp=False):
        result = subprocess.run(
            [str(x) for x in command], capture_output=True, text=True, timeout=45
        )
        combined = result.stdout + result.stderr
        codes = re.findall(r"\b(?:SIG|CERT|POL|VM)_\d{3}\b", combined)
        passed = (
            result.returncode == 0 and (not cpp or result.stdout.strip() == "ALLOW")
            if code is None
            else result.returncode != 0 and code in codes
        )
        record = {
            "name": name,
            "command": [str(x) for x in command],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "expected_error": code,
            "observed_errors": codes,
            "passed": passed,
        }
        records.append(record)
        if not passed:
            raise RuntimeError(f"{name} failed: {record}")
        return record

    try:
        fixture = args.fixtures / "valid.wasm"
        old_policy = args.fixtures / "valid-policy" / "policy"
        rule_lines = [
            line.removeprefix("module=")
            for line in old_policy.read_text().splitlines()
            if line.startswith("module=")
        ]
        if len(rule_lines) != 1:
            raise RuntimeError("expected one known module rule in valid fixture")
        module_id = rule_lines[0].split("|")[0]
        root = args.fixtures / "trusted" / "root.pem"
        certificate = args.fixtures / "trusted" / "signer.pem"
        key = args.fixtures / "trusted" / "signer.key"
        crl = Path(str(fixture) + ".crl.pem")

        def bootstrap(name):
            policy = out / (name + ".policy")
            run(
                name + "-bootstrap",
                [args.go_cli, "policy-init", "--output", policy,
                 "--trust-root", root, "--state-dir", out / (name + "-state"),
                 "--certificate", certificate, "--module-id", module_id,
                 "--minimum-version", "1", "--minimum-epoch", "0",
                 "--capabilities", "63"],
            )
            return policy

        # Reverse direction: a separate, real OpenSSL-generated COSE fixture is
        # verified using Go, then the production C++ code and loader.
        openssl_policy = bootstrap("openssl")
        run("openssl-to-go", [args.go_cli, "verify", fixture, "--policy", openssl_policy])
        run("openssl-to-cpp", [args.verifier, openssl_policy, fixture], cpp=True)
        run("openssl-to-loader", [args.loader_probe, "--secure", "module", fixture,
                                  openssl_policy, "--run", fixture])

        # Forward direction: Go signs a byte-for-byte module snapshot and all
        # independent verifiers must accept the newly generated COSE encoding.
        module = out / "go-signed.wasm"
        module.write_bytes(fixture.read_bytes())
        os.chmod(module, 0o600)
        policy = bootstrap("go")
        now = datetime.datetime.now(datetime.timezone.utc)
        stamp = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
        run("go-sign", [args.go_cli, "sign", module, "--policy", policy,
                        "--key", key, "--certificate", certificate, "--crl", crl,
                        "--module-id", module_id, "--module-version", "100",
                        "--security-epoch", "100", "--capabilities", "63",
                        "--not-before", stamp(now - datetime.timedelta(minutes=1)),
                        "--not-after", stamp(now + datetime.timedelta(hours=1))])
        run("go-to-go", [args.go_cli, "verify", module, "--policy", policy])
        run("go-to-cpp", [args.verifier, policy, module], cpp=True)
        run("go-to-loader", [args.loader_probe, "--secure", "module", module,
                             policy, "--run", module])

        # Stable error-code parity for shared validation stages. Each case is
        # restored before the next; no protected monotonic state is reset.
        original_module = module.read_bytes()
        original_policy = policy.read_bytes()
        signature = Path(str(module) + ".sig.cose")
        original_signature = signature.read_bytes()

        def deny_pair(name, code):
            run(name + "-go", [args.go_cli, "verify", module, "--policy", policy], code=code)
            run(name + "-cpp", [args.verifier, policy, module], code=code, cpp=True)

        try:
            module.write_bytes(original_module + b"\x00\x01\x00")
            deny_pair("module-tamper", "SIG_004")
        finally:
            module.write_bytes(original_module)
        try:
            signature.write_bytes(b"\x00" + original_signature[1:])
            deny_pair("cose-malformed", "SIG_002")
        finally:
            signature.write_bytes(original_signature)
        try:
            text = original_policy.decode()
            old_rule = next(line for line in text.splitlines() if line.startswith("module="))
            fields = old_rule.split("|")
            fields[3] = "101"
            policy.write_text(text.replace(old_rule, "|".join(fields)))
            deny_pair("version-floor", "POL_001")
        finally:
            policy.write_bytes(original_policy)
        try:
            policy.write_bytes(original_policy.replace(b"max_crl_age_seconds=86400\n",
                                                      b"max_crl_age_seconds=86399\n"))
            deny_pair("same-version-policy-replacement", "POL_002")
        finally:
            policy.write_bytes(original_policy)
        run("final-go-valid", [args.go_cli, "verify", module, "--policy", policy])
        run("final-cpp-valid", [args.verifier, policy, module], cpp=True)
        # Authenticated revocation is a permanent publisher fact, not merely a
        # property of the most recently supplied evidence. This case is last:
        # no marker or protected monotonic state is ever cleared by the test.
        crl_sidecar = Path(str(module) + ".crl.pem")
        old_good_crl = crl_sidecar.read_bytes()
        revoked_crl = args.fixtures / "revoked.wasm.crl.pem"
        try:
            crl_sidecar.write_bytes(revoked_crl.read_bytes())
            run("cpp-learns-authenticated-revocation", [args.verifier, policy, module],
                code="CERT_004", cpp=True)
        finally:
            crl_sidecar.write_bytes(old_good_crl)
        signer_pin = next(line for line in policy.read_text().splitlines()
                          if line.startswith("module=")).split("|")[2]
        marker = out / "go-state" / ("revoked-" + signer_pin)
        if marker.is_symlink() or not marker.is_file() or marker.stat().st_mode & 0o777 != 0o600:
            raise RuntimeError("production verifier did not persist a safe publisher revocation marker")
        records.append({"name": "permanent-revocation-marker", "passed": True,
                        "path": str(marker), "mode": "0600"})
        deny_pair("old-good-crl-cannot-undo-known-revocation", "CERT_004")
        run("known-revocation-to-loader", [args.loader_probe, "--secure", "module", module,
                                          policy, "--run", module], code="CERT_004")
        success = True
    except Exception as error:
        success = False
        records.append({"name": "failure", "passed": False, "error": str(error)})
    report = {
        "passed": success,
        "scope": ("Go secure CLI; production C++ COSE/PKI verifier; actual production VM executing the fixture guest." if args.full_vm else "Go secure CLI; production C++ COSE/PKI verifier; production CLI parser/module loader/initializer. No guest instructions executed."),
        "records": records,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"passed": success, "checks": len(records), "report": str(out / "report.json")}))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
