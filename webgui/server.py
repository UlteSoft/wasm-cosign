#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors. Licensed under the Apache License, Version 2.0.
"""Local, dependency-free UI bridge to an explicitly supplied WSEA CLI.

No cryptography, compiler, downloader, shell, or private-key reader lives here.
Run: python3 webgui/server.py --binary /absolute/path/to/cosign
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ALGORITHMS = ("ES256", "ESP256", "ES384", "ESP384", "ES512", "ESP512", "Ed25519",
              "PS256", "PS384", "PS512", "RS256", "RS384", "RS512")
MAX_BODY = 64 * 1024
MAX_OUTPUT = 1024 * 1024
STATIC = Path(__file__).resolve().parent / "static"
# Each command's complete, explicitly allowed native flag set. Empty optional
# values are omitted, especially policy-update's Changed() patch semantics.
SCHEMAS = {
    "sign": {
        "module": "path!", "policy": "path!", "output": "path", "key": "path!",
        "certificate": "path!", "crl": "path!", "algorithm": "algorithm",
        "module-id": "text!", "module-version": "uint!", "security-epoch": "uint",
        "capabilities": "mask", "not-before": "time!", "not-after": "time!",
        "append-signature": "bool", "replace-signature": "bool", "allow-partial": "bool",
        "in-place": "bool",
    },
    "verify": {"module": "path!", "policy": "path!"},
    "fetch": {"output": "path!", "policy": "path!", "url": "url!"},
    "policy-init": {
        "output": "path!", "trust-root": "path!", "state-dir": "path!", "certificate": "path!",
        "additional-certificate": "paths", "signature-threshold": "threshold", "module-id": "text!",
        "algorithms": "algorithms", "policy-version": "uint", "minimum-version": "uint",
        "minimum-epoch": "uint", "capabilities": "mask", "max-crl-age-seconds": "uint",
        "max-module-bytes": "uint",
    },
    "policy-update": {
        "policy": "path!", "policy-version": "uint!", "trust-root": "path", "certificate": "path",
        "additional-certificate": "paths", "clear-additional-signers": "bool",
        "signature-threshold": "threshold", "module-id": "text", "algorithms": "algorithms",
        "minimum-version": "uint", "minimum-epoch": "uint", "capabilities": "mask",
        "max-crl-age-seconds": "uint", "max-module-bytes": "uint",
    },
}


class InputError(ValueError):
    pass


PUBLIC_COMMANDS = ("sign", "verify", "fetch", "policy-init", "policy-update")


def file_role(command, field):
    """Opaque capabilities are scoped to a file's purpose, not arbitrary paths."""
    if command not in PUBLIC_COMMANDS or SCHEMAS[command].get(field, "").rstrip("!") not in ("path", "paths"):
        raise InputError("INVALID_FIELD")
    if field == "output":
        return "policy-output" if command == "policy-init" else "module-output"
    return "certificate" if field == "additional-certificate" else field


def clean_path(value: str) -> str:
    if not os.path.isabs(value) or os.path.normpath(value) != value:
        raise InputError("Use a clean absolute local path (no . or .. components).")
    return value


def timestamp(value: str) -> dt.datetime:
    if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)", value):
        raise InputError("Use an RFC3339 timestamp, for example 2026-01-01T00:00:00Z.")
    try:
        result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.timestamp() < 0:
            raise ValueError()
        return result
    except ValueError as exc:
        raise InputError("Invalid RFC3339 timestamp or time before the Unix epoch.") from exc


def build_argv(binary: str, command: str, fields: dict) -> list[str]:
    if not isinstance(command, str) or command not in SCHEMAS or not isinstance(fields, dict):
        raise InputError("Unsupported command or fields object.")
    schema = SCHEMAS[command]
    if set(fields) - set(schema):
        raise InputError("Unknown fields: " + ", ".join(sorted(set(fields) - set(schema))))
    values = {}
    for name, spec in schema.items():
        value = fields.get(name)
        kind = spec.rstrip("!")
        if kind == "bool":
            if value is not None and not isinstance(value, bool):
                raise InputError(name + ": expected a boolean.")
            if value:
                values[name] = True
            continue
        if value is None or value == "" or value == []:
            if spec.endswith("!"):
                raise InputError(name + ": required.")
            continue
        if kind == "paths":
            if not isinstance(value, list) or len(value) > 7:
                raise InputError(name + ": at most seven additional certificate paths.")
            for path in value:
                if not isinstance(path, str) or not path or len(path) > 4096 or any(ord(c) < 32 for c in path):
                    raise InputError(name + ": invalid certificate path.")
                clean_path(path)
            values[name] = value
            continue
        # Uint64 values stay decimal strings end to end, including in JavaScript.
        if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 for c in value):
            raise InputError(name + ": expected a short text value without control characters.")
        if kind == "path":
            clean_path(value)
        elif kind in ("uint", "mask", "threshold"):
            limit = 63 if kind == "mask" else 8 if kind == "threshold" else 2**64 - 1
            if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})", value) or int(value) > limit or (kind == "threshold" and int(value) < 1):
                raise InputError(name + ": invalid unsigned decimal integer.")
        elif kind in ("algorithm", "algorithms"):
            chosen = value.split(",")
            if any(a not in ALGORITHMS for a in chosen) or len(set(chosen)) != len(chosen) or (kind == "algorithm" and len(chosen) != 1):
                raise InputError(name + ": use exact supported algorithm names, without duplicates.")
        elif kind == "time":
            timestamp(value)
        elif kind == "url":
            try:
                parsed = urlsplit(value)
                valid = parsed.scheme == "https" and parsed.hostname and parsed.username is None and parsed.password is None and not parsed.fragment
                _ = parsed.port
            except ValueError:
                valid = False
            if not valid:
                raise InputError("url: use an HTTPS URL without credentials or a fragment.")
        values[name] = value
    if command == "sign":
        if values.get("append-signature") and values.get("replace-signature"):
            raise InputError("Append and replace are mutually exclusive.")
        if values.get("in-place"):
            if values.get("output") and values["output"] != values["module"]:
                raise InputError("In-place signing cannot also select another output.")
            values.pop("output", None)
        elif not values.get("output") or values["output"] == values["module"]:
            raise InputError("Choose a new output path or explicitly enable in-place signing.")
        if timestamp(values["not-after"]) <= timestamp(values["not-before"]):
            raise InputError("not-after must be later than not-before.")
    if command == "policy-update":
        if values.get("clear-additional-signers") and values.get("additional-certificate"):
            raise InputError("Cannot clear and replace additional signers together.")
        rule_fields = {"certificate", "additional-certificate", "clear-additional-signers", "signature-threshold",
                       "algorithms", "minimum-version", "minimum-epoch", "capabilities"}
        if rule_fields.intersection(values) and not values.get("module-id"):
            raise InputError("Module rule changes require module-id.")
    args = [binary, "wasm", "secure", command]
    positional = values.get("module") if command in ("sign", "verify") else values.get("output") if command == "fetch" else None
    for name, value in values.items():
        if name in ("module", "in-place") or (command == "fetch" and name == "output"):
            continue
        if value is True:
            args.append("--" + name)
        else:
            for item in value if isinstance(value, list) else [value]:
                args.append("--" + name + "=" + item)
    if positional is not None:
        args += ["--", positional]
    return args


def stop_process(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def run_bounded(argv: list[str], timeout: float, stop: threading.Event | None = None,
                output_limit: int = MAX_OUTPUT) -> dict:
    """Drain both pipes without unbounded buffering; terminate on timeout/overflow.

    Mutating commands are never automatically retried: interruption may occur
    after a native atomic write. The caller reports this uncertainty explicitly.
    """
    started = time.monotonic()
    options = {"start_new_session": True, "umask": 0o077} if os.name == "posix" else {}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False, **options)
    except OSError as exc:
        return {"exit_code": None, "stdout": "", "stderr": str(exc), "interrupted": "launch", "seconds": 0}
    buffers = [bytearray(), bytearray()]
    overflow = threading.Event()
    size_lock = threading.Lock()

    def drain(pipe, index):
        try:
            while True:
                chunk = pipe.read(8192)
                if not chunk:
                    break
                with size_lock:
                    room = max(0, output_limit - sum(map(len, buffers)))
                    buffers[index].extend(chunk[:room])
                    if len(chunk) > room:
                        overflow.set()
        finally:
            pipe.close()

    readers = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
               for i, pipe in enumerate((process.stdout, process.stderr))]
    for thread in readers:
        thread.start()
    reason = None
    while process.poll() is None or any(t.is_alive() for t in readers):
        if overflow.is_set():
            reason = "output-limit"
        elif stop is not None and stop.is_set():
            reason = "server-stopped"
        elif time.monotonic() - started > timeout:
            reason = "timeout"
        if reason:
            stop_process(process)
            break
        time.sleep(0.02)
    process.wait()
    for thread in readers:
        thread.join(timeout=2)
    if overflow.is_set():
        reason = "output-limit"
    return {"exit_code": process.returncode, "stdout": buffers[0].decode("utf-8", "replace"),
            "stderr": buffers[1].decode("utf-8", "replace"), "interrupted": reason,
            "seconds": round(time.monotonic() - started, 3)}


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate field")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("Non-JSON number")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def public_manifest(document):
    """Positive schema: never forward a native JSON object wholesale."""
    m = document["manifest"]
    if not isinstance(m, dict) or m.get("embedded") is not True:
        raise ValueError()
    ident = m.get("module_id")
    if not isinstance(ident, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", ident):
        raise ValueError()
    result = {"module_id": ident}
    for field in ("version", "security_epoch", "capabilities", "not_before", "not_after"):
        v = m[field]
        if type(v) is not int or not 0 <= v <= 2**64 - 1:
            raise ValueError()
        result[field] = str(v)
    if m["version"] == 0 or m["capabilities"] > 63 or m["not_after"] <= m["not_before"]:
        raise ValueError()
    algs, signers = m["signature_algorithms"], m["signer_spkis"]
    if (not isinstance(algs, list) or not 1 <= len(algs) <= 8 or any(a not in ALGORITHMS for a in algs)
            or not isinstance(signers, list) or not 1 <= len(signers) <= len(algs)
            or any(not isinstance(s, str) or not re.fullmatch(r"[a-f0-9]{64}", s) for s in signers)
            or len(set(signers)) != len(signers)):
        raise ValueError()
    result.update(signature_algorithms=algs, signer_count=len(signers))
    return result


def native_error(stderr):
    # Only fixed codes cross HTTP; never the surrounding message or path.
    match = re.match(r"(?:Error: )?((?:SIG_00[1-5]|CERT_00[1-6]|POL_00[1-4]|VM_001)):", stderr)
    return match[1] if match else "OPERATION_FAILED"


def choose_local_file(role, language, stop):
    # A separate desktop process owns the OS dialog and its path. The browser
    # never enumerates a directory, uploads a key, or supplies a filesystem path.
    r = run_bounded([sys.executable, str(Path(__file__).with_name("native_picker.py")),
                     role, language], 300, stop, output_limit=8192)
    if r["exit_code"] == 2 and not r["interrupted"]:
        return None
    if r["exit_code"] != 0 or r["interrupted"]:
        raise InputError("PICKER_UNAVAILABLE")
    return strict_json(r["stdout"])["path"]


class Application:
    def __init__(self, binary: Path, timeout: int = 120, picker=choose_local_file):
        self.binary = str(binary.resolve(strict=True))
        if not Path(self.binary).is_file() or not os.access(self.binary, os.X_OK):
            raise InputError("--binary must be an existing executable file.")
        probe = run_bounded([self.binary, "version"], min(timeout, 10), output_limit=4096)
        if (probe["exit_code"] != 0 or probe["interrupted"]
                or not re.fullmatch(r"wasm-cosign [^\r\n]+ WSEA v2", probe["stdout"].strip())):
            raise InputError("The supplied executable did not identify itself as wasm-cosign WSEA v2.")
        self.timeout = timeout
        self.picker = picker
        self.token = secrets.token_urlsafe(32)
        self.stop = threading.Event()
        self.lock = threading.RLock()
        # Public jobs and private execution inputs are deliberately separate.
        self.jobs = collections.OrderedDict()
        self.inputs = {}
        self.files = {}
        self.selections = collections.OrderedDict()
        self.active = None
        self.selecting = None
        self.worker = None
        self.picker_worker = None

    def config(self):
        with self.lock:
            return {"algorithms": ALGORITHMS, "active_job": self.active,
                    "selection": self.selecting, "jobs": list(self.jobs.values())[::-1]}

    def register_file(self, path, role):
        """Only desktop selection / successful native output calls this method."""
        if not isinstance(path, str) or len(path) > 4096 or any(ord(c) < 32 for c in path):
            raise InputError("FILE_UNAVAILABLE")
        path = clean_path(path)
        if role in ("module-output", "policy-output", "state-dir"):
            if not Path(path).parent.is_dir():
                raise InputError("FILE_UNAVAILABLE")
        elif not Path(path).is_file():
            raise InputError("FILE_UNAVAILABLE")
        with self.lock:
            if len(self.files) >= 512:
                raise InputError("SESSION_FULL")
            ident = secrets.token_hex(16)
            self.files[ident] = {"path": path, "role": role}
            return {"id": ident, "name": Path(path).name}

    def resolve_fields(self, command, fields):
        if command not in PUBLIC_COMMANDS or not isinstance(fields, dict) or set(fields) - set(SCHEMAS[command]):
            raise InputError("INVALID_INPUT")
        result = dict(fields)
        for field, spec in SCHEMAS[command].items():
            if spec.rstrip("!") not in ("path", "paths") or fields.get(field) in (None, "", []):
                continue
            many = spec == "paths"
            refs = fields[field] if many else [fields[field]]
            if not isinstance(refs, list) or len(refs) > 7:
                raise InputError("INVALID_SELECTION")
            resolved = []
            for ref in refs:
                entry = self.files.get(ref) if isinstance(ref, str) else None
                if not entry or entry["role"] != file_role(command, field):
                    raise InputError("INVALID_SELECTION")
                resolved.append(entry["path"])
            result[field] = resolved if many else resolved[0]
        return result

    def select_file(self, command, field, language):
        role = file_role(command, field)
        if language not in ("zh", "en"):
            raise InputError("INVALID_INPUT")
        with self.lock:
            if self.active or self.selecting or self.stop.is_set():
                raise InputError("BUSY")
            ident = secrets.token_hex(12)
            selection = {"id": ident, "state": "picking"}
            self.selections[ident] = selection
            while len(self.selections) > 20:
                self.selections.popitem(last=False)
            self.selecting = ident
            self.picker_worker = threading.Thread(target=self._select, args=(ident, role, language), daemon=True)
            self.picker_worker.start()
            return dict(selection)

    def _select(self, ident, role, language):
        try:
            path = self.picker(role, language, self.stop)
            result = {"state": "selected", "file": self.register_file(path, role)} if path else {"state": "cancelled"}
        except Exception:
            result = {"state": "failed", "error": "PICKER_UNAVAILABLE"}
        with self.lock:
            self.selections[ident] = {"id": ident, **result}
            self.selecting = None

    def get_selection(self, ident):
        with self.lock:
            if ident not in self.selections:
                raise InputError("NOT_FOUND")
            return dict(self.selections[ident])

    def submit(self, command, fields):
        with self.lock:
            if self.active or self.selecting or self.stop.is_set():
                raise InputError("BUSY")
            resolved = self.resolve_fields(command, fields)
            argv = build_argv(self.binary, command, resolved)
            ident = secrets.token_hex(12)
            job = {"id": ident, "command": command, "state": "running"}
            self.jobs[ident] = job
            self.inputs[ident] = resolved
            while len(self.jobs) > 20:
                expired, _ = self.jobs.popitem(last=False)
                self.inputs.pop(expired, None)
            self.active = ident
            self.worker = threading.Thread(target=self._execute, args=(ident, argv), daemon=True)
            self.worker.start()
            return dict(job)

    def close(self):
        self.stop.set()
        for worker in (self.worker, self.picker_worker):
            if worker is not None:
                worker.join(timeout=6)
        with self.lock:
            self.files.clear()
            self.inputs.clear()

    def _execute(self, ident, argv):
        public = {"state": "failed", "error": "OPERATION_FAILED"}
        try:
            result = run_bounded(argv, self.timeout, self.stop)
            command = self.jobs[ident]["command"]
            if result["interrupted"]:
                public = {"state": "interrupted", "error": "INTERRUPTED"}
            elif result["exit_code"] != 0:
                public["error"] = native_error(result["stderr"])
            elif command in ("sign", "verify", "fetch"):
                try:
                    document = strict_json(result["stdout"])
                    status = document["status"]
                    if status not in ("VERIFIED", "SIGNED_PARTIAL"):
                        raise ValueError()
                    if status == "SIGNED_PARTIAL" and (command != "sign" or not self.inputs[ident].get("allow-partial")):
                        raise ValueError()
                    manifest = public_manifest(document)
                    public = {"state": "partial" if status == "SIGNED_PARTIAL" else "succeeded",
                              "document": {"status": status, "manifest": manifest}}
                except (ValueError, KeyError, TypeError, RecursionError):
                    public = {"state": "failed", "error": "INVALID_RESULT"}
            else:
                # Current native policy commands have no JSON flag. Their text
                # contains local paths: discard it and map the exit status only.
                public = {"state": "succeeded", "document": {"status": "COMPLETED"}}
        except Exception:
            public = {"state": "interrupted", "error": "INTERRUPTED"}
        finally:
            with self.lock:
                self.jobs[ident] = {"id": ident, "command": self.jobs[ident]["command"], **public}
                self.active = None

    def get_job(self, ident):
        with self.lock:
            if ident not in self.jobs:
                raise InputError("NOT_FOUND")
            return dict(self.jobs[ident])

    def next_operation(self, ident, action):
        """Reuse selected inputs without sending paths, keys, or diagnostics."""
        with self.lock:
            job = self.get_job(ident)
            if job["state"] not in ("succeeded", "partial") or self.active or self.selecting:
                raise InputError("BUSY")
            original = self.inputs[ident]
            fields, files = {}, {}

            def use(field, path, role):
                selected = self.register_file(path, role)
                files[selected["id"]] = selected["name"]
                fields[field] = selected["id"]

            if action in ("append", "verify") and job["command"] in ("sign", "fetch", "verify"):
                use("module", original.get("output") or original["module"], "module")
                use("policy", original["policy"], "policy")
                command = "verify" if action == "verify" else "sign"
                if action == "append":
                    m = job["document"]["manifest"]
                    # Format timestamps on the server, without JS number loss.
                    try:
                        times = {dst: dt.datetime.fromtimestamp(int(m[src]), dt.timezone.utc).isoformat().replace("+00:00", "Z")
                                 for src, dst in (("not_before", "not-before"), ("not_after", "not-after"))}
                    except (ValueError, OverflowError, OSError):
                        raise InputError("INVALID_INPUT") from None
                    fields.update({"module-id": m["module_id"], "module-version": m["version"],
                                   "security-epoch": m["security_epoch"], "capabilities": m["capabilities"],
                                   "algorithm": "ES256", "append-signature": True,
                                   "allow-partial": job["state"] == "partial", **times})
            elif action == "use-policy" and job["command"] in ("policy-init", "policy-update"):
                use("policy", original.get("output") or original["policy"], "policy")
                command = "sign"
            else:
                raise InputError("INVALID_INPUT")
            return {"command": command, "fields": fields, "files": files}


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, address, app):
        self.app = app
        self.slots = threading.BoundedSemaphore(24)
        super().__init__(address, Handler)
        self.origin = "http://127.0.0.1:" + str(self.server_port)
        self.authority = "127.0.0.1:" + str(self.server_port)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def server_close(self):
        self.app.close()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "WSEA-Local"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *_):
        pass  # No request/token/path logs or persistent operation history.

    def send_error(self, code, message=None, explain=None):
        # BaseHTTPRequestHandler's HTML diagnostics are not part of our API.
        self.respond(code, {"error": "REQUEST_REJECTED"})

    def respond(self, code, data, content_type="application/json; charset=utf-8"):
        raw = json.dumps(data, ensure_ascii=True).encode() if isinstance(data, (dict, list)) else data
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def gate(self, authenticated=False):
        if self.headers.get_all("Host", []) != [self.server.authority]:
            self.respond(403, {"error": "REQUEST_REJECTED"})
            return False
        origins = self.headers.get_all("Origin", [])
        if (origins and origins != [self.server.origin]) or self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            self.respond(403, {"error": "REQUEST_REJECTED"})
            return False
        if authenticated:
            auth = self.headers.get_all("Authorization", [])
            expected = "Bearer " + self.server.app.token
            if len(auth) != 1 or not hmac.compare_digest(auth[0].encode(), expected.encode()):
                self.respond(401, {"error": "SESSION_REQUIRED"})
                return False
            if self.command == "POST" and origins != [self.server.origin]:
                self.respond(403, {"error": "REQUEST_REJECTED"})
                return False
        return True

    def do_GET(self):
        if not self.gate(self.path.startswith("/api/")):
            return
        if self.path == "/api/config":
            self.respond(200, self.server.app.config())
        elif re.fullmatch(r"/api/jobs/[a-f0-9]{24}", self.path):
            try:
                self.respond(200, self.server.app.get_job(self.path.rsplit("/", 1)[1]))
            except InputError:
                self.respond(404, {"error": "NOT_FOUND"})
        elif re.fullmatch(r"/api/selections/[a-f0-9]{24}", self.path):
            try:
                self.respond(200, self.server.app.get_selection(self.path.rsplit("/", 1)[1]))
            except InputError:
                self.respond(404, {"error": "NOT_FOUND"})
        elif self.path in ("/", "/app.js", "/style.css", "/mark.svg"):
            name, content_type = {"/": ("index.html", "text/html; charset=utf-8"),
                                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                                  "/style.css": ("style.css", "text/css; charset=utf-8"),
                                  "/mark.svg": ("mark.svg", "image/svg+xml")}[self.path]
            self.respond(200, (STATIC / name).read_bytes(), content_type)
        else:
            self.respond(404, {"error": "NOT_FOUND"})

    def do_POST(self):
        if not self.gate(True):
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
                raise InputError("A single Content-Length is required; transfer encoding is not supported.")
            size = int(lengths[0])
            if size > MAX_BODY:
                self.respond(413, {"error": "REQUEST_TOO_LARGE"})
                return
            if self.headers.get_content_type() != "application/json":
                self.respond(415, {"error": "JSON_REQUIRED"})
                return
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise InputError("Incomplete request.")

            data = strict_json(raw)
            if not isinstance(data, dict):
                raise InputError("Expected a JSON object.")
            if self.path == "/api/selections":
                if set(data) != {"command", "field", "language"}:
                    raise InputError("INVALID_INPUT")
                self.respond(202, self.server.app.select_file(data["command"], data["field"], data["language"]))
            elif self.path == "/api/jobs":
                if set(data) != {"command", "fields"}:
                    raise InputError("Expected command and fields only.")
                self.respond(202, self.server.app.submit(data["command"], data["fields"]))
            elif re.fullmatch(r"/api/jobs/[a-f0-9]{24}/next", self.path):
                if set(data) != {"action"}:
                    raise InputError("INVALID_INPUT")
                self.respond(200, self.server.app.next_operation(self.path.split("/")[3], data["action"]))
            else:
                self.respond(404, {"error": "NOT_FOUND"})
        except (InputError, ValueError, UnicodeError, OSError, RecursionError, TypeError, KeyError) as exc:
            allowed = {"BUSY", "INVALID_SELECTION", "FILE_UNAVAILABLE", "SESSION_FULL", "NOT_FOUND"}
            code = str(exc) if isinstance(exc, InputError) and str(exc) in allowed else "INVALID_INPUT"
            self.respond(400, {"error": code})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Existing native wasm-cosign executable; never built or downloaded")
    parser.add_argument("--port", type=int, default=8765, help="Loopback HTTP port (0 selects a free port; default: 8765)")
    parser.add_argument("--timeout", type=int, default=120, help="Native command deadline in seconds (1..3600, default: 120)")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or not 1 <= args.timeout <= 3600:
        parser.error("Invalid port or timeout.")
    os.umask(0o077)
    try:
        app = Application(args.binary, args.timeout)
        server = LocalServer(("127.0.0.1", args.port), app)
    except (OSError, InputError) as exc:
        parser.error(str(exc))
    print("WSEA Studio · local Web GUI", flush=True)
    print("Open this private session link in your browser:\n" + server.origin + "/#token=" + app.token, flush=True)
    print("Only 127.0.0.1 is bound. Ctrl+C stops the server. No automatic builds or downloads.", flush=True)

    def interrupted(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
