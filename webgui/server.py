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
import shlex
import signal
import subprocess
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
    "help": {"topic": "topic"},
    "version": {},
}


class InputError(ValueError):
    pass


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
        elif kind == "topic" and value not in ("root", "secure", "sign", "verify", "fetch", "policy-init", "policy-update"):
            raise InputError("Unknown help topic.")
        values[name] = value
    if command == "version":
        return [binary, "version"]
    if command == "help":
        topic = values.get("topic", "secure")
        return [binary, *([] if topic == "root" else ["wasm", "secure"]), *([] if topic in ("root", "secure") else [topic]), "--help"]
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


def display_command(argv: list[str]) -> str:
    return subprocess.list2cmdline(argv) if os.name == "nt" else shlex.join(argv)


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


def exact_json(value):
    """Keep uint64 manifest fields exact in browsers (no floating-point loss)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return [exact_json(v) for v in value]
    if isinstance(value, dict):
        return {k: exact_json(v) for k, v in value.items()}
    return value


class Application:
    def __init__(self, binary: Path, browse_roots: list[Path], timeout: int = 120):
        self.binary = str(binary.resolve(strict=True))
        if not Path(self.binary).is_file() or not os.access(self.binary, os.X_OK):
            raise InputError("--binary must be an existing executable file.")
        probe = run_bounded([self.binary, "version"], min(timeout, 10), output_limit=4096)
        self.version = probe["stdout"].strip()
        if probe["exit_code"] != 0 or probe["interrupted"] or not re.fullmatch(r"wasm-cosign [^\r\n]+ WSEA v2", self.version):
            raise InputError("The supplied executable did not identify itself as wasm-cosign WSEA v2.")
        self.roots = list(dict.fromkeys(str(p.resolve(strict=True)) for p in browse_roots))
        if not self.roots or any(not Path(p).is_dir() for p in self.roots):
            raise InputError("--browse-root must name existing directories.")
        self.timeout = timeout
        self.token = secrets.token_urlsafe(32)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.jobs = collections.OrderedDict()
        self.active = None
        self.worker = None

    def config(self):
        with self.lock:
            return {"binary": self.binary, "version": self.version, "algorithms": ALGORITHMS,
                    "browse_roots": self.roots, "timeout": self.timeout, "active_job": self.active,
                    "commands": list(SCHEMAS), "jobs": list(self.jobs.values())[::-1]}

    def submit(self, command, fields):
        argv = build_argv(self.binary, command, fields)
        with self.lock:
            if self.active is not None or self.stop.is_set():
                raise InputError("Another operation is running. Wait for its result before starting another.")
            ident = secrets.token_hex(12)
            job = {"id": ident, "command": command, "fields": fields, "argv": argv,
                   "display": display_command(argv), "state": "running", "started": time.time()}
            self.jobs[ident] = job
            while len(self.jobs) > 20:
                self.jobs.popitem(last=False)
            self.active = ident
            self.worker = threading.Thread(target=self._execute, args=(ident, argv), daemon=True)
            self.worker.start()
        return dict(job)

    def close(self):
        self.stop.set()
        with self.lock:
            worker = self.worker
        if worker is not None:
            worker.join(timeout=6)

    def _execute(self, ident, argv):
        result = run_bounded(argv, self.timeout, self.stop)
        state = "failed"
        document = None
        if result["interrupted"]:
            state = "interrupted"
        elif result["exit_code"] == 0:
            state = "succeeded"
            if self.jobs[ident]["command"] in ("sign", "verify", "fetch"):
                try:
                    document = json.loads(result["stdout"])
                    status = document["status"]
                    if status not in ("VERIFIED", "SIGNED_PARTIAL") or not isinstance(document["manifest"], dict):
                        raise ValueError()
                    if status == "SIGNED_PARTIAL":
                        if self.jobs[ident]["command"] != "sign" or not self.jobs[ident]["fields"].get("allow-partial"):
                            raise ValueError()
                        state = "partial"
                except (ValueError, KeyError, TypeError):
                    state = "failed"
                    document = None
                    result["protocol_error"] = "CLI returned unexpected verification output; no success is asserted."
        with self.lock:
            self.jobs[ident] = {**self.jobs[ident], **result, "state": state,
                                "document": exact_json(document), "finished": time.time()}
            self.active = None

    def get_job(self, ident):
        with self.lock:
            if ident not in self.jobs:
                raise InputError("Unknown or expired session operation.")
            return dict(self.jobs[ident])

    def browse(self, path):
        if not isinstance(path, str) or len(path) > 4096:
            raise InputError("Invalid directory.")
        target = Path(path).resolve(strict=True)
        roots = [Path(p) for p in self.roots]
        if not any(target == root or root in target.parents for root in roots):
            raise InputError("Directory is outside the configured file-picker roots.")
        entries = []
        truncated = False
        with os.scandir(target) as iterator:
            for entry in iterator:
                # No file contents, symlink navigation, or hidden executable commands.
                if entry.is_symlink():
                    continue
                if len(entries) == 1000:
                    truncated = True
                    break
                try:
                    if entry.is_dir(follow_symlinks=False):
                        kind = "directory"
                    elif entry.is_file(follow_symlinks=False):
                        kind = "file"
                    else:
                        continue
                    entries.append({"name": entry.name, "path": str(target / entry.name), "kind": kind})
                except OSError:
                    continue
        parent = target.parent
        parent_allowed = parent != target and any(parent == r or r in parent.parents for r in roots)
        return {"path": str(target), "parent": str(parent) if parent_allowed else None,
                "entries": sorted(entries, key=lambda e: (e["kind"] != "directory", e["name"].lower())),
                "truncated": truncated}


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
            self.respond(403, {"error": "Use the exact loopback URL printed by the server."})
            return False
        origins = self.headers.get_all("Origin", [])
        if (origins and origins != [self.server.origin]) or self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            self.respond(403, {"error": "Cross-origin requests are not allowed."})
            return False
        if authenticated:
            auth = self.headers.get_all("Authorization", [])
            expected = "Bearer " + self.server.app.token
            if len(auth) != 1 or not hmac.compare_digest(auth[0].encode(), expected.encode()):
                self.respond(401, {"error": "Open the session link printed in the server terminal."})
                return False
            if self.command == "POST" and origins != [self.server.origin]:
                self.respond(403, {"error": "A same-origin request is required."})
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
            except InputError as exc:
                self.respond(404, {"error": str(exc)})
        elif self.path in ("/", "/app.js", "/style.css", "/mark.svg"):
            name, content_type = {"/": ("index.html", "text/html; charset=utf-8"),
                                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                                  "/style.css": ("style.css", "text/css; charset=utf-8"),
                                  "/mark.svg": ("mark.svg", "image/svg+xml")}[self.path]
            self.respond(200, (STATIC / name).read_bytes(), content_type)
        else:
            self.respond(404, {"error": "Not found."})

    def do_POST(self):
        if not self.gate(True):
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isdigit():
                raise InputError("A single Content-Length is required; transfer encoding is not supported.")
            size = int(lengths[0])
            if size > MAX_BODY:
                self.respond(413, {"error": "Request too large."})
                return
            if self.headers.get_content_type() != "application/json":
                self.respond(415, {"error": "JSON is required."})
                return
            raw = self.rfile.read(size)
            if len(raw) != size:
                raise InputError("Incomplete request.")

            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise InputError("Duplicate JSON field.")
                    result[key] = value
                return result

            data = json.loads(raw, object_pairs_hook=unique_object)
            if not isinstance(data, dict):
                raise InputError("Expected a JSON object.")
            if self.path == "/api/browse":
                if set(data) != {"path"}:
                    raise InputError("Expected directory path only.")
                self.respond(200, self.server.app.browse(data["path"]))
            elif self.path in ("/api/preview", "/api/jobs"):
                if set(data) != {"command", "fields"}:
                    raise InputError("Expected command and fields only.")
                argv = build_argv(self.server.app.binary, data["command"], data["fields"])
                if self.path == "/api/preview":
                    self.respond(200, {"argv": argv, "display": display_command(argv)})
                else:
                    self.respond(202, self.server.app.submit(data["command"], data["fields"]))
            else:
                self.respond(404, {"error": "Not found."})
        except (InputError, ValueError, UnicodeError, OSError, RecursionError) as exc:
            self.respond(400, {"error": str(exc) or "Invalid request."})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="Existing native wasm-cosign executable; never built or downloaded")
    parser.add_argument("--port", type=int, default=8765, help="Loopback HTTP port (0 selects a free port; default: 8765)")
    parser.add_argument("--browse-root", type=Path, action="append", help="Allowed file-picker directory; repeatable, default: current directory. Not a CLI sandbox.")
    parser.add_argument("--timeout", type=int, default=120, help="Native command deadline in seconds (1..3600, default: 120)")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or not 1 <= args.timeout <= 3600:
        parser.error("Invalid port or timeout.")
    os.umask(0o077)
    try:
        app = Application(args.binary, args.browse_root or [Path.cwd()], args.timeout)
        server = LocalServer(("127.0.0.1", args.port), app)
    except (OSError, InputError) as exc:
        parser.error(str(exc))
    print("WSEA Studio · local Web GUI", flush=True)
    print(app.version, flush=True)
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
