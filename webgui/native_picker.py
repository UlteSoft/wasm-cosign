#!/usr/bin/env python3
# Copyright 2026 The Sigstore Authors. Apache-2.0.
"""Private desktop helper. Its stdout is consumed only by the Python server."""
import json
import shutil
import subprocess
import sys


def select(role, language):
    titles = {
        "module": ("选择 WASM 模块", "Select WASM module"),
        "policy": ("选择信任策略", "Select trust policy"),
        "key": ("选择私钥", "Select private key"),
        "certificate": ("选择签名证书", "Select signer certificate"),
        "crl": ("选择 CRL", "Select CRL"),
        "trust-root": ("选择根证书", "Select trust roots"),
        "module-output": ("保存 WASM 文件", "Save WASM file"),
        "policy-output": ("保存策略文件", "Save policy file"),
        "state-dir": ("选择新状态目录的名称与位置", "Choose a name and location for new state directory"),
    }
    title = titles[role][language == "en"]
    save = role in ("module-output", "policy-output", "state-dir")
    name = {"module-output": "signed.wasm", "policy-output": "policy", "state-dir": "state"}.get(role, "")
    zenity = shutil.which("zenity") if sys.platform.startswith("linux") else None
    if zenity:
        args = [zenity, "--file-selection", "--title=" + title]
        if save:
            args += ["--save", "--filename=" + name]
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, check=False)
        if result.returncode == 1:
            return None
        if result.returncode != 0:
            raise RuntimeError()
        return result.stdout.rstrip("\r\n") or None
    # Tk uses the platform's file dialogs on Windows/macOS and works on Linux
    # with a desktop and the optional system tkinter package.
    import tkinter
    from tkinter import filedialog
    root = tkinter.Tk()
    root.withdraw()
    try:
        if save:
            return filedialog.asksaveasfilename(parent=root, title=title, initialfile=name,
                                               confirmoverwrite=False) or None
        return filedialog.askopenfilename(parent=root, title=title) or None
    finally:
        root.destroy()


if __name__ == "__main__":
    try:
        path = select(*sys.argv[1:])
        if path is None:
            sys.exit(2)
        print(json.dumps({"path": path}))
    except Exception:
        # Never print exceptions/paths to either HTTP or diagnostic logs.
        sys.exit(1)
