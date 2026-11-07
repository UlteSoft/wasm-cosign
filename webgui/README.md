# WSEA Studio

Local Web GUI for wasm-cosign: signing, verification, multisignatures, HTTPS retrieval and policy management. Supports Chinese and English.

- [中文使用说明](README.zh_CN.md)
- [English user guide](README.en_US.md)

```sh
python3 webgui/server.py --binary /absolute/path/to/cosign
```

Requires Python 3.10+, an existing native wasm-cosign executable, and a local desktop with Zenity (Linux) or Python Tk file dialogs. Open the session link printed in the terminal.
