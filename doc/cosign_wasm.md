## cosign wasm

> **Historical reference:** The `wasm-cosign` signature container and the legacy
> sign/verify/list/extract/strip commands below are **deprecated**. The current
> executable exposes [`cosign wasm secure`](wsea-cli/cosign_wasm_secure.md),
> which uses `uwvm.wsea.v2`. The tool name and the secure subgroup are not deprecated.

Utilities for working with WebAssembly modules and embedded wasm-cosign signatures

### Options

```
  -h, --help   help for wasm
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign](cosign.md)	 - A tool for Container Signing, Verification and Storage in an OCI registry
* [cosign wasm extract-signatures](cosign_wasm_extract-signatures.md)	 - Print embedded wasm-cosign bundle payloads from a WebAssembly module
* [cosign wasm list-signatures](cosign_wasm_list-signatures.md)	 - List embedded wasm-cosign signatures in a WebAssembly module
* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust
* [cosign wasm sign](cosign_wasm_sign.md)	 - Sign a WebAssembly module with an embedded wasm-cosign custom section
* [cosign wasm strip-signatures](cosign_wasm_strip-signatures.md)	 - Remove embedded wasm-cosign custom sections from a WebAssembly module
* [cosign wasm verify](cosign_wasm_verify.md)	 - Verify a WebAssembly module with embedded wasm-cosign signatures

