## cosign wasm secure

Manage embedded WSEA custom-section signatures and offline UWVM trust

### Options

```
  -h, --help   help for secure
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm](cosign_wasm.md)	 - Utilities for working with WebAssembly modules and embedded wasm-cosign signatures
* [cosign wasm secure fetch](cosign_wasm_secure_fetch.md)	 - Download one bounded signed WASM over HTTPS, verify embedded WSEA, then publish without clobbering files
* [cosign wasm secure policy-init](cosign_wasm_secure_policy-init.md)	 - Bootstrap an OS protected local trust policy and VM rollback state (administrator operation)
* [cosign wasm secure policy-update](cosign_wasm_secure_policy-update.md)	 - Atomically update a protected policy as its local administrator, preserving VM state
* [cosign wasm secure sign](cosign_wasm_secure_sign.md)	 - Embed a policy-authorized signature, certificate chain and CRLs in one final WASM custom section
* [cosign wasm secure verify](cosign_wasm_secure_verify.md)	 - Verify exact module bytes, pinned signer, X.509 path, fresh CRLs and local rollback state
