## cosign wasm secure verify

Verify exact module bytes, pinned signer, X.509 path, fresh CRLs and local rollback state

```
cosign wasm secure verify <module> [flags]
```

### Options

```
  -h, --help            help for verify
      --policy string   protected WSEA policy file (required)
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust
