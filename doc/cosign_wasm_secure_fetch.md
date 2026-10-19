## cosign wasm secure fetch

Download one bounded signed WASM over HTTPS, verify embedded WSEA, then publish without clobbering files

```
cosign wasm secure fetch <output.wasm> [flags]
```

### Options

```
  -h, --help            help for fetch
      --policy string   protected local WSEA policy
      --url string      HTTPS URL of the complete WASM with embedded WSEA
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust
