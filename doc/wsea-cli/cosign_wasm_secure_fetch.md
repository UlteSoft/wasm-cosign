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

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust

