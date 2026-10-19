## cosign wasm secure policy-update

Atomically update a protected policy as its local administrator, preserving VM state

```
cosign wasm secure policy-update [flags]
```

### Options

```
      --additional-certificate stringArray   replace the additional signer certificate set; repeat for distinct keys
      --algorithms string                    replace this module's exact allowed algorithm set (requires --module-id) (default "ES256")
      --capabilities uint                    allowed module capability mask
      --certificate string                   PEM leaf certificate to authorize for this module
      --clear-additional-signers             explicitly remove additional signer pins; a compatible threshold must also be supplied
  -h, --help                                 help for policy-update
      --max-crl-age-seconds uint             maximum CRL age (default 86400)
      --max-module-bytes uint                maximum exact module size (default 104857600)
      --minimum-epoch uint                   minimum module security epoch
      --minimum-version uint                 minimum module version (default 1)
      --module-id string                     module rule to add or update
      --policy string                        existing protected policy path
      --policy-version uint                  strictly increasing administrator policy version
      --signature-threshold uint             explicitly replace this module's required number of distinct valid signers (default 1)
      --trust-root string                    explicit new locally provisioned trust root PEM path
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust
