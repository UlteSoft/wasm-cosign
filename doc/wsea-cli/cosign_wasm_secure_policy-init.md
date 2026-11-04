## cosign wasm secure policy-init

Bootstrap an OS protected local trust policy and VM rollback state (administrator operation)

```
cosign wasm secure policy-init [flags]
```

### Options

```
      --additional-certificate stringArray   additional protected leaf certificate path; repeat for distinct authorized signers (at most eight total)
      --algorithms string                    comma-separated exact allowed algorithm names (no aliases or duplicates) (default "ES256")
      --capabilities uint                    allowed capability mask
      --certificate string                   absolute leaf certificate PEM path to authorize
  -h, --help                                 help for policy-init
      --max-crl-age-seconds uint             maximum age of authenticated CRLs (default 86400)
      --max-module-bytes uint                maximum exact module size (default 104857600)
      --minimum-epoch uint                   minimum security epoch
      --minimum-version uint                 minimum module version (default 1)
      --module-id string                     authorized module ID
      --output string                        absolute policy output path
      --policy-version uint                  policy version (default 1)
      --signature-threshold uint             required number of distinct valid authorized public keys (default 1)
      --state-dir string                     absolute protected VM state directory
      --trust-root string                    absolute locally trusted CA PEM path
```

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust

