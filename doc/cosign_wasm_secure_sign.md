## cosign wasm secure sign

Embed a policy-authorized signature, certificate chain and CRLs in one final WASM custom section

```
cosign wasm secure sign <module> [flags]
```

### Options

```
      --algorithm string      exact signing algorithm permitted by the protected module rule (default "ES256")
      --allow-partial         signing workflow only: emit SIGNED_PARTIAL if the protected quorum is incomplete; verification, fetch and VM still refuse it
      --append-signature      authenticate existing contributions and append a signature over the identical manifest
      --capabilities uint     requested host capability mask (0..63)
      --certificate string    PEM leaf followed by intermediates to embed
      --crl string            authenticated complete CRL bundle to embed
  -h, --help                  help for sign
      --key string            absolute path to a protected PEM ECDSA, Ed25519 or RSA private key
      --module-id string      authorized module identity
      --module-version uint   monotonic module release version
      --not-after string      validity end in RFC3339 UTC
      --not-before string     validity start in RFC3339 UTC
      --output string         new signed WASM output; default atomically replaces the input
      --policy string         protected WSEA policy file (required)
      --replace-signature     explicitly replace an existing final WSEA section
      --security-epoch uint   monotonic module security epoch
```

### Options inherited from parent commands

```
      --output-file string   log output to a file
  -t, --timeout duration     timeout for commands (default 3m0s)
  -d, --verbose              log debug output
```

### SEE ALSO

* [cosign wasm secure](cosign_wasm_secure.md)	 - Manage embedded WSEA custom-section signatures and offline UWVM trust
