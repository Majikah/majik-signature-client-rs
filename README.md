# majik-signature-client

Rust port of the TS `MajikSignatureClient`, composed on `majik-key-client`: `SignatureClient` owns a
`KeyClient<SigHooks>` (`keys()` / `keys_mut()`) plus contacts, stamps, logs, preferences and signing.

| Module | What it covers |
|---|---|
| `client` | construction (`in_memory`, `with_sqlite`), TS-order hydration, preferences, logs, own-account meta, contact + group API with events and audit entries |
| `signing` | `with_signing_key`, signing sessions (closure and explicit begin/end), signer resolution, `sign*`, `verify*` |
| `files` | `sign_file[_detached]`, `batch_sign_files`, `verify_file*` (+ all-signatures, chain, revisions), seal, allowlist, signatories, envelope info |
| `mjks` | `.mjksmap` read/describe/sign/cosign/verify, signing-order verification |
| `stamps`, `stamps_api` | encrypted stamps (`MajikFile` envelopes), repositories (`majik_signature_stamps`), manager, client API |
| `backup` | `STMP` / `MJKC` / `MJKA` backups (magic header + `majik-cjson`), read / restore / selective restore |
| `logs`, `prefs`, `events`, `hooks`, `shared`, `bus` | history + activity logs (TS JSON + tables), user app preferences, one merged event stream, own-account<->contact sync |
