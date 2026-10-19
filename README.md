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

## IMPORTANT: `majik-file` 1.0.0 cannot share a dependency tree with `majik-key` 1.1.x

`majik-file` 1.0.0 depends on `ml-kem 0.2.x`, which requires `kem =0.3.0-pre.0`; `majik-key` 1.1.1 depends on
`ml-kem 0.3.2`, which requires `kem ^0.3` (the final release). Cargo cannot satisfy both, so any crate using
both fails to resolve. This crate needs both, so it ships against **`../majik-file-rs` (1.0.1)**: identical
except the three ML-KEM-768 functions in `core/crypto/crypto_provider.rs` now use the `ml-kem 0.3.2` API
(same 2400-byte expanded secret keys and wire format). Publish that as `majik-file` 1.0.1 and switch the
path dependency in `Cargo.toml` to the crates.io version.

## Behaviour notes
- Unlocking never prompts: a locked account fails with `unlockRequired`; unlock via `keys_mut().unlock_account` and retry.
- Lock order: never call into `keys_mut()` while holding a guard from `SigShared` (hooks lock the contacts).
- Signing re-locks the account afterwards unless a signing session is open or one-time unlock is on (default).
- `clear_directory` re-adds own-account contacts; `restore_*` with overwrite updates an existing contact's meta
  (TS threw on existing ids).
- Log / history `data` and stamps are `MajikFile` envelopes encrypted to the account's ML-KEM key.
- `with_signing_key` follows the pattern visible in the TS client; I could not see its own source lines, so verify
  its re-lock behaviour against your expectations.

## Not in this crate yet
The IPC layer (DTOs + Tauri plugin + TS facade for the signature client). Design is settled: reuse
`majik_key_client::ipc` and `ClientHandle`, same command names under the `majik-signature-client` plugin so
`MajikSignatureClientTauri extends MajikKeyClientTauri`. Use `begin_signing_session` / `end_signing_session`
there (closures cannot cross IPC).

Path dependencies point at sibling directories: `majik-key-client-rs`, `majik-contact-manager-rs`, `majik-file-rs`.
