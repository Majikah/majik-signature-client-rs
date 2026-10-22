# Majik Signature Client

**Majik Signature Client** is a high-level Rust wrapper for `MajikSignature`, built directly on top of `MajikKeyClient`. 

Designed to be used natively within the Majikah ecosystem, it inherits all core `MajikKey` account management—such as creation, lock/unlock states, and active-account tracking—while introducing domain-specific functionality for file signing, contact management, and encrypted reusable stamps.

Rust port of the TS [@majikah/majik-signature-client](https://www.npmjs.com/package/@majikah/majik-signature), composed on `majik-key-client`: `SignatureClient` owns a
`KeyClient<SigHooks>` (`keys()` / `keys_mut()`) plus contacts, stamps, logs, preferences and signing.

## Core Capabilities

*   **Integrated Key & Account Management**: Extends `MajikKeyClient` to seamlessly handle account lifecycles and cryptographic unlocking. Accounts can easily be shared alongside `MajikMessage`.
*   **Contact & Group Directory**: Utilizes `MajikContactManager` for full contact CRUD operations, including system/user groups, favorites, and blocked lists.
*   **Post-Quantum Signing & Verification**: Provides intuitive methods (`signFile`, `verifyFile`, `batchSignFiles`) for text, raw bytes, and file blobs. Verifications automatically resolve public keys from the internal contact directory or active keystore.
*   **Multi-sig & Envelope Sealing**: Built-in support for restricted allowlists (`expectedSigners`), multi-sig pending states, and cryptographic sealing to prevent further modifications to a file.
*   **Encrypted Stamp Assets**: Uses `MajikSignatureStampManager` to securely create, encrypt, and manage reusable assets (signatures, audio, text) bound to the user's ML-KEM keys.
*   **Data Backup & Restore**: Robust export and hydration capabilities for contacts, stamps, and user preferences utilizing `MajikCompressedJSON` and protected by strict magic byte headers.

---



| Module | What it covers |
|---|---|
| `client` | construction (`in_memory`, `with_sqlite`), TS-order hydration, preferences, logs, own-account meta, contact + group API with events and audit entries |
| `signing` | `with_signing_key`, signing sessions (closure and explicit begin/end), signer resolution, `sign*`, `verify*` |
| `files` | `sign_file[_detached]`, `batch_sign_files`, `verify_file*` (+ all-signatures, chain, revisions), seal, allowlist, signatories, envelope info |
| `mjks` | `.mjksmap` read/describe/sign/cosign/verify, signing-order verification |
| `stamps`, `stamps_api` | encrypted stamps (`MajikFile` envelopes), repositories (`majik_signature_stamps`), manager, client API |
| `backup` | `STMP` / `MJKC` / `MJKA` backups (magic header + `majik-cjson`), read / restore / selective restore |
| `logs`, `prefs`, `events`, `hooks`, `shared`, `bus` | history + activity logs (TS JSON + tables), user app preferences, one merged event stream, own-account<->contact sync |



## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-signature-client-rs](https://github.com/Majikah/majik-signature-client-rs)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)