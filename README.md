# Majik Signature Client

**Majik Signature Client** is a high-level Rust wrapper for `MajikSignature`, built directly on top of `MajikKeyClient`.

Designed to be used natively within the Majikah ecosystem, it inherits all core `MajikKey` account management—such as creation, lock/unlock states, and active-account tracking—while introducing domain-specific functionality for file signing, contact management, and encrypted reusable stamps.

Rust port of the TS [@majikah/majik-signature-client](https://www.npmjs.com/package/@majikah/majik-signature), composed on `majik-key-client`: `SignatureClient` owns a
`KeyClient<SigHooks>` (`keys()` / `keys_mut()`) plus contacts, stamps, logs, preferences and signing.

## Core Capabilities

* **Integrated Key & Account Management**: Extends `MajikKeyClient` to seamlessly handle account lifecycles and cryptographic unlocking.
* **Contact & Group Directory**: Utilizes `MajikContactManager` for full contact CRUD operations, including system/user groups, favorites, and blocked lists.
* **Post-Quantum Signing & Verification**: Provides file signing, detached signing, batch operations, and verification, with public-key resolution from the internal contact directory or active keystore.
* **Multi-sig & Envelope Sealing**: Built-in support for restricted allowlists (`expectedSigners`), multi-sig pending states, and cryptographic sealing to prevent further modifications to a file.
* **Encrypted Stamp Assets**: Uses `MajikSignatureStampManager` to securely create, encrypt, and manage reusable assets bound to the user's ML-KEM keys.
* **Data Backup & Restore**: Export and hydration capabilities for contacts, stamps, and user preferences utilizing `MajikCompressedJSON`.

---

## Bounded-memory file streaming

The `streaming` module adds native-path APIs for large files. Unlike the existing `FileInput::load()` and byte-slice methods, these operations read and write fixed-size chunks and do not materialize the source document as a `Vec<u8>` or base64 payload. The default chunk is 1 MiB; callers can choose 64 KiB–8 MiB, supply an optional maximum input size, cancel between reads, and receive byte progress. By default, no arbitrary total file-size ceiling is imposed on streaming operations.

```rust
use std::sync::atomic::AtomicBool;
use majik_signature_client::{
    OpContext, SignDetachedFileOptions, SignatureClient, StreamingFileOptions,
};

let cancelled = AtomicBool::new(false);
let mut stream = StreamingFileOptions {
    cancellation: Some(&cancelled),
    ..Default::default()
};

let result = client.sign_file_detached_stream(
    "./large-video.mov",
    "./large-video.mov.mjksig",
    &SignDetachedFileOptions::default(),
    &OpContext::default(),
    &mut stream,
    false, // do not overwrite an existing sidecar
)?;
println!("Signed {} bytes", result.source_size_bytes);
```

### Streaming format support

| Operation | Supported content | Notes |
|---|---|---|
| Detached sign / verify | PDF, MP4/MOV, and opaque/raw files | Recognizes and strips PDF, MP4/MOV, and universal fallback signature representations. Specialised in-memory formats such as PNG/JPEG, FLAC/MP3/WAV, Matroska/WebM, text/markup, MSIX/AppX, and Office ZIP documents are rejected rather than silently hashed with different canonicalisation semantics. An explicit `application/octet-stream` MIME override can be used only when the caller intentionally wants to sign the literal raw bytes and knows the file does not contain a format-specific Majik signature. |
| Embedded sign / verify | PDF | Appends/replaces the existing Majik PDF trailer without loading the document. |
| Embedded sign / verify | MP4/MOV | Rewrites only the bounded `moov` metadata and streams media payload boxes unchanged. The current safe writer requires `mdat` to precede a final `moov` box; files with `moov` before `mdat`, or later top-level boxes after `moov`, are rejected for embedded signing rather than risking stale absolute chunk offsets. When no `moov` exists, the universal trailer is used. |

MP4/MOV `moov` metadata is limited to 64 MiB and embedded envelope payloads to 16 MiB. These are metadata safety limits, not limits on the media payload. Other embedded formats (for example, PNG/JPEG and Office ZIP containers) remain on the existing in-memory APIs until their container handlers gain reader/writer implementations. Prior-file revision inputs (`priorFile` / `priorSignedFile`) are also not part of this first streaming surface.

Streaming operations record signature/history metadata but intentionally do not copy a multi-gigabyte source into the encrypted history blob. The existing byte-based APIs and their 1 GiB load ceiling are unchanged. The new streaming APIs are additive; this avoids accidentally lifting limits on operations that still require full in-memory content. The Tauri plugin can expose these methods as dedicated commands in a follow-up integration change.

---

| Module | What it covers |
|---|---|
| `client` | construction (`in_memory`, `with_sqlite`), TS-order hydration, preferences, logs, own-account meta, contact + group API with events and audit entries |
| `signing` | `with_signing_key`, signing sessions, signer resolution, content sign/verify |
| `files` | embedded/detached byte-slice signing, batch signing, verification, revisions, seals, allowlists, signatories, envelope info |
| `streaming` | path-backed detached signing / verification and bounded-memory PDF + MP4/MOV embedded signing / verification |
| `mjks` | `.mjksmap` read/describe/sign/cosign/verify, signing-order verification |
| `stamps`, `stamps_api` | encrypted stamps (`MajikFile` envelopes), repositories (`majik_signature_stamps`), manager, client API |
| `backup` | `STMP` / `MJKC` / `MJKA` backups (magic header + `majik-cjson`), read / restore / selective restore |
| `logs`, `prefs`, `events`, `hooks`, `shared`, `bus` | history + activity logs, user app preferences, one merged event stream, own-account<->contact sync |

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
