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

The `streaming` module adds native-path APIs for large files. Unlike the existing `FileInput::load()` and byte-slice methods, these operations read and write fixed-size chunks and do not materialize the source document as a `Vec<u8>` or base64 payload. The default chunk is 1 MiB; callers can choose 64 KiB–64 MiB, supply an optional maximum input size, cancel between reads, and receive byte progress. Streaming buffer allocation uses fallible reservation and reports the stable `memoryAllocation` error kind so native integrations can downgrade and retry before output publication. By default, no arbitrary total file-size ceiling is imposed on streaming operations.

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

### Streaming detached batch signing and MJKSMAP verification

The 1.6.0 client adds path-backed batch operations that reuse the same format-aware
canonicalization plans as the single-file streaming APIs. Each input pairs a
relative `manifest_path` with a native `source_path`; the client opens the
source, constructs a canonical `RewrittenFileReader`, and passes those readers
to the core 1.6.0 streaming batch operations.

```rust
use majik_signature_client::{
    BatchSignOptions, BatchStreamingFileOptions, OpContext, SignatureClient,
    StreamingBatchPathInput,
};

let inputs = vec![
    StreamingBatchPathInput {
        manifest_path: "contracts/contract.pdf".into(),
        source_path: "./files/contract.pdf".into(),
        mime_type: Some("application/pdf".into()),
    },
    StreamingBatchPathInput {
        manifest_path: "media/demo.mp4".into(),
        source_path: "./files/demo.mp4".into(),
        mime_type: Some("video/mp4".into()),
    },
];

let mut streaming = BatchStreamingFileOptions::default();
let result = client.sign_batch_detached_paths_stream(
    &inputs,
    &BatchSignOptions::default(),
    &OpContext::default(),
    &mut streaming,
)?;
```

The result preserves the core `BatchSignResult` modes: one MJKSMAP manifest or
separate MJKSIG sidecars. Source documents are not returned or materialized.
Use `write_atomic_bytes()` to publish the small manifest or sidecar bytes when
a filesystem destination is needed.

Use `verify_mjks_map_paths_stream()` with a `VerifyTarget` containing a trusted
key, contact, or address. Streaming verification deliberately requires trusted
public keys; use the existing buffered `verify_mjks_map()` for self-reported
envelope-key verification. Both streaming operations preserve path-first
tamper detection and content-hash relocation behavior, support per-file
progress, maximum input sizes, and cancellation.

The supported chunk override range is 64 KiB–64 MiB, matching the core 1.6.0
contract. The 1 MiB default and 8 MiB automatic core threshold are unchanged.

### Streaming format support

| Operation | Supported content | Notes |
|---|---|---|
| Detached sign / verify | PDF, MP4/MOV, PNG, JPEG, MP3, FLAC, WAV, OOXML/ODF Office files, Matroska/WebM, and formats using the core universal-trailer fallback | Uses each format's existing canonical representation. Large media payloads are hashed in chunks. Office ZIP entries are inflated and staged to disk, then rebuilt into the core deterministic stored-ZIP canonical form. |
| Embedded sign / verify | PDF | Appends/replaces the Majik PDF signature trailer while streaming the document. |
| Embedded sign / verify | MP4/MOV | Rewrites only bounded ISO-BMFF moov metadata and streams large media payload boxes unchanged. A final moov after mdat is required when the moov must grow; fast-start layouts with moov before mdat, or later boxes after moov, are rejected rather than risking stale absolute chunk offsets. Containers without moov use the universal trailer. |
| Embedded sign / verify | PNG/JPEG | Writes Majik's existing PNG iTXt or JPEG APP15 metadata. Image pixel data is streamed unchanged. |
| Embedded sign / verify | MP3/FLAC/WAV | Rewrites only the bounded ID3, FLAC metadata, or RIFF/INFO metadata. Compressed audio/sample data is streamed unchanged. RF64 WAV is not supported by the existing core WAV format handler and is rejected safely. |
| Embedded sign / verify | OOXML/ODF Office files | Rebuilds the deterministic canonical ZIP from disk-staged entries and appends/replaces the final majik-signature.json entry. The full uncompressed archive is never materialised in memory. |
| Embedded sign / verify | Matroska/WebM | Uses the existing universal trailer representation; the EBML/media payload is streamed unchanged. |

The default chunk size is 1 MiB (configurable from 64 KiB to 64 MiB). The default streaming API has no arbitrary total input-size cap for ordinary files; callers can set max_bytes. Format metadata is separately bounded (32 MiB for container metadata and 16 MiB for embedded envelopes). Office ZIP processing retains the core 512 MiB total uncompressed-content ceiling, adds a 32 MiB central-directory safety limit, and caps the embedded signature entry at 8 MiB. Office staging and archive writes remain bounded and observe cancellation; progress callbacks report the canonical content hashing/signing passes rather than a separate ZIP decompression progress stream. These are format-specific safety bounds, not arbitrary caps on standalone large media payloads.

### Path-backed revision signing

Both embedded and detached signing have explicit *_stream_with_prior variants. They accept native paths for the prior file, verify the previous signature and current revision-chain head using reader-based hashing/verification, and then append the next FileVersion and version-chain commitment. Detached revision signing also requires the prior .mjksig envelope in existing_envelope; the prior file bytes remain path-backed. The byte-array priorFile / priorSignedFile options are intentionally rejected by streaming operations.

MSIX/AppX packages, text/markup formats, and ZIP files that are not recognised as OOXML/ODF Office containers remain explicitly rejected by the streaming API. MSIX packages have separate package-signature semantics; text/markup canonicalisation still requires a dedicated streaming normalizer; generic ZIP formats do not have a supported Majik canonicalisation handler. They remain on legacy APIs where supported, whose byte-slice paths retain the existing 1 GiB in-memory safety ceiling. This PR does not remove that limit globally.

The crate's minimum supported Rust version is 1.92, matching the current dependency graph. CI checks Linux, Windows, and the declared Rust 1.92 minimum.


Streaming operations record signature/history metadata but intentionally do not copy a multi-gigabyte source into the encrypted history blob. The new APIs are additive. Tauri command exposure, progress events, cancellation commands, and desktop integration belong in the subsequent plugin/application changes.
---

| Module | What it covers |
|---|---|
| `client` | construction (`in_memory`, `with_sqlite`), TS-order hydration, preferences, logs, own-account meta, contact + group API with events and audit entries |
| `signing` | `with_signing_key`, signing sessions, signer resolution, content sign/verify |
| `files` | embedded/detached byte-slice signing, batch signing, verification, revisions, seals, allowlists, signatories, envelope info |
| `streaming` | path-backed detached / embedded signing, bounded-memory media and Office ZIP canonicalisation, and path-backed revisions |
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
