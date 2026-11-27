//! # majik-signature-client
//!
//! High-level Rust application client for Majik Signature. It composes
//! [`majik_key_client`] with contact/group management, signing and verification,
//! detached and embedded file operations, stamps, backups, logs, preferences,
//! and native-path bounded-memory streaming.
//!
//! The crate is an application-facing integration layer; cryptographic formats,
//! signature verification, and envelope parsing are implemented by
//! [`majik_signature`].

/// Portable application-data backup and selective restore helpers.
pub mod backup;
/// Synchronous event bus used by client managers.
pub mod bus;
/// High-level client construction, account integration, and orchestration.
pub mod client;
/// Contact and contact-group management.
pub mod contacts;
/// Client error types and the crate-wide result alias.
pub mod error;
/// Typed signature-client events.
pub mod events;
/// File identity and metadata helpers.
pub mod file_identity;
/// Buffered embedded/detached signing, verification, and revision operations.
pub mod files;
/// Hooks adapting Majik Key client lifecycle events to signature domains.
pub mod hooks;
/// IPC-facing input and command support shared by native integrations.
pub mod ipc;
/// History and user-activity log models and repositories.
pub mod logs;
/// MJKSMAP read, describe, batch signing, and verification helpers.
pub mod mjks;
/// User-application preference models and persistence.
pub mod prefs;
/// Shared client state, resource limits, and internal references.
pub mod shared;
/// Signing-key resolution and signing/verification result models.
pub mod signing;
/// Encrypted reusable signature stamp models and managers.
pub mod stamps;
/// High-level stamp API exposed by the client.
pub mod stamps_api;
/// Format-aware native-path file streaming and atomic output helpers.
pub mod streaming;
/// Timestamp-authority integration models and helpers.
pub mod tsa;

/// Public backup snapshots and backup format descriptors.
pub use backup::{AppDataSnapshot, BackupType, ContactManagerSnapshot};
/// Public event-bus primitives.
pub use bus::{Bus, Listener, ListenerId};
/// Main client type and hydration report.
pub use client::{HydrateReport, SignatureClient};
/// Crate result alias and error enum.
pub use error::{Result, SignatureClientError};
/// Signature and client event enums.
pub use events::{SigEvent, SigOnlyEvent};
/// Common file-signing option structures.
pub use files::{SignDetachedFileOptions, SignFileOptions};
/// Adapter hooks for the signature client.
pub use hooks::SigHooks;
/// Shared database connection type exported by the log repositories.
pub use logs::repo::SharedConnection;
/// Supported MJKSMAP input forms.
pub use mjks::MjksMapInput;
/// User application preferences.
pub use prefs::UserAppPreferences;
/// Shared client state and the activity-log capacity limit.
pub use shared::{SigShared, MAX_ACTIVITY_LOGS};
/// Signing, signer-reference, and verification models.
pub use signing::{OpContext, SigInput, SignResult, SignerRef, VerifyResult, VerifyTarget};
/// Encrypted signature stamp types.
pub use stamps::{MajikSignatureStamp, StampAssetKind, StampJson, StampMeta};
/// Public streaming option, result, file-handle, progress, and atomic-write helpers.
pub use streaming::{
    write_atomic_bytes, write_atomic_with, BatchStreamingFileOptions, OpenedStreamFile,
    StreamingBatchPathInput, StreamingBatchProgress, StreamingDetachedSignResult,
    StreamingEmbeddedSignResult, StreamingFileOptions, StreamingOutput,
};

/// Contact manager compatibility namespace.
pub use contacts as majik_contact_manager;
/// Re-export Majik File primitives used by the client.
pub use majik_file;
/// Re-export Majik Key Client primitives used by the client.
pub use majik_key_client;
/// Re-export Majik Signature core primitives and types.
pub use majik_signature;
