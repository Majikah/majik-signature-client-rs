//! Transport-agnostic IPC surface for `SignatureClient` (no Tauri dependency).
//!
//! * [`input`]: the path/bytes normaliser (`FileInput`, `OutputTarget`, `deliver`).
//! * [`dto`]: camelCase wire types.
//! * [`ops`]: one function per operation.
//!
//! Account commands (create / unlock / ...) are `majik_key_client::ipc::*` called on
//! `client.keys_mut()`; the same command names are exposed so the TS facade can extend the key
//! client's.

pub mod dto;
pub mod input;
pub mod ops;

pub use dto::*;
pub use input::{deliver, BytesOutput, FileInput, LoadLimits, LoadedFile, OutputTarget};

/// Event channel the signature plugin emits on (key events and signature events together).
pub const EVENT_CHANNEL: &str = "majik-signature-client:event";
