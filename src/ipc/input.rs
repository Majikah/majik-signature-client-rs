//! File input / output normalisation for the IPC layer.
//!
//! The webview never sends large files as JSON. A file argument is either a **path** (Rust reads
//! it) or **inline base64 data** (small, in-memory blobs); results are either **written to a path**
//! or **returned as base64**. Loading validates the input and fails with a stable, descriptive
//! error (`fileNotFound`, `fileNotAFile`, `fileUnreadable`, `fileEmpty`, `fileTooLarge`,
//! `fileInvalid`) instead of an opaque I/O message.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SignatureClientError};

/// Largest file loaded into memory (signing hashes and re-embeds the whole file).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024 * 1024;

fn err(kind: &'static str, message: impl Into<String>) -> SignatureClientError {
    SignatureClientError::FileInput {
        kind,
        message: message.into(),
    }
}

/// A file argument: `{ "path": "C:\\docs\\a.pdf" }` or `{ "data": "<base64>", "name": "a.pdf" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum FileInput {
    Path {
        path: String,
        #[serde(default)]
        mime_type: Option<String>,
    },
    Bytes {
        /// Standard base64.
        data: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        mime_type: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedFile {
    pub bytes: Vec<u8>,
    /// File name (from the path, or the `name` of inline data).
    pub name: Option<String>,
    /// Explicit MIME type, else guessed from the extension.
    pub mime_type: Option<String>,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
pub struct LoadLimits {
    pub max_bytes: u64,
    pub allow_empty: bool,
}

impl Default for LoadLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_FILE_BYTES,
            allow_empty: false,
        }
    }
}

/// MIME type from a file extension, for the formats the signature handlers understand.
pub fn mime_from_name(name: &str) -> Option<String> {
    let ext = Path::new(name).extension()?.to_str()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "txt" | "log" => "text/plain",
        "md" => "text/markdown",
        "json" => "application/json",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => return None,
    };
    Some(mime.to_string())
}

impl FileInput {
    pub fn load(&self) -> Result<LoadedFile> {
        self.load_with(LoadLimits::default())
    }

    pub fn load_with(&self, limits: LoadLimits) -> Result<LoadedFile> {
        match self {
            Self::Path { path, mime_type } => load_path(path, mime_type.clone(), limits),
            Self::Bytes {
                data,
                name,
                mime_type,
            } => {
                let bytes = STANDARD.decode(data.trim()).map_err(|_| {
                    err(
                        "fileInvalid",
                        "The file data is not valid base64. Send a path instead, or encode the \
                         bytes as standard base64.",
                    )
                })?;
                check_size(bytes.len() as u64, "inline data", limits)?;
                Ok(LoadedFile {
                    mime_type: mime_type
                        .clone()
                        .or_else(|| name.as_deref().and_then(mime_from_name)),
                    name: name.clone(),
                    bytes,
                    path: None,
                })
            }
        }
    }
}

fn check_size(len: u64, what: &str, limits: LoadLimits) -> Result<()> {
    if len == 0 && !limits.allow_empty {
        return Err(err("fileEmpty", format!("The file is empty: {what}")));
    }
    if len > limits.max_bytes {
        return Err(err(
            "fileTooLarge",
            format!(
                "The file is too large to process in memory ({} MB; the limit is {} MB): {what}",
                len / (1024 * 1024),
                limits.max_bytes / (1024 * 1024)
            ),
        ));
    }
    Ok(())
}

fn load_path(raw: &str, mime_type: Option<String>, limits: LoadLimits) -> Result<LoadedFile> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err("fileInvalid", "No file path was provided."));
    }
    if trimmed.contains('\0') {
        return Err(err(
            "fileInvalid",
            "The file path contains an invalid character.",
        ));
    }
    let path = PathBuf::from(trimmed);
    let meta = fs::metadata(&path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => err("fileNotFound", format!("File not found: {trimmed}")),
        ErrorKind::PermissionDenied => err(
            "fileUnreadable",
            format!("Permission denied reading: {trimmed}"),
        ),
        _ => err("fileUnreadable", format!("Cannot access {trimmed}: {e}")),
    })?;
    if !meta.is_file() {
        return Err(err(
            "fileNotAFile",
            format!("Not a file (is it a folder?): {trimmed}"),
        ));
    }
    check_size(meta.len(), trimmed, limits)?;
    let bytes = fs::read(&path).map_err(|e| match e.kind() {
        ErrorKind::NotFound => err("fileNotFound", format!("File not found: {trimmed}")),
        ErrorKind::PermissionDenied => err(
            "fileUnreadable",
            format!("Permission denied reading: {trimmed}"),
        ),
        _ => err("fileUnreadable", format!("Could not read {trimmed}: {e}")),
    })?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string);
    Ok(LoadedFile {
        mime_type: mime_type.or_else(|| name.as_deref().and_then(mime_from_name)),
        name,
        bytes,
        path: Some(path),
    })
}

// ─── Output ──────────────────────────────────────────────────────────────────

/// Where a result goes. Omit `path` to get the bytes back inline (base64).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputTarget {
    #[serde(default)]
    pub path: Option<String>,
    /// Replace an existing file (default: fail with `fileExists`).
    #[serde(default)]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BytesOutput {
    pub size: usize,
    /// Present when written to disk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Present when returned inline (base64).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
}

/// Write `bytes` to `target.path` (atomically, via a temp file) or return them inline.
pub fn deliver(bytes: Vec<u8>, target: Option<&OutputTarget>) -> Result<BytesOutput> {
    let size = bytes.len();
    match target.and_then(|t| t.path.as_deref().map(|p| (p, t.overwrite))) {
        None => Ok(BytesOutput {
            size,
            path: None,
            data: Some(STANDARD.encode(&bytes)),
        }),
        Some((raw, overwrite)) => {
            write_atomic(raw, &bytes, overwrite)?;
            Ok(BytesOutput {
                size,
                path: Some(raw.to_string()),
                data: None,
            })
        }
    }
}

fn write_atomic(raw: &str, bytes: &[u8], overwrite: bool) -> Result<()> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(err("fileInvalid", "No output path was provided."));
    }
    let dest = PathBuf::from(trimmed);
    if dest.is_dir() {
        return Err(err(
            "fileInvalid",
            format!("The output path is a folder, not a file: {trimmed}"),
        ));
    }
    if dest.exists() && !overwrite {
        return Err(err(
            "fileExists",
            format!("A file already exists at {trimmed}"),
        ));
    }
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    if !parent.is_dir() {
        return Err(err(
            "fileInvalid",
            format!("The output folder does not exist: {}", parent.display()),
        ));
    }
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        dest.file_name().and_then(|n| n.to_str()).unwrap_or("out"),
        uuid::Uuid::new_v4().simple()
    ));
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        if overwrite && dest.exists() {
            let _ = fs::remove_file(&dest);
        }
        fs::rename(&tmp, &dest)
    };
    write().map_err(|e| {
        let _ = fs::remove_file(&tmp);
        err("fileWriteFailed", format!("Could not write {trimmed}: {e}"))
    })
}

/// `<dir>/<name>`, validating that `dir` is an existing folder (for batch outputs).
pub fn join_output_dir(dir: &str, name: &str) -> Result<String> {
    let trimmed = dir.trim();
    if trimmed.is_empty() || !Path::new(trimmed).is_dir() {
        return Err(err(
            "fileInvalid",
            format!("The output folder does not exist: {trimmed}"),
        ));
    }
    let safe = Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| err("fileInvalid", format!("Invalid file name: {name}")))?;
    Ok(Path::new(trimmed).join(safe).to_string_lossy().into_owned())
}

/// `MajikSignatureEnvelope::to_mjksig_bytes()` returns `Vec<u8>` in `majik-signature` 1.0.x and
/// `Result<Vec<u8>, _>` in 1.1.x. This adapter lets the crate compile against both.
pub(crate) trait IntoMjksig {
    fn into_mjksig(self) -> Result<Vec<u8>>;
}

impl IntoMjksig for Vec<u8> {
    fn into_mjksig(self) -> Result<Vec<u8>> {
        Ok(self)
    }
}

impl IntoMjksig for std::result::Result<Vec<u8>, majik_signature::MajikSignatureError> {
    fn into_mjksig(self) -> Result<Vec<u8>> {
        self.map_err(Into::into)
    }
}
