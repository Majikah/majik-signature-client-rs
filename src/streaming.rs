//! Path-backed, bounded-memory file operations.
//!
//! These APIs are intentionally separate from the legacy `FileInput::load()` path, which
//! materialises inputs into `Vec<u8>` and keeps its existing 1 GiB safety ceiling. Streaming
//! operations accept native paths, use fixed-size buffers, and never return the source file as
//! base64. Format-aware rewriting covers PDF, ISO-BMFF (MP4/MOV), PNG/JPEG, MP3, FLAC,
//! WAV, and universal-trailer containers such as Matroska/WebM. Only bounded container metadata
//! is held in memory; large image, audio, and video payloads are copied and hashed in chunks.

mod media;
mod office;

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::SystemTime;

use jiff::Timestamp;
use majik_signature::{
    bytes_to_base64, parse_embedded_envelope, serialize_embedded_envelope, BatchSignOptions,
    BatchSignResult, BatchStreamingOptions as CoreBatchStreamingOptions, BatchVerifyOptions,
    EnvelopeInput, FileVersion, MajikSignature, MajikSignatureEnvelope, SignOptions,
    StreamingBatchFileInput, StreamingBatchVerifyInput, StreamingHashOptions,
    StreamingHashProgress,
};
pub use majik_signature::StreamingBatchProgress;
use sha2::{Digest, Sha256};

use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::events::SigOnlyEvent;
use crate::files::{SignDetachedFileOptions, SignFileOptions};
use crate::ipc::input::mime_from_name;
use crate::logs::{HistorySource, HistoryType};
use crate::signing::{
    invalid_result, OpContext, OpNote, SignEventPayload, SignResult, VerifyResult, VerifyTarget,
};

const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
const MIN_CHUNK_SIZE: usize = 64 * 1024;
const MAX_CHUNK_SIZE: usize = 64 * 1024 * 1024;
const MAX_CONTAINER_METADATA_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MP4_METADATA_BOXES: usize = 65_536;
const MAX_EMBEDDED_ENVELOPE_BYTES: u64 = 16 * 1024 * 1024;

const PDF_SIGNATURE_MARKER: &[u8] = b"\n%%MajikSig%%\n";
const UNIVERSAL_TRAILER_MAGIC: [u8; 8] = *b"MAJIKSIG";
const MP4_SIGNATURE_BOX: [u8; 4] = *b"majk";

fn file_error(kind: &'static str, message: impl Into<String>) -> SignatureClientError {
    SignatureClientError::FileInput {
        kind,
        message: message.into(),
    }
}

fn io_file_error(kind: &'static str, path: &Path, error: io::Error) -> SignatureClientError {
    file_error(kind, format!("{}: {error}", path.display()))
}

/// Allocate and initialize a streaming buffer without using infallible Vec allocation.
fn allocate_stream_buffer(size: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(size)
        .map_err(|error| SignatureClientError::MemoryAllocation {
            message: format!("Unable to allocate the {size}-byte streaming file buffer: {error}"),
        })?;
    // The reservation above guarantees capacity, so resize does not request another allocation.
    buffer.resize(size, 0);
    Ok(buffer)
}

/// Controls memory, cancellation, maximum input size, and progress for one streaming operation.
///
/// The default uses a 1 MiB buffer and does not impose an arbitrary total file-size limit.
pub struct StreamingFileOptions<'a> {
    pub chunk_size: usize,
    pub max_bytes: Option<u64>,
    pub cancellation: Option<&'a AtomicBool>,
    pub on_progress: Option<&'a mut dyn FnMut(StreamingHashProgress)>,
}

impl<'a> Default for StreamingFileOptions<'a> {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_bytes: None,
            cancellation: None,
            on_progress: None,
        }
    }
}

/// A native source file paired with its path inside the MJKSMAP batch.
#[derive(Debug, Clone)]
pub struct StreamingBatchPathInput {
    /// Relative, normalized POSIX path stored in the manifest.
    pub manifest_path: String,
    /// Native file path read through the existing format-aware streaming handlers.
    pub source_path: PathBuf,
    /// Optional MIME override; otherwise inferred from the source filename.
    pub mime_type: Option<String>,
}

/// Chunking, size, cancellation, and per-file progress controls for native batch operations.
pub struct BatchStreamingFileOptions<'a> {
    pub chunk_size: usize,
    pub max_bytes_per_file: Option<u64>,
    pub cancellation: Option<&'a AtomicBool>,
    pub on_progress: Option<&'a mut dyn FnMut(StreamingBatchProgress)>,
}

impl Default for BatchStreamingFileOptions<'_> {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_bytes_per_file: None,
            cancellation: None,
            on_progress: None,
        }
    }
}

impl BatchStreamingFileOptions<'_> {
    fn validate(&self) -> Result<()> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return Err(SignatureClientError::Invalid(format!(
                "Streaming chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
            )));
        }
        Ok(())
    }

    fn check_cancelled(&self) -> Result<()> {
        if self.cancellation.is_some_and(|flag| {
            flag.load(std::sync::atomic::Ordering::Acquire)
        }) {
            return Err(SignatureClientError::Invalid(
                "Streaming operation was cancelled".into(),
            ));
        }
        Ok(())
    }
}

struct PreparedStreamingBatch {
    sources: Vec<OpenedStreamFile>,
    readers: Vec<RewrittenFileReader>,
    metadata: Vec<(String, u64, Option<String>)>,
}

fn prepare_streaming_batch(
    inputs: &[StreamingBatchPathInput],
    options: &BatchStreamingFileOptions<'_>,
) -> Result<PreparedStreamingBatch> {
    options.validate()?;
    options.check_cancelled()?;
    if inputs.is_empty() {
        return Err(SignatureClientError::Invalid(
            "Streaming batch must contain at least one file".into(),
        ));
    }

    let mut seen = HashSet::with_capacity(inputs.len());
    let mut sources = Vec::with_capacity(inputs.len());
    let mut plans = Vec::with_capacity(inputs.len());
    let mut metadata = Vec::with_capacity(inputs.len());

    for input in inputs {
        if input.manifest_path.trim().is_empty() {
            return Err(SignatureClientError::Invalid(
                "Every streaming batch file must have a non-empty manifest path".into(),
            ));
        }
        if !seen.insert(input.manifest_path.as_str()) {
            return Err(SignatureClientError::Invalid(format!(
                "Duplicate path in streaming batch: \"{}\"", input.manifest_path
            )));
        }

        let source = OpenedStreamFile::open(&input.source_path, input.mime_type.as_deref())?;
        if let Some(max) = options.max_bytes_per_file {
            if source.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&source, options.cancellation)?;
        let canonical_len = plan.canonical_len()?;
        metadata.push((
            input.manifest_path.clone(),
            canonical_len,
            Some(plan.mime_type.clone()),
        ));
        sources.push(source);
        plans.push(plan);
    }

    let mut readers = Vec::with_capacity(inputs.len());
    for (source, plan) in sources.iter().zip(plans.iter()) {
        readers.push(RewrittenFileReader::new(source.try_clone_file()?, plan)?);
    }

    Ok(PreparedStreamingBatch {
        sources,
        readers,
        metadata,
    })
}

fn ensure_streaming_batch_sources_unchanged(
    sources: &[OpenedStreamFile],
) -> Result<()> {
    for source in sources {
        source.ensure_unchanged()?;
    }
    Ok(())
}


impl StreamingFileOptions<'_> {
    fn validate(&self) -> Result<()> {
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return Err(SignatureClientError::Invalid(format!(
                "Streaming chunk size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE} bytes"
            )));
        }
        Ok(())
    }

    fn check_cancelled(&self) -> Result<()> {
        if self
            .cancellation
            .map(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
            .unwrap_or(false)
        {
            return Err(SignatureClientError::Invalid(
                "Streaming operation was cancelled".into(),
            ));
        }
        Ok(())
    }
}

/// Metadata for a streamed output. Large source bytes are never included in this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingOutput {
    pub path: String,
    pub size_bytes: u64,
}

/// Result of detached path-based signing. `output` is the small `.mjksig` sidecar.
#[derive(Debug, Clone)]
pub struct StreamingDetachedSignResult {
    pub signature: MajikSignature,
    pub envelope: MajikSignatureEnvelope,
    pub output: StreamingOutput,
    pub source_size_bytes: u64,
    pub handler: String,
    pub mime_type: String,
}

/// Result of embedded path-based signing. The source document is written to `output`.
#[derive(Debug, Clone)]
pub struct StreamingEmbeddedSignResult {
    pub signature: MajikSignature,
    pub envelope: MajikSignatureEnvelope,
    pub output: StreamingOutput,
    pub source_size_bytes: u64,
    pub handler: String,
    pub mime_type: String,
}

/// An opened regular file plus the metadata captured from the open handle (not a separate path
/// lookup). Keeping the handle open avoids a path-swap between validation and reading.
pub struct OpenedStreamFile {
    file: File,
    path: PathBuf,
    length: u64,
    modified: Option<SystemTime>,
    name: Option<String>,
    mime_type: Option<String>,
}

impl OpenedStreamFile {
    pub fn open(path: impl AsRef<Path>, mime_type: Option<&str>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(file_error(
                "fileInvalid",
                "No input file path was provided.",
            ));
        }
        // Check before opening so directories, devices and FIFOs are rejected without blocking
        // on a special file's open semantics. The opened handle is checked again immediately after.
        let path_metadata = fs::metadata(&path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => io_file_error("fileNotFound", &path, error),
            io::ErrorKind::PermissionDenied => io_file_error("fileUnreadable", &path, error),
            _ => io_file_error("fileUnreadable", &path, error),
        })?;
        if !path_metadata.is_file() {
            return Err(file_error(
                "fileNotAFile",
                format!("Not a regular file: {}", path.display()),
            ));
        }
        let file = File::open(&path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => io_file_error("fileNotFound", &path, error),
            io::ErrorKind::PermissionDenied => io_file_error("fileUnreadable", &path, error),
            _ => io_file_error("fileUnreadable", &path, error),
        })?;
        let metadata = file
            .metadata()
            .map_err(|error| io_file_error("fileUnreadable", &path, error))?;
        if !metadata.is_file() {
            return Err(file_error(
                "fileNotAFile",
                format!("Not a regular file: {}", path.display()),
            ));
        }
        if metadata.len() == 0 {
            return Err(file_error(
                "fileEmpty",
                format!("The file is empty: {}", path.display()),
            ));
        }
        let name = path
            .file_name()
            .and_then(|part| part.to_str())
            .map(str::to_owned);
        let inferred = name.as_deref().and_then(mime_from_name);
        Ok(Self {
            file,
            path,
            length: metadata.len(),
            modified: metadata.modified().ok(),
            name,
            mime_type: mime_type.map(str::to_owned).or(inferred),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn length(&self) -> u64 {
        self.length
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }
    fn try_clone_file(&self) -> Result<File> {
        self.file
            .try_clone()
            .map_err(|error| io_file_error("fileUnreadable", &self.path, error))
    }

    /// Check for ordinary concurrent modifications after a read. The final output-copy path also
    /// hashes the exact canonical bytes it writes, catching same-size edits that metadata alone
    /// cannot identify.
    pub fn ensure_unchanged(&self) -> Result<()> {
        let current = self
            .file
            .metadata()
            .map_err(|error| io_file_error("fileUnreadable", &self.path, error))?;
        if !current.is_file() || current.len() != self.length {
            return Err(file_error(
                "fileChanged",
                format!(
                    "The source file changed while it was being processed: {}",
                    self.path.display()
                ),
            ));
        }
        if let (Some(before), Ok(after)) = (self.modified, current.modified()) {
            if before != after {
                return Err(file_error(
                    "fileChanged",
                    format!(
                        "The source file changed while it was being processed: {}",
                        self.path.display()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Write a result to a sibling temporary file, sync it, then publish it. With `overwrite=false`,
/// a hard-link publication prevents a race from silently replacing an existing destination.
pub fn write_atomic_with<F>(
    target: impl AsRef<Path>,
    overwrite: bool,
    writer: F,
) -> Result<StreamingOutput>
where
    F: FnOnce(&mut File) -> Result<u64>,
{
    let target = target.as_ref();
    if target.as_os_str().is_empty() {
        return Err(file_error("fileInvalid", "No output path was provided."));
    }
    if target.exists() && !target.is_file() {
        return Err(file_error(
            "fileInvalid",
            format!(
                "The output path is not a regular file: {}",
                target.display()
            ),
        ));
    }
    if target.exists() && !overwrite {
        return Err(file_error(
            "fileExists",
            format!("A file already exists at {}", target.display()),
        ));
    }
    let parent = target
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        return Err(file_error(
            "fileInvalid",
            format!("The output folder does not exist: {}", parent.display()),
        ));
    }
    let file_name = target
        .file_name()
        .and_then(|part| part.to_str())
        .unwrap_or("majik-output");
    let mut temp_path = None;
    let mut temp_file = None;
    for _ in 0..8 {
        let candidate = parent.join(format!(
            ".{file_name}.{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_file_error("fileWriteFailed", &candidate, error)),
        }
    }
    let temp_path = temp_path.ok_or_else(|| {
        file_error(
            "fileWriteFailed",
            "Could not reserve a temporary output file.",
        )
    })?;
    let mut temp_file = temp_file.ok_or_else(|| {
        file_error(
            "fileWriteFailed",
            "Could not open the temporary output file.",
        )
    })?;

    let writer_result = catch_unwind(AssertUnwindSafe(|| writer(&mut temp_file)));
    let size_bytes = match writer_result {
        Ok(Ok(size)) => size,
        Ok(Err(error)) => {
            drop(temp_file);
            let _ = fs::remove_file(&temp_path);
            return Err(error);
        }
        Err(_) => {
            drop(temp_file);
            let _ = fs::remove_file(&temp_path);
            return Err(SignatureClientError::Invalid(
                "Output writer panicked; the incomplete temporary file was discarded".into(),
            ));
        }
    };
    match temp_file.metadata() {
        Ok(metadata) if metadata.len() == size_bytes => {}
        Ok(metadata) => {
            drop(temp_file);
            let _ = fs::remove_file(&temp_path);
            return Err(file_error(
                "fileWriteFailed",
                format!(
                    "Output writer reported {size_bytes} bytes but staged {} bytes",
                    metadata.len()
                ),
            ));
        }
        Err(error) => {
            drop(temp_file);
            let _ = fs::remove_file(&temp_path);
            return Err(io_file_error("fileWriteFailed", &temp_path, error));
        }
    }
    if let Err(error) = temp_file.sync_all() {
        drop(temp_file);
        let _ = fs::remove_file(&temp_path);
        return Err(io_file_error("fileWriteFailed", &temp_path, error));
    }
    drop(temp_file);

    let publish = if overwrite {
        #[cfg(windows)]
        {
            if target.exists() {
                let backup = parent.join(format!(
                    ".{file_name}.{}.bak",
                    uuid::Uuid::new_v4().simple()
                ));
                fs::rename(target, &backup).and_then(|()| {
                    match fs::rename(&temp_path, target) {
                        Ok(()) => {
                            let _ = fs::remove_file(&backup);
                            Ok(())
                        }
                        Err(publish_error) => {
                            match fs::rename(&backup, target) {
                                Ok(()) => Err(publish_error),
                                Err(restore_error) => Err(io::Error::other(
                                    format!("Could not publish output ({publish_error}) or restore the previous file ({restore_error}); previous file is preserved at {}", backup.display()),
                                )),
                            }
                        }
                    }
                })
            } else {
                fs::rename(&temp_path, target)
            }
        }
        #[cfg(not(windows))]
        {
            fs::rename(&temp_path, target)
        }
    } else {
        match fs::hard_link(&temp_path, target) {
            Ok(()) => {
                let _ = fs::remove_file(&temp_path);
                Ok(())
            }
            Err(error) => Err(error),
        }
    };
    if let Err(error) = publish {
        let _ = fs::remove_file(&temp_path);
        let kind = if error.kind() == io::ErrorKind::AlreadyExists {
            "fileExists"
        } else {
            "fileWriteFailed"
        };
        return Err(io_file_error(kind, target, error));
    }
    Ok(StreamingOutput {
        path: target.to_string_lossy().into_owned(),
        size_bytes,
    })
}

/// Atomically write a small sidecar (for example, a `.mjksig` envelope).
pub fn write_atomic_bytes(
    target: impl AsRef<Path>,
    bytes: &[u8],
    overwrite: bool,
) -> Result<StreamingOutput> {
    write_atomic_with(target, overwrite, |file| {
        file.write_all(bytes)
            .map_err(|error| SignatureClientError::FileInput {
                kind: "fileWriteFailed",
                message: format!("Could not write sidecar: {error}"),
            })?;
        Ok(bytes.len() as u64)
    })
}

#[derive(Clone)]
struct RewritePlan {
    source_len: u64,
    replace_start: u64,
    replace_end: u64,
    canonical_replacement: Vec<u8>,
    envelope_payload: Option<String>,
    handler: &'static str,
    mime_type: String,
    has_mp4_moov: bool,
    /// True when an mdat precedes moov, so extending moov does not shift media chunk offsets.
    mp4_moov_after_mdat: bool,
    /// Canonical RIFF size field bytes for WAV (the unsigned form is normalised to its true length).
    riff_size_patch: Option<[u8; 4]>,
    /// Disk-backed canonical ZIP representation for Office/ODF files.
    office_archive: Option<Arc<office::OfficeArchivePlan>>,
}

impl RewritePlan {
    fn canonical_len(&self) -> Result<u64> {
        if let Some(office) = self.office_archive.as_ref() {
            return Ok(office.canonical_size());
        }
        if self.replace_start > self.replace_end || self.replace_end > self.source_len {
            return Err(SignatureClientError::Invalid(
                "Invalid source rewrite range".into(),
            ));
        }
        self.source_len
            .checked_sub(self.replace_end - self.replace_start)
            .and_then(|length| length.checked_add(self.canonical_replacement.len() as u64))
            .ok_or_else(|| SignatureClientError::Invalid("Canonical file size overflowed".into()))
    }
}

/// Read a logical file where one source range is replaced by a bounded metadata buffer. This lets
/// the signature engine hash PDF/MP4 canonical bytes without staging the whole file on disk.
struct RewrittenFileReader {
    file: File,
    source_len: u64,
    replace_start: u64,
    replace_end: u64,
    replacement: Vec<u8>,
    riff_size_patch: Option<[u8; 4]>,
    position: u64,
    virtual_len: u64,
}

impl RewrittenFileReader {
    fn new(source_file: File, plan: &RewritePlan) -> Result<Self> {
        let virtual_len = plan.canonical_len()?;
        if let Some(office) = plan.office_archive.as_ref() {
            let file = File::open(office.canonical_path())
                .map_err(|error| io_file_error("fileUnreadable", office.canonical_path(), error))?;
            return Ok(Self {
                file,
                source_len: virtual_len,
                replace_start: virtual_len,
                replace_end: virtual_len,
                replacement: Vec::new(),
                riff_size_patch: None,
                position: 0,
                virtual_len,
            });
        }
        Ok(Self {
            file: source_file,
            source_len: plan.source_len,
            replace_start: plan.replace_start,
            replace_end: plan.replace_end,
            replacement: plan.canonical_replacement.clone(),
            riff_size_patch: plan.riff_size_patch,
            position: 0,
            virtual_len,
        })
    }

    fn apply_riff_size_patch(&self, physical_start: u64, bytes: &mut [u8]) {
        let Some(patch) = self.riff_size_patch else {
            return;
        };
        let read_end = physical_start.saturating_add(bytes.len() as u64);
        let overlap_start = physical_start.max(4);
        let overlap_end = read_end.min(8);
        if overlap_start >= overlap_end {
            return;
        }
        let destination_start = (overlap_start - physical_start) as usize;
        let destination_end = (overlap_end - physical_start) as usize;
        let patch_start = (overlap_start - 4) as usize;
        let patch_end = (overlap_end - 4) as usize;
        bytes[destination_start..destination_end].copy_from_slice(&patch[patch_start..patch_end]);
    }
}

impl Read for RewrittenFileReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position >= self.virtual_len {
            return Ok(0);
        }
        let replacement_end = match self
            .replace_start
            .checked_add(self.replacement.len() as u64)
        {
            Some(end) => end,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "replacement range overflowed",
                ))
            }
        };
        if self.position < self.replace_start {
            let distance = self.replace_start - self.position;
            let count = output.len().min(distance.min(usize::MAX as u64) as usize);
            self.file.seek(SeekFrom::Start(self.position))?;
            let read = self.file.read(&mut output[..count])?;
            self.apply_riff_size_patch(self.position, &mut output[..read]);
            self.position += read as u64;
            return Ok(read);
        }
        if self.position < replacement_end {
            let offset = (self.position - self.replace_start) as usize;
            let count = output.len().min(self.replacement.len() - offset);
            output[..count].copy_from_slice(&self.replacement[offset..offset + count]);
            self.position += count as u64;
            return Ok(count);
        }
        let physical = self
            .replace_end
            .checked_add(self.position - replacement_end)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "source offset overflowed")
            })?;
        if physical >= self.source_len {
            return Ok(0);
        }
        let distance = self.source_len - physical;
        let count = output.len().min(distance.min(usize::MAX as u64) as usize);
        self.file.seek(SeekFrom::Start(physical))?;
        let read = self.file.read(&mut output[..count])?;
        self.apply_riff_size_patch(physical, &mut output[..read]);
        self.position += read as u64;
        Ok(read)
    }
}

fn report_stream_progress(
    options: &mut StreamingFileOptions<'_>,
    processed: u64,
    total: u64,
) -> Result<()> {
    if let Some(callback) = options.on_progress.as_deref_mut() {
        let event = StreamingHashProgress {
            bytes_processed: processed,
            total_bytes: Some(total),
        };
        if catch_unwind(AssertUnwindSafe(|| callback(event))).is_err() {
            return Err(SignatureClientError::Invalid(
                "The streaming progress callback panicked; output was not published".into(),
            ));
        }
    }
    Ok(())
}

// This helper intentionally receives the file, output, hash, and progress state separately so
// each bounded-copy step can update the canonical digest and caller-visible progress.
#[allow(clippy::too_many_arguments)]
fn copy_source_segment(
    file: &mut File,
    output: &mut File,
    start: u64,
    length: u64,
    hash: &mut Sha256,
    options: &mut StreamingFileOptions<'_>,
    processed: &mut u64,
    total: u64,
    riff_size_patch: Option<[u8; 4]>,
) -> Result<u64> {
    file.seek(SeekFrom::Start(start)).map_err(|error| {
        file_error(
            "fileUnreadable",
            format!("Could not seek source file: {error}"),
        )
    })?;
    let mut remaining = length;
    let mut buffer = allocate_stream_buffer(options.chunk_size)?;
    let mut written = 0u64;
    while remaining > 0 {
        options.check_cancelled()?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let count = file.read(&mut buffer[..wanted]).map_err(|error| {
            file_error(
                "fileUnreadable",
                format!("Could not read source file: {error}"),
            )
        })?;
        if count == 0 {
            return Err(file_error(
                "fileChanged",
                "The source file ended before the expected byte range was copied.",
            ));
        }
        if let Some(patch) = riff_size_patch {
            let physical_start = start + (length - remaining);
            let read_end = physical_start.saturating_add(count as u64);
            let overlap_start = physical_start.max(4);
            let overlap_end = read_end.min(8);
            if overlap_start < overlap_end {
                let destination_start = (overlap_start - physical_start) as usize;
                let destination_end = (overlap_end - physical_start) as usize;
                let patch_start = (overlap_start - 4) as usize;
                let patch_end = (overlap_end - 4) as usize;
                buffer[destination_start..destination_end]
                    .copy_from_slice(&patch[patch_start..patch_end]);
            }
        }
        output.write_all(&buffer[..count]).map_err(|error| {
            file_error(
                "fileWriteFailed",
                format!("Could not write output file: {error}"),
            )
        })?;
        hash.update(&buffer[..count]);
        remaining -= count as u64;
        written = written
            .checked_add(count as u64)
            .ok_or_else(|| SignatureClientError::Invalid("Copied byte count overflowed".into()))?;
        *processed = processed.checked_add(count as u64).ok_or_else(|| {
            SignatureClientError::Invalid("Progress byte count overflowed".into())
        })?;
        report_stream_progress(options, *processed, total)?;
    }
    Ok(written)
}

/// Copy a rewritten file while hashing its canonical (unsigned) form. The hash is checked before
/// the temporary file is published, so a same-size source edit during the operation is rejected.
fn write_rewritten_and_check(
    file: &mut File,
    output: &mut File,
    plan: &RewritePlan,
    output_replacement: &[u8],
    expected_hash: &str,
    options: &mut StreamingFileOptions<'_>,
) -> Result<u64> {
    let total_canonical = plan.canonical_len()?;
    let mut hash = Sha256::new();
    let mut total_output = 0u64;
    let mut processed = 0u64;
    total_output = total_output
        .checked_add(copy_source_segment(
            file,
            output,
            0,
            plan.replace_start,
            &mut hash,
            options,
            &mut processed,
            total_canonical,
            plan.riff_size_patch,
        )?)
        .ok_or_else(|| SignatureClientError::Invalid("Output byte count overflowed".into()))?;

    options.check_cancelled()?;
    output.write_all(output_replacement).map_err(|error| {
        file_error(
            "fileWriteFailed",
            format!("Could not write embedded signature: {error}"),
        )
    })?;
    total_output = total_output
        .checked_add(output_replacement.len() as u64)
        .ok_or_else(|| SignatureClientError::Invalid("Output byte count overflowed".into()))?;
    hash.update(&plan.canonical_replacement);
    processed = processed
        .checked_add(plan.canonical_replacement.len() as u64)
        .ok_or_else(|| SignatureClientError::Invalid("Progress byte count overflowed".into()))?;
    if !plan.canonical_replacement.is_empty() {
        report_stream_progress(options, processed, total_canonical)?;
    }

    let suffix_len = plan
        .source_len
        .checked_sub(plan.replace_end)
        .ok_or_else(|| SignatureClientError::Invalid("Invalid source rewrite range".into()))?;
    total_output = total_output
        .checked_add(copy_source_segment(
            file,
            output,
            plan.replace_end,
            suffix_len,
            &mut hash,
            options,
            &mut processed,
            total_canonical,
            plan.riff_size_patch,
        )?)
        .ok_or_else(|| SignatureClientError::Invalid("Output byte count overflowed".into()))?;

    if processed != total_canonical {
        return Err(SignatureClientError::Invalid(
            "The canonical source byte count changed during output writing".into(),
        ));
    }
    let actual = bytes_to_base64(&hash.finalize());
    if actual != expected_hash {
        return Err(SignatureClientError::Invalid(
            "The source changed after it was signed. No output was published; please retry.".into(),
        ));
    }
    if plan.handler == "WAV" {
        let riff_size = total_output.checked_sub(8).ok_or_else(|| {
            SignatureClientError::Invalid("WAV output is shorter than its RIFF header".into())
        })?;
        let riff_size = u32::try_from(riff_size).map_err(|_| {
            SignatureClientError::Invalid("WAV output exceeds the 32-bit RIFF size limit; RF64 is not supported by the core WAV handler".into())
        })?;
        output
            .seek(SeekFrom::Start(4))
            .map_err(|error| file_error("fileWriteFailed", error.to_string()))?;
        output
            .write_all(&riff_size.to_le_bytes())
            .map_err(|error| file_error("fileWriteFailed", error.to_string()))?;
        output
            .seek(SeekFrom::End(0))
            .map_err(|error| file_error("fileWriteFailed", error.to_string()))?;
    }
    Ok(total_output)
}

fn run_with_hash_options<T, F>(
    options: &mut StreamingFileOptions<'_>,
    total_bytes: u64,
    with_progress: bool,
    operation: F,
) -> Result<T>
where
    F: FnOnce(
        &mut StreamingHashOptions<'_>,
    ) -> std::result::Result<T, majik_signature::MajikSignatureError>,
{
    let chunk_size = options.chunk_size;
    let max_bytes = options.max_bytes;
    let cancellation = options.cancellation;
    let mut progress_callback = if with_progress {
        options.on_progress.as_deref_mut()
    } else {
        None
    };
    let mut callback_panicked = false;
    let mut guarded_progress = |update| {
        if callback_panicked {
            return;
        }
        if let Some(callback) = progress_callback.as_deref_mut() {
            if catch_unwind(AssertUnwindSafe(|| callback(update))).is_err() {
                callback_panicked = true;
            }
        }
    };
    let operation_result = {
        let mut hash_options = StreamingHashOptions {
            chunk_size,
            threshold_bytes: 0,
            max_bytes,
            total_bytes: Some(total_bytes),
            cancellation,
            on_progress: if with_progress {
                Some(&mut guarded_progress)
            } else {
                None
            },
        };
        catch_unwind(AssertUnwindSafe(|| operation(&mut hash_options)))
    };
    let value =
        match operation_result {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Err(SignatureClientError::Invalid(
                "The streaming signature operation aborted unexpectedly; no output was published"
                    .into(),
            )),
        };
    if callback_panicked {
        return Err(SignatureClientError::Invalid(
            "The streaming progress callback panicked; the operation was cancelled safely".into(),
        ));
    }
    Ok(value)
}

fn hash_reader_for_plan(
    source: &OpenedStreamFile,
    plan: &RewritePlan,
    options: &mut StreamingFileOptions<'_>,
    with_progress: bool,
) -> Result<[u8; 32]> {
    options.validate()?;
    if let Some(max) = options.max_bytes {
        if source.length() > max {
            return Err(file_error(
                "fileTooLarge",
                format!("Input exceeds the configured streaming limit of {max} bytes"),
            ));
        }
    }
    options.check_cancelled()?;
    let mut reader = RewrittenFileReader::new(source.try_clone_file()?, plan)?;
    let total = plan.canonical_len()?;
    let result = run_with_hash_options(options, total, with_progress, |hash_options| {
        majik_signature::hash_reader(&mut reader, hash_options)
    })?;
    Ok(result.digest)
}

fn read_exact_at(file: &mut File, offset: u64, length: usize, path: &Path) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| io_file_error("fileUnreadable", path, error))?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)
        .map_err(|error| io_file_error("fileUnreadable", path, error))?;
    Ok(bytes)
}

fn parse_pdf_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    let mut file = source.try_clone_file()?;
    let len = source.length();
    if len < 4 {
        return Err(SignatureClientError::Invalid(
            "The input is not a PDF file".into(),
        ));
    }
    let prefix = read_exact_at(&mut file, 0, 4, source.path())?;
    if prefix.as_slice() != b"%PDF" {
        return Err(SignatureClientError::Invalid(
            "The input is not a PDF file".into(),
        ));
    }
    let existing = read_pdf_signature(&mut file, len, source.path())?;
    let (prefix_len, payload) = existing.unwrap_or((len, None));
    Ok(RewritePlan {
        source_len: len,
        replace_start: prefix_len,
        replace_end: len,
        canonical_replacement: Vec::new(),
        envelope_payload: payload,
        handler: "PDF",
        mime_type: "application/pdf".to_string(),
        has_mp4_moov: false,
        mp4_moov_after_mdat: false,
        riff_size_patch: None,
        office_archive: None,
    })
}

fn read_pdf_signature(
    file: &mut File,
    len: u64,
    path: &Path,
) -> Result<Option<(u64, Option<String>)>> {
    if len < (PDF_SIGNATURE_MARKER.len() + 5) as u64 {
        return Ok(None);
    }
    let tail = read_exact_at(file, len - 4, 4, path)?;
    let payload_len = u32::from_be_bytes([tail[0], tail[1], tail[2], tail[3]]) as u64;
    if payload_len == 0 {
        return Ok(None);
    }
    let Some(payload_start) = len
        .checked_sub(4)
        .and_then(|value| value.checked_sub(payload_len))
    else {
        // Ordinary unsigned PDFs may end in arbitrary bytes that resemble an impossible length.
        return Ok(None);
    };
    if payload_start < PDF_SIGNATURE_MARKER.len() as u64 {
        return Ok(None);
    }
    let marker_start = payload_start - PDF_SIGNATURE_MARKER.len() as u64;
    let marker = read_exact_at(file, marker_start, PDF_SIGNATURE_MARKER.len(), path)?;
    if marker.as_slice() != PDF_SIGNATURE_MARKER {
        return Ok(None);
    }
    if payload_len > MAX_EMBEDDED_ENVELOPE_BYTES {
        return Err(file_error(
            "fileTooLarge",
            "Embedded PDF signature exceeds the streaming metadata limit",
        ));
    }
    let bytes = read_exact_at(file, payload_start, payload_len as usize, path)?;
    let payload = String::from_utf8(bytes).map_err(|error| {
        SignatureClientError::Invalid(format!("Malformed embedded PDF signature payload: {error}"))
    })?;
    Ok(Some((marker_start, Some(payload))))
}

#[derive(Clone)]
struct Mp4BoxPart {
    kind: [u8; 4],
    raw: std::ops::Range<usize>,
    data: std::ops::Range<usize>,
}

/// Parse only box boundaries. Child payloads remain borrowed from the bounded moov buffer rather
/// than being cloned into multiple Vecs.
fn parse_mp4_boxes(data: &[u8]) -> Result<(Vec<Mp4BoxPart>, std::ops::Range<usize>)> {
    let mut boxes = Vec::new();
    let mut offset = 0usize;
    while offset
        .checked_add(8)
        .map(|end| end <= data.len())
        .unwrap_or(false)
    {
        let size32 = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        let kind = [
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ];
        let (size, header_len) = if size32 == 1 {
            if offset
                .checked_add(16)
                .map(|end| end > data.len())
                .unwrap_or(true)
            {
                break;
            }
            let ext = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            (ext, 16usize)
        } else if size32 == 0 {
            return Err(SignatureClientError::Invalid(
                "MP4/MOV metadata contains a size-zero child box; refusing to rewrite an ambiguous container".into(),
            ));
        } else {
            (size32, 8usize)
        };
        if size < header_len as u64 || size > (data.len() - offset) as u64 {
            break;
        }
        let size = size as usize; // bounded above by data.len() - offset
        let end = offset + size;
        if boxes.len() >= MAX_MP4_METADATA_BOXES {
            return Err(SignatureClientError::Invalid(format!(
                "MP4/MOV metadata contains more than {MAX_MP4_METADATA_BOXES} boxes; refusing an unexpectedly complex container"
            )));
        }
        boxes.push(Mp4BoxPart {
            kind,
            raw: offset..end,
            data: (offset + header_len)..end,
        });
        offset = end;
    }
    Ok((boxes, offset..data.len()))
}

fn build_mp4_box(kind: [u8; 4], payload: &[u8]) -> Result<Vec<u8>> {
    let total = payload
        .len()
        .checked_add(8)
        .ok_or_else(|| SignatureClientError::Invalid("MP4 metadata box size overflowed".into()))?;
    let size = u32::try_from(total).map_err(|_| {
        SignatureClientError::Invalid(
            "MP4 metadata box exceeds the supported 32-bit box size".into(),
        )
    })?;
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&kind);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn mp4_moov_data(moov: &[u8]) -> Result<&[u8]> {
    if moov.len() < 8 || &moov[4..8] != b"moov" {
        return Err(SignatureClientError::Invalid(
            "Malformed MP4/MOV moov box".into(),
        ));
    }
    let size32 = u32::from_be_bytes([moov[0], moov[1], moov[2], moov[3]]);
    let header = if size32 == 1 { 16 } else { 8 };
    if moov.len() < header {
        return Err(SignatureClientError::Invalid(
            "Truncated MP4/MOV moov header".into(),
        ));
    }
    Ok(&moov[header..])
}

/// Mirrors the existing MP4 handler's `strip`: remove `udta/majk`, preserve all other boxes and
/// trailing bytes, and rebuild only the small `moov` metadata block.
fn strip_mp4_moov(moov: &[u8]) -> Result<(Vec<u8>, Option<String>)> {
    let data = mp4_moov_data(moov)?;
    let (children, trailing) = parse_mp4_boxes(data)?;
    let Some(udta_index) = children.iter().position(|child| &child.kind == b"udta") else {
        return Ok((moov.to_vec(), None));
    };
    let udta_data = &data[children[udta_index].data.clone()];
    let (udta_children, udta_trailing) = parse_mp4_boxes(udta_data)?;
    let mut payload = None;
    let mut filtered = Vec::new();
    for child in udta_children {
        if child.kind == MP4_SIGNATURE_BOX {
            if payload.is_none() {
                let encoded = &udta_data[child.data];
                if encoded.len() as u64 > MAX_EMBEDDED_ENVELOPE_BYTES {
                    return Err(file_error(
                        "fileTooLarge",
                        "Embedded MP4/MOV signature exceeds the streaming envelope safety limit",
                    ));
                }
                payload = Some(std::str::from_utf8(encoded).map(str::to_owned).map_err(
                    |error| {
                        SignatureClientError::Invalid(format!(
                            "Malformed MP4/MOV embedded signature payload: {error}"
                        ))
                    },
                )?);
            }
        } else {
            filtered.extend_from_slice(&udta_data[child.raw]);
        }
    }
    filtered.extend_from_slice(&udta_data[udta_trailing]);
    let remove_udta = filtered.is_empty();
    let replacement_udta = if remove_udta {
        None
    } else {
        Some(build_mp4_box(*b"udta", &filtered)?)
    };

    let mut new_moov_data = Vec::with_capacity(data.len());
    for (index, child) in children.iter().enumerate() {
        if index == udta_index {
            if let Some(udta) = replacement_udta.as_deref() {
                new_moov_data.extend_from_slice(udta);
            }
        } else {
            new_moov_data.extend_from_slice(&data[child.raw.clone()]);
        }
    }
    new_moov_data.extend_from_slice(&data[trailing]);
    Ok((build_mp4_box(*b"moov", &new_moov_data)?, payload))
}

/// Mirrors the existing MP4 handler's `embed`, inserting one `majk` child into `moov/udta`.
fn embed_mp4_moov(stripped_moov: &[u8], payload: &str) -> Result<Vec<u8>> {
    let data = mp4_moov_data(stripped_moov)?;
    let (children, trailing) = parse_mp4_boxes(data)?;
    let majk = build_mp4_box(MP4_SIGNATURE_BOX, payload.as_bytes())?;
    let udta_index = children.iter().position(|child| &child.kind == b"udta");
    let mut udta_data = Vec::new();
    if let Some(index) = udta_index {
        let existing_udta = &data[children[index].data.clone()];
        let (udta_children, udta_trailing) = parse_mp4_boxes(existing_udta)?;
        for child in udta_children {
            udta_data.extend_from_slice(&existing_udta[child.raw]);
        }
        udta_data.extend_from_slice(&majk);
        udta_data.extend_from_slice(&existing_udta[udta_trailing]);
    } else {
        udta_data.extend_from_slice(&majk);
    }
    let new_udta = build_mp4_box(*b"udta", &udta_data)?;

    let mut new_moov_data = Vec::new();
    for (index, child) in children.iter().enumerate() {
        if Some(index) == udta_index {
            new_moov_data.extend_from_slice(&new_udta);
        } else {
            new_moov_data.extend_from_slice(&data[child.raw.clone()]);
        }
    }
    if udta_index.is_none() {
        new_moov_data.extend_from_slice(&new_udta);
    }
    new_moov_data.extend_from_slice(&data[trailing]);
    build_mp4_box(*b"moov", &new_moov_data)
}

fn read_universal_trailer(file: &mut File, len: u64, path: &Path) -> Result<Option<(u64, String)>> {
    if len < 16 {
        return Ok(None);
    }
    let suffix = read_exact_at(file, len - 16, 16, path)?;
    if suffix[8..] != UNIVERSAL_TRAILER_MAGIC {
        return Ok(None);
    }
    let payload_len = u64::from_le_bytes([
        suffix[0], suffix[1], suffix[2], suffix[3], suffix[4], suffix[5], suffix[6], suffix[7],
    ]);
    if payload_len == 0 {
        return Ok(None);
    }
    if payload_len > MAX_EMBEDDED_ENVELOPE_BYTES {
        return Err(file_error(
            "fileTooLarge",
            "Embedded signature trailer exceeds the streaming metadata limit",
        ));
    }
    let suffix_len = 16u64.checked_add(payload_len).ok_or_else(|| {
        SignatureClientError::Invalid("Malformed universal signature trailer length".into())
    })?;
    let payload_start = len.checked_sub(suffix_len).ok_or_else(|| {
        SignatureClientError::Invalid("Malformed universal signature trailer length".into())
    })?;
    let bytes = read_exact_at(file, payload_start, payload_len as usize, path)?;
    let payload = String::from_utf8(bytes).map_err(|error| {
        SignatureClientError::Invalid(format!("Malformed universal signature payload: {error}"))
    })?;
    Ok(Some((payload_start, payload)))
}

fn parse_mp4_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    let len = source.length();
    let mut file = source.try_clone_file()?;
    let mut offset = 0u64;
    let mut seen_mdat = false;
    while offset.checked_add(8).map(|end| end <= len).unwrap_or(false) {
        let header = read_exact_at(&mut file, offset, 8, source.path())?;
        let size32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let kind = [header[4], header[5], header[6], header[7]];
        let (box_size, header_size) = if size32 == 1 {
            if offset.checked_add(16).map(|end| end > len).unwrap_or(true) {
                break;
            }
            let ext = read_exact_at(&mut file, offset + 8, 8, source.path())?;
            (
                u64::from_be_bytes([
                    ext[0], ext[1], ext[2], ext[3], ext[4], ext[5], ext[6], ext[7],
                ]),
                16u64,
            )
        } else if size32 == 0 {
            (len - offset, 8u64)
        } else {
            (size32, 8u64)
        };
        if box_size < header_size
            || offset
                .checked_add(box_size)
                .map(|end| end > len)
                .unwrap_or(true)
        {
            break;
        }
        if kind == *b"mdat" {
            seen_mdat = true;
        }
        if kind == *b"moov" {
            if box_size > MAX_CONTAINER_METADATA_BYTES {
                return Err(file_error(
                    "fileTooLarge",
                    format!(
                        "The MP4/MOV moov metadata exceeds the {} MiB streaming metadata limit",
                        MAX_CONTAINER_METADATA_BYTES / (1024 * 1024)
                    ),
                ));
            }
            let moov = read_exact_at(&mut file, offset, box_size as usize, source.path())?;
            let (stripped, payload) = strip_mp4_moov(&moov)?;
            return Ok(RewritePlan {
                source_len: len,
                replace_start: offset,
                replace_end: offset + box_size,
                canonical_replacement: stripped,
                envelope_payload: payload,
                handler: "MP4/MOV",
                mime_type: "video/mp4".to_string(),
                has_mp4_moov: true,
                mp4_moov_after_mdat: seen_mdat && offset.checked_add(box_size) == Some(len),
                riff_size_patch: None,
                office_archive: None,
            });
        }
        offset += box_size;
        if size32 == 0 {
            break;
        }
    }
    let trailer = read_universal_trailer(&mut file, len, source.path())?;
    let (prefix, payload) = trailer.unwrap_or((len, String::new()));
    Ok(RewritePlan {
        source_len: len,
        replace_start: prefix,
        replace_end: len,
        canonical_replacement: Vec::new(),
        envelope_payload: if payload.is_empty() {
            None
        } else {
            Some(payload)
        },
        handler: "MP4/MOV",
        mime_type: "video/mp4".to_string(),
        has_mp4_moov: false,
        mp4_moov_after_mdat: false,
        riff_size_patch: None,
        office_archive: None,
    })
}

fn detect_stream_format(
    source: &OpenedStreamFile,
    cancellation: Option<&AtomicBool>,
) -> Result<&'static str> {
    if cancellation
        .map(|flag| flag.load(std::sync::atomic::Ordering::Acquire))
        .unwrap_or(false)
    {
        return Err(SignatureClientError::Invalid(
            "Streaming operation was cancelled".into(),
        ));
    }
    let mut file = source.try_clone_file()?;
    let head_len = usize::try_from(source.length().min(16)).unwrap_or(16);
    let head = read_exact_at(&mut file, 0, head_len, source.path())?;
    let mime = source.mime_type().unwrap_or_default();

    if head.starts_with(b"%PDF") || mime == "application/pdf" {
        return Ok("pdf");
    }
    let mp4_mime = matches!(
        mime,
        "video/mp4" | "video/quicktime" | "audio/mp4" | "audio/m4a" | "video/x-m4v" | "video/m4v"
    );
    let mp4_magic = head.len() >= 8
        && (&head[4..8] == b"ftyp" || &head[4..8] == b"moov" || &head[4..8] == b"mdat");
    if mp4_mime || mp4_magic {
        return Ok("mp4");
    }

    if let Some(format) = media::detect_format(source, &head) {
        return Ok(format);
    }
    if office::detect_office_input(source, &head, cancellation)? {
        return Ok("office");
    }

    // Text and ZIP-based document formats retain specialised canonicalisation in the core
    // library. Never hash these as opaque bytes: doing so would silently diverge from verify().
    let specialised_mime = mime.starts_with("text/")
        || matches!(
            mime,
            "application/xml"
                | "application/json"
                | "application/javascript"
                | "application/typescript"
                | "application/x-sh"
                | "application/x-yaml"
                | "application/toml"
                | "application/msix"
                | "application/appx"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                | "application/vnd.ms-word.document.macroEnabled.12"
                | "application/vnd.ms-excel.sheet.macroEnabled.12"
                | "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
                | "audio/wav"
                | "audio/wave"
                | "audio/x-wav"
        );
    let specialised_magic = head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WAVE";
    if specialised_mime || specialised_magic {
        return Err(SignatureClientError::Invalid(format!(
            "Streaming operations do not yet support this specialised container handler (MIME: {}). Use the legacy in-memory API until its bounded-memory handler is available.",
            if mime.is_empty() { "unknown" } else { mime }
        )));
    }

    // Matroska/WebM use the same universal trailer as the fallback handler in the core crate,
    // so their media payload can be streamed unchanged by the generic trailer path.
    Ok("raw")
}

fn build_rewrite_plan(
    source: &OpenedStreamFile,
    cancellation: Option<&AtomicBool>,
) -> Result<RewritePlan> {
    let format = detect_stream_format(source, cancellation)?;
    match format {
        "pdf" => parse_pdf_plan(source),
        "mp4" => parse_mp4_plan(source),
        "png" | "jpeg" | "mp3" | "flac" | "wav" => media::build_plan(source, format),
        "office" => office::build_plan(source, cancellation),
        _ => {
            let mut file = source.try_clone_file()?;
            let trailer = read_universal_trailer(&mut file, source.length(), source.path())?;
            let (replace_start, payload) = trailer
                .map(|(start, value)| (start, Some(value)))
                .unwrap_or((source.length(), None));
            Ok(RewritePlan {
                source_len: source.length(),
                replace_start,
                replace_end: source.length(),
                canonical_replacement: Vec::new(),
                envelope_payload: payload,
                handler: "Fallback (Universal Trailer)",
                mime_type: source
                    .mime_type()
                    .unwrap_or("application/octet-stream")
                    .to_string(),
                has_mp4_moov: false,
                mp4_moov_after_mdat: false,
                riff_size_patch: None,
                office_archive: None,
            })
        }
    }
}

fn validate_stream_input_size(
    source: &OpenedStreamFile,
    stream: &StreamingFileOptions<'_>,
) -> Result<()> {
    if let Some(max) = stream.max_bytes {
        if source.length() > max {
            return Err(file_error(
                "fileTooLarge",
                format!("Input exceeds the configured streaming limit of {max} bytes"),
            ));
        }
    }
    Ok(())
}

fn normalized_destination(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .map_err(|error| io_file_error("fileWriteFailed", path, error));
    }
    let parent = path
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| file_error("fileInvalid", "Output path must include a filename"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| io_file_error("fileWriteFailed", parent, error))?;
    Ok(parent.join(name))
}

fn ensure_distinct_paths(source: &Path, destination: &Path) -> Result<()> {
    let source_canonical =
        fs::canonicalize(source).map_err(|error| io_file_error("fileUnreadable", source, error))?;
    let destination_canonical = normalized_destination(destination)?;
    if source_canonical == destination_canonical {
        return Err(file_error(
            "fileInvalid",
            "The output path must be different from the source path",
        ));
    }
    // Also reject hard-link aliases on Unix, where canonical paths alone are insufficient.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let source_meta = fs::metadata(&source_canonical)
            .map_err(|error| io_file_error("fileUnreadable", &source_canonical, error))?;
        if destination_canonical.exists() {
            let destination_meta = fs::metadata(&destination_canonical)
                .map_err(|error| io_file_error("fileWriteFailed", &destination_canonical, error))?;
            if source_meta.dev() == destination_meta.dev()
                && source_meta.ino() == destination_meta.ino()
            {
                return Err(file_error(
                    "fileInvalid",
                    "The output path refers to the same underlying file as the source",
                ));
            }
        }
    }
    Ok(())
}

fn validate_envelope_commitments(envelope: &MajikSignatureEnvelope) -> Result<()> {
    let allowlist = envelope.verify_allowlist_integrity();
    if !allowlist.valid {
        return Err(SignatureClientError::Invalid(format!(
            "Signature envelope allowlist integrity failed: {}",
            allowlist.reason.unwrap_or_default()
        )));
    }
    let chain_integrity = envelope.verify_version_chain_integrity();
    if !chain_integrity.valid {
        return Err(SignatureClientError::Invalid(format!(
            "Signature envelope version chain integrity failed: {}",
            chain_integrity.reason.unwrap_or_default()
        )));
    }

    let versions = envelope.file_versions();
    for signature_json in envelope.signatures() {
        let signature = MajikSignature::from_json(signature_json)?;
        let keys = signature.extract_public_keys()?;
        let commitment = MajikSignature::verify_commitment(&signature, &keys, None)?;
        if !commitment.base.valid {
            return Err(SignatureClientError::Invalid(format!(
                "Signature commitment for signer {} is invalid: {}",
                signature.signer_id(),
                commitment
                    .base
                    .reason
                    .unwrap_or_else(|| "cryptographic verification failed".into())
            )));
        }

        if versions.is_empty() {
            if signature.version_chain_hash().is_some() {
                return Err(SignatureClientError::Invalid(format!(
                    "Signature {} contains a version-chain commitment but the envelope has no fileVersions entries",
                    signature.signer_id()
                )));
            }
            continue;
        }

        let matching_version = versions.iter().enumerate().find(|(index, entry)| {
            if entry.content_hash != signature.content_hash() {
                return false;
            }
            match signature.version_chain_hash() {
                Some(expected) => {
                    MajikSignatureEnvelope::hash_file_version_chain(&versions[..=*index])
                        == expected
                }
                None => true,
            }
        });
        if matching_version.is_none() {
            return Err(SignatureClientError::Invalid(format!(
                "No fileVersions entry matches signature {} and its version-chain commitment",
                signature.signer_id()
            )));
        }
    }
    Ok(())
}

fn select_signature_for_content<'a>(
    envelope: &'a MajikSignatureEnvelope,
    content_hash: &str,
    expected_signer_id: Option<&str>,
) -> Option<&'a majik_signature::MajikSignatureJSON> {
    let matches = |signature: &&majik_signature::MajikSignatureJSON| {
        signature.content_hash == content_hash
            && expected_signer_id
                .map(|id| signature.signer_id == id)
                .unwrap_or(true)
    };
    let full_chain_hash = MajikSignatureEnvelope::hash_file_version_chain(envelope.file_versions());
    envelope
        .signatures()
        .iter()
        .find(|signature| {
            matches(signature)
                && signature.version_chain_hash.as_deref() == Some(full_chain_hash.as_str())
        })
        .or_else(|| envelope.signatures().iter().find(matches))
}

fn parse_plan_envelope(plan: &RewritePlan) -> Result<Option<MajikSignatureEnvelope>> {
    plan.envelope_payload
        .as_deref()
        .map(parse_embedded_envelope)
        .transpose()
        .map_err(Into::into)
}

fn verify_prior_stream(
    source: &OpenedStreamFile,
    plan: &RewritePlan,
    envelope: &MajikSignatureEnvelope,
    stream: &mut StreamingFileOptions<'_>,
) -> Result<String> {
    validate_envelope_commitments(envelope)?;
    let content_hash = bytes_to_base64(&hash_reader_for_plan(source, plan, stream, false)?);
    if let Some(latest) = envelope.last_file_version() {
        if latest.content_hash != content_hash {
            return Err(SignatureClientError::Invalid(
                "The prior file does not match the latest fileVersions entry; refusing to branch a new revision from an older version.".into(),
            ));
        }
    }
    let selected = select_signature_for_content(envelope, &content_hash, None).ok_or_else(|| {
        SignatureClientError::Invalid(
            "The prior file does not match any signature in its envelope; refusing to create a revision."
                .into(),
        )
    })?;
    let signature = MajikSignature::from_json(selected)?;
    let public_keys = signature.extract_public_keys()?;
    let mut reader = RewrittenFileReader::new(source.try_clone_file()?, plan)?;
    let verified = run_with_hash_options(stream, plan.canonical_len()?, false, |hash_options| {
        MajikSignature::verify_reader_with_options(
            &mut reader,
            &signature,
            &public_keys,
            None,
            hash_options,
        )
    })?;
    if !verified.valid {
        return Err(SignatureClientError::Invalid(format!(
            "The prior file signature is invalid: {}",
            verified
                .reason
                .unwrap_or_else(|| "signature verification failed".into())
        )));
    }
    source.ensure_unchanged()?;
    Ok(content_hash)
}

fn backfill_initial_file_version(
    envelope: MajikSignatureEnvelope,
    content_hash: &str,
) -> Result<MajikSignatureEnvelope> {
    if !envelope.file_versions().is_empty() || envelope.signatures().is_empty() {
        return Ok(envelope);
    }
    let first = &envelope.signatures()[0];
    let entry = FileVersion {
        version: 1,
        timestamp: first.timestamp.clone(),
        content_hash: content_hash.to_owned(),
        previous_version_hash: None,
        created_by: Some(first.signer_id.clone()),
        message: None,
    };
    Ok(envelope.with_file_version(entry)?)
}

fn check_envelope_before_signing(
    envelope: &MajikSignatureEnvelope,
    _current_hash: &str,
) -> Result<()> {
    // A changed document may legitimately carry an older signed envelope. Validate the previous
    // signers' cryptographic commitments and revision chain, then append a new FileVersion for the
    // current content rather than requiring the old envelope to match the new file hash.
    validate_envelope_commitments(envelope)
}

fn pdf_or_mp4_output_replacement(plan: &RewritePlan, payload: &str) -> Result<Vec<u8>> {
    if payload.len() as u64 > MAX_EMBEDDED_ENVELOPE_BYTES {
        return Err(SignatureClientError::Invalid(
            "Embedded signature envelope exceeds the streaming metadata limit".into(),
        ));
    }
    match plan.handler {
        "PDF" => {
            let len = u32::try_from(payload.len()).map_err(|_| {
                SignatureClientError::Invalid(
                    "PDF signature payload exceeds the 32-bit trailer limit".into(),
                )
            })?;
            let mut replacement =
                Vec::with_capacity(PDF_SIGNATURE_MARKER.len() + payload.len() + 4);
            replacement.extend_from_slice(PDF_SIGNATURE_MARKER);
            replacement.extend_from_slice(payload.as_bytes());
            replacement.extend_from_slice(&len.to_be_bytes());
            Ok(replacement)
        }
        "MP4/MOV" => {
            if !plan.has_mp4_moov {
                let mut replacement = Vec::with_capacity(payload.len() + 16);
                replacement.extend_from_slice(payload.as_bytes());
                replacement.extend_from_slice(&(payload.len() as u64).to_le_bytes());
                replacement.extend_from_slice(&UNIVERSAL_TRAILER_MAGIC);
                Ok(replacement)
            } else {
                embed_mp4_moov(&plan.canonical_replacement, payload)
            }
        }
        "PNG" | "JPEG" | "MP3" | "FLAC" | "WAV" => media::output_replacement(plan, payload)?
            .ok_or_else(|| {
                SignatureClientError::Invalid(
                    "The media streaming handler did not produce signature metadata".into(),
                )
            }),
        "Fallback (Universal Trailer)" => {
            let mut replacement = Vec::with_capacity(payload.len() + 16);
            replacement.extend_from_slice(payload.as_bytes());
            replacement.extend_from_slice(&(payload.len() as u64).to_le_bytes());
            replacement.extend_from_slice(&UNIVERSAL_TRAILER_MAGIC);
            Ok(replacement)
        }
        _ => Err(SignatureClientError::Invalid(
            "Embedded streaming is not available for this specialised container handler".into(),
        )),
    }
}

fn sign_event_and_history(
    client: &mut SignatureClient,
    signature: &MajikSignature,
    envelope: &MajikSignatureEnvelope,
    source: HistorySource,
    detached: bool,
) {
    let sign_result = SignResult {
        signature: signature.clone(),
        signer_id: signature.signer_id().to_string(),
        content_hash: signature.content_hash().to_string(),
        timestamp: signature.timestamp().to_string(),
        content_type: signature.content_type().map(str::to_owned),
    };
    client.emit(SigOnlyEvent::Sign(Box::new(SignEventPayload::from(
        &sign_result,
    ))));
    let mut note = OpNote::new(signature.content_hash(), HistoryType::Sign, source);
    note.detached = detached;
    note.tsa = signature.has_tsa();
    note.signer_count = Some(envelope.signatures().len() as u32);
    // Deliberately do not put a multi-gigabyte file into the encrypted history envelope.
    client.note_history(
        Some(signature.signer_id()),
        note,
        signature.content_hash(),
        None,
    );
}

impl SignatureClient {
    /// Sign format-aware native file paths as detached batch signatures without
    /// materializing source documents. The returned manifest or sidecars are small
    /// outputs; file contents are consumed sequentially through bounded readers.
    pub fn sign_batch_detached_paths_stream(
        &mut self,
        inputs: &[StreamingBatchPathInput],
        options: &BatchSignOptions,
        context: &OpContext,
        streaming: &mut BatchStreamingFileOptions<'_>,
    ) -> Result<BatchSignResult> {
        let mut prepared = prepare_streaming_batch(inputs, streaming)?;
        let PreparedStreamingBatch {
            sources,
            metadata,
            readers,
        } = &mut prepared;

        let mut core_inputs = Vec::with_capacity(inputs.len());
        for ((path, total_bytes, mime_type), reader) in
            metadata.iter().zip(readers.iter_mut())
        {
            core_inputs.push(StreamingBatchFileInput {
                path: path.clone(),
                reader,
                total_bytes: Some(*total_bytes),
                mime_type: mime_type.clone(),
            });
        }

        let chunk_size = streaming.chunk_size;
        let max_bytes_per_file = streaming.max_bytes_per_file;
        let cancellation = streaming.cancellation;
        let progress_callback = streaming.on_progress.as_deref_mut();
        let mut callback_panicked = false;
        let mut guarded_progress = |progress: StreamingBatchProgress| {
            if let Some(callback) = progress_callback.as_deref_mut() {
                if catch_unwind(AssertUnwindSafe(|| callback(progress))).is_err() {
                    callback_panicked = true;
                }
            }
        };
        let core_streaming = CoreBatchStreamingOptions {
            chunk_size,
            max_bytes_per_file,
            cancellation,
            on_progress: Some(&mut guarded_progress),
        };

        let signed = self.with_signing_key(context.account_id.as_deref(), false, |key| {
            Ok(MajikSignature::sign_batch_detached_stream(
                &mut core_inputs,
                key,
                Some(options),
                core_streaming,
            )?)
        });
        let (result, _) = self.report("signBatchDetachedPathsStream", signed)?;
        drop(core_inputs);
        drop(guarded_progress);

        if callback_panicked {
            return Err(SignatureClientError::Invalid(
                "The streaming batch progress callback panicked; no batch result was returned"
                    .into(),
            ));
        }
        ensure_streaming_batch_sources_unchanged(sources)?;

        match &result {
            BatchSignResult::Map { map, failures, .. } => {
                for entry in map.entries() {
                    let envelope = MajikSignatureEnvelope::from_json(&entry.envelope)?;
                    let signature_json = envelope.signatures().last().ok_or_else(|| {
                        SignatureClientError::Invalid(
                            "A streaming batch result contained an envelope without signatures"
                                .into(),
                        )
                    })?;
                    let signature = MajikSignature::from_json(signature_json)?;
                    sign_event_and_history(self, &signature, &envelope, context.source, true);
                }
                for failure in failures {
                    self.emit_error(
                        "signBatchDetachedPathsStream",
                        &SignatureClientError::Invalid(format!(
                            "{}: {}", failure.path, failure.error
                        )),
                    );
                }
            }
            BatchSignResult::Separate { signatures, failures } => {
                for separate in signatures {
                    let envelope = MajikSignatureEnvelope::from_mjksig(&separate.blob)?;
                    let signature_json = envelope.signatures().last().ok_or_else(|| {
                        SignatureClientError::Invalid(
                            "A streaming batch sidecar contained no signatures".into(),
                        )
                    })?;
                    let signature = MajikSignature::from_json(signature_json)?;
                    sign_event_and_history(self, &signature, &envelope, context.source, true);
                }
                for failure in failures {
                    self.emit_error(
                        "signBatchDetachedPathsStream",
                        &SignatureClientError::Invalid(format!(
                            "{}: {}", failure.path, failure.error
                        )),
                    );
                }
            }
        }

        Ok(result)
    }

    /// Verify format-aware native file paths against a MJKSMAP manifest without
    /// materializing file contents. Streaming verification requires a trusted
    /// key/contact/address; use the buffered method for self-reported-key mode.
    pub fn verify_mjks_map_paths_stream(
        &mut self,
        map_input: crate::mjks::MjksMapInput,
        inputs: &[StreamingBatchPathInput],
        target: &VerifyTarget<'_>,
        require_all_present: bool,
        source: HistorySource,
        streaming: &mut BatchStreamingFileOptions<'_>,
    ) -> Result<crate::mjks::MapVerifyResult> {
        let map = map_input.resolve()?;
        let public_keys = self
            .resolve_signer_public_keys(target)?
            .ok_or_else(|| SignatureClientError::Invalid(
                "Streaming MJKSMAP verification requires a trusted signer key, contact, or address."
                    .into(),
            ))?;

        let mut prepared = prepare_streaming_batch(inputs, streaming)?;
        let PreparedStreamingBatch {
            sources,
            metadata,
            readers,
        } = &mut prepared;

        let mut core_inputs = Vec::with_capacity(inputs.len());
        for ((path, total_bytes, _mime_type), reader) in
            metadata.iter().zip(readers.iter_mut())
        {
            core_inputs.push(StreamingBatchVerifyInput {
                path: path.clone(),
                reader,
                total_bytes: Some(*total_bytes),
            });
        }

        let verify_options = BatchVerifyOptions {
            expected_signer_id: target.expected_signer_id.map(str::to_owned),
            now: target.now,
            require_all_present,
        };
        let chunk_size = streaming.chunk_size;
        let max_bytes_per_file = streaming.max_bytes_per_file;
        let cancellation = streaming.cancellation;
        let progress_callback = streaming.on_progress.as_deref_mut();
        let mut callback_panicked = false;
        let mut guarded_progress = |progress: StreamingBatchProgress| {
            if let Some(callback) = progress_callback.as_deref_mut() {
                if catch_unwind(AssertUnwindSafe(|| callback(progress))).is_err() {
                    callback_panicked = true;
                }
            }
        };
        let core_streaming = CoreBatchStreamingOptions {
            chunk_size,
            max_bytes_per_file,
            cancellation,
            on_progress: Some(&mut guarded_progress),
        };

        let outcome = MajikSignature::verify_files_from_mjksmap_stream(
            &map,
            &mut core_inputs,
            &public_keys,
            Some(&verify_options),
            core_streaming,
        );
        let results = self.report("verifyMjksMapPathsStream", outcome)?;
        drop(core_inputs);
        drop(guarded_progress);

        if callback_panicked {
            return Err(SignatureClientError::Invalid(
                "The streaming batch progress callback panicked; no verification result was returned"
                    .into(),
            ));
        }
        ensure_streaming_batch_sources_unchanged(sources)?;

        let missing_from_batch = if require_all_present {
            let mut covered: HashSet<String> =
                inputs.iter().map(|file| file.manifest_path.clone()).collect();
            for result in &results {
                if let Some(original) = result.relocated_from.as_ref() {
                    covered.insert(original.clone());
                }
            }
            map.entries()
                .iter()
                .filter(|entry| !covered.contains(&entry.path))
                .map(|entry| entry.path.clone())
                .collect()
        } else {
            Vec::new()
        };
        let summary = MajikSignature::summarize_batch_verification(&results);

        let fingerprint = self.active_fingerprint();
        for result in &results {
            if let Some(first) = result.results.as_ref().and_then(|items| items.first()) {
                if let Some(hash) = first.content_hash.clone().filter(|value| !value.is_empty()) {
                    let mut note = OpNote::new(&hash, HistoryType::Verify, source);
                    note.detached = true;
                    note.valid = Some(first.valid);
                    self.note_history(fingerprint.as_deref(), note, &hash, None);
                }
            }
        }

        Ok(crate::mjks::MapVerifyResult {
            results,
            summary,
            missing_from_batch,
        })
    }

    /// Sign a native file path into a detached .mjksig sidecar using bounded memory.
    /// Use `sign_file_detached_stream_with_prior` to verify and extend a previous file version
    /// without loading that previous file into memory.
    pub fn sign_file_detached_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        envelope_output_path: impl AsRef<Path>,
        options: &SignDetachedFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingDetachedSignResult> {
        self.sign_file_detached_stream_inner(
            input_path.as_ref(),
            envelope_output_path.as_ref(),
            options,
            context,
            stream,
            overwrite,
            None,
        )
    }

    /// Create a detached revision after verifying the previous file path against its existing
    /// sidecar envelope. The previous file itself is read and hashed incrementally.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_file_detached_stream_with_prior(
        &mut self,
        input_path: impl AsRef<Path>,
        envelope_output_path: impl AsRef<Path>,
        prior_file_path: impl AsRef<Path>,
        options: &SignDetachedFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingDetachedSignResult> {
        self.sign_file_detached_stream_inner(
            input_path.as_ref(),
            envelope_output_path.as_ref(),
            options,
            context,
            stream,
            overwrite,
            Some(prior_file_path.as_ref()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_file_detached_stream_inner(
        &mut self,
        input_path: &Path,
        envelope_output_path: &Path,
        options: &SignDetachedFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
        prior_file_path: Option<&Path>,
    ) -> Result<StreamingDetachedSignResult> {
        if options.prior_file.is_some() {
            return Err(SignatureClientError::Invalid(
                "For streaming revisions, pass priorFile as a native path using sign_file_detached_stream_with_prior; the in-memory priorFile field is not used by streaming APIs.".into(),
            ));
        }
        stream.validate()?;
        let source = OpenedStreamFile::open(input_path, options.mime_type.as_deref())?;
        ensure_distinct_paths(source.path(), envelope_output_path)?;
        if let Some(max) = stream.max_bytes {
            if source.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&source, stream.cancellation)?;
        let (envelope, prior_content_hash) = if let Some(prior_path) = prior_file_path {
            ensure_distinct_paths(prior_path, input_path)?;
            ensure_distinct_paths(prior_path, envelope_output_path)?;
            let prior_input = options.existing_envelope.clone().ok_or_else(|| {
                SignatureClientError::Invalid(
                    "A detached revision requires existingEnvelope for the prior file.".into(),
                )
            })?;
            let prior_envelope = MajikSignatureEnvelope::from_input(prior_input)?;
            let prior_source = OpenedStreamFile::open(prior_path, None)?;
            validate_stream_input_size(&prior_source, stream)?;
            let prior_plan = build_rewrite_plan(&prior_source, stream.cancellation)?;
            let prior_hash =
                verify_prior_stream(&prior_source, &prior_plan, &prior_envelope, stream)?;
            let prior_envelope = backfill_initial_file_version(prior_envelope, &prior_hash)?;
            (prior_envelope, Some(prior_hash))
        } else {
            let envelope = match options.existing_envelope.clone() {
                Some(input) => MajikSignatureEnvelope::from_input(input)?,
                None => parse_plan_envelope(&plan)?.unwrap_or_else(MajikSignatureEnvelope::empty),
            };
            (envelope, None)
        };
        validate_envelope_commitments(&envelope)?;
        let total = plan.canonical_len()?;
        let current_content_hash = if prior_content_hash.is_some() {
            Some(bytes_to_base64(&hash_reader_for_plan(
                &source, &plan, stream, false,
            )?))
        } else {
            None
        };
        let sign_result = self.with_signing_key(context.account_id.as_deref(), false, |key| {
            envelope.assert_can_sign(key)?;
            let allowlist_hash =
                envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());
            let revision = if let Some(content_hash) = current_content_hash.as_deref() {
                let last = envelope.last_file_version();
                let next_version = match last {
                    Some(entry) => entry.version.checked_add(1).ok_or_else(|| {
                        SignatureClientError::Invalid(
                            "Detached file version counter overflowed".into(),
                        )
                    })?,
                    None => 1,
                };
                let timestamp = options
                    .timestamp
                    .clone()
                    .unwrap_or_else(|| Timestamp::now().to_string());
                Some(FileVersion {
                    version: next_version,
                    timestamp,
                    content_hash: content_hash.to_owned(),
                    previous_version_hash: last
                        .map(MajikSignatureEnvelope::hash_file_version_entry),
                    created_by: Some(key.fingerprint().to_string()),
                    message: options
                        .message
                        .clone()
                        .filter(|message| !message.is_empty()),
                })
            } else {
                None
            };
            let version_chain_hash = revision.as_ref().map(|entry| {
                let mut chain = envelope.file_versions().to_vec();
                chain.push(entry.clone());
                MajikSignatureEnvelope::hash_file_version_chain(&chain)
            });
            let sign_options = SignOptions {
                content_type: options.content_type.clone(),
                timestamp: revision
                    .as_ref()
                    .map(|entry| entry.timestamp.clone())
                    .or_else(|| options.timestamp.clone()),
                valid_until: options.valid_until.clone(),
                allowlist_hash,
                version_chain_hash,
                session_context_hash: options.session_context_hash.clone(),
                ..Default::default()
            };
            let file = source.try_clone_file()?;
            let mut reader = RewrittenFileReader::new(file, &plan)?;
            let mut signature = run_with_hash_options(stream, total, true, |hash_options| {
                MajikSignature::sign_reader_with_options(
                    &mut reader,
                    key,
                    Some(&sign_options),
                    hash_options,
                )
            })?;
            if let Some(tsa) = options.tsa.clone() {
                signature.add_tsa(tsa)?;
            }

            let establishing = envelope.is_first_signer()
                && options
                    .expected_signers
                    .as_ref()
                    .map(|signers| !signers.is_empty())
                    .unwrap_or(false);
            let with_allowlist = if establishing {
                envelope.with_allowlist(
                    options.expected_signers.as_deref().unwrap_or(&[]),
                    key.fingerprint(),
                )?
            } else {
                envelope.clone()
            };
            if let Some(expected_hash) = current_content_hash.as_deref() {
                if signature.content_hash() != expected_hash {
                    return Err(SignatureClientError::Invalid(
                        "The source changed between the revision pre-hash and signing pass".into(),
                    ));
                }
            }
            let with_version = match revision {
                Some(entry) => with_allowlist.with_file_version(entry)?,
                None => with_allowlist,
            };
            let next = with_version.with_signature(signature.to_json())?;

            // Re-read and verify before publishing the sidecar. This catches source changes that
            // preserve file size/mtime precision while the first pass was running.
            let file = source.try_clone_file()?;
            let mut verify_reader = RewrittenFileReader::new(file, &plan)?;
            let public_keys = signature.extract_public_keys()?;
            let verified = run_with_hash_options(stream, total, false, |hash_options| {
                MajikSignature::verify_reader_with_options(
                    &mut verify_reader,
                    &signature,
                    &public_keys,
                    None,
                    hash_options,
                )
            })?;
            if !verified.valid {
                return Err(SignatureClientError::Invalid(
                    "The source file changed while it was being signed; no sidecar was written."
                        .into(),
                ));
            }
            Ok((signature, next))
        });
        let ((signature, envelope), _) = self.report("signFileDetachedStream", sign_result)?;
        source.ensure_unchanged()?;
        let envelope_bytes = envelope.to_mjksig_bytes()?;
        if envelope_bytes.len() as u64 > MAX_EMBEDDED_ENVELOPE_BYTES {
            return Err(file_error(
                "fileTooLarge",
                "Detached signature envelope exceeds the 16 MiB streaming safety limit",
            ));
        }
        let output = write_atomic_bytes(envelope_output_path, &envelope_bytes, overwrite)?;
        sign_event_and_history(self, &signature, &envelope, context.source, true);
        Ok(StreamingDetachedSignResult {
            signature,
            envelope,
            output,
            source_size_bytes: source.length(),
            handler: plan.handler.to_string(),
            mime_type: options
                .mime_type
                .clone()
                .or_else(|| source.mime_type().map(str::to_owned))
                .unwrap_or_else(|| plan.mime_type.clone()),
        })
    }

    /// Verify a file path against a detached `.mjksig` sidecar without loading the media bytes.
    pub fn verify_file_detached_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        envelope_path: impl AsRef<Path>,
        target: &VerifyTarget<'_>,
        stream: &mut StreamingFileOptions<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        stream.validate()?;
        let file = OpenedStreamFile::open(&input_path, target.mime_type)?;
        if let Some(max) = stream.max_bytes {
            if file.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let envelope_bytes = read_small_envelope(envelope_path.as_ref())?;
        let envelope = MajikSignatureEnvelope::from_input(EnvelopeInput::Bytes(envelope_bytes))?;
        validate_envelope_commitments(&envelope)?;
        let plan = build_rewrite_plan(&file, stream.cancellation)?;
        let current_hash = bytes_to_base64(&hash_reader_for_plan(&file, &plan, stream, true)?);
        let resolved = self.resolve_signer_public_keys(target)?;
        let signer_id = target
            .expected_signer_id
            .or_else(|| resolved.as_ref().map(|keys| keys.signer_id.as_str()));
        let selected = select_signature_for_content(&envelope, &current_hash, signer_id);
        let Some(selected) = selected else {
            let result = invalid_result("No signature in the detached envelope matches the current file contents and requested signer");
            return Ok(self.finish_file_verify(result, false, envelope.is_sealed(), true, source));
        };
        let signature = MajikSignature::from_json(selected)?;
        let keys = match resolved {
            Some(keys) => keys,
            None => signature.extract_public_keys()?,
        };
        let mut reader = RewrittenFileReader::new(file.try_clone_file()?, &plan)?;
        let result = run_with_hash_options(stream, plan.canonical_len()?, true, |hash_options| {
            MajikSignature::verify_reader_with_options(
                &mut reader,
                &signature,
                &keys,
                target.now,
                hash_options,
            )
        })?;
        file.ensure_unchanged()?;
        let tsa = signature.has_tsa();
        Ok(self.finish_file_verify(result, tsa, envelope.is_sealed(), true, source))
    }

    /// Sign and embed a file using bounded-memory native path I/O.
    ///
    /// Container metadata is the only part buffered: PDF and MP4/MOV rewrite their signature
    /// structures; PNG/JPEG, MP3/FLAC/WAV use their existing metadata layouts; Matroska/WebM and
    /// unknown fallback formats use the core universal trailer. MP4/MOV embedding is restricted
    /// to layouts where a final `moov` follows `mdat`, avoiding unsafe media-offset rebasing.
    pub fn sign_file_embedded_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        options: &SignFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingEmbeddedSignResult> {
        self.sign_file_embedded_stream_inner(
            input_path.as_ref(),
            output_path.as_ref(),
            options,
            context,
            stream,
            overwrite,
            None,
        )
    }

    /// Sign a new file version after verifying the prior signed file from a native path.
    /// The prior file is never loaded into memory; its embedded envelope and content are checked
    /// with the same reader-based verification used by normal streaming verification.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_file_embedded_stream_with_prior(
        &mut self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        prior_signed_file_path: impl AsRef<Path>,
        options: &SignFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingEmbeddedSignResult> {
        self.sign_file_embedded_stream_inner(
            input_path.as_ref(),
            output_path.as_ref(),
            options,
            context,
            stream,
            overwrite,
            Some(prior_signed_file_path.as_ref()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_file_embedded_stream_inner(
        &mut self,
        input_path: &Path,
        output_path: &Path,
        options: &SignFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
        prior_signed_file_path: Option<&Path>,
    ) -> Result<StreamingEmbeddedSignResult> {
        if options.prior_signed_file.is_some() {
            return Err(SignatureClientError::Invalid(
                "For streaming revisions, pass priorSignedFile as a native path using sign_file_embedded_stream_with_prior; the in-memory priorSignedFile field is not used by streaming APIs.".into(),
            ));
        }
        stream.validate()?;
        let mut source = OpenedStreamFile::open(input_path, options.mime_type.as_deref())?;
        ensure_distinct_paths(source.path(), output_path)?;
        if let Some(max) = stream.max_bytes {
            if source.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&source, stream.cancellation)?;
        if !matches!(
            plan.handler,
            "PDF"
                | "Office (DOCX/XLSX/PPTX/ODF)"
                | "MP4/MOV"
                | "PNG"
                | "JPEG"
                | "MP3"
                | "FLAC"
                | "WAV"
                | "Fallback (Universal Trailer)"
        ) {
            return Err(SignatureClientError::Invalid(
                "Large-file embedded signing is currently supported for PDF, MP4/MOV, PNG, JPEG, MP3, FLAC, WAV, and universal-trailer formats. This specialised container is not yet supported by the streaming writer.".into(),
            ));
        }
        if plan.has_mp4_moov && !plan.mp4_moov_after_mdat {
            return Err(SignatureClientError::Invalid(
                "This MP4/MOV places its moov metadata before media data. Expanding moov can shift absolute media chunk offsets; use detached streaming signing or a file with moov after mdat until chunk-offset rebasing is available.".into(),
            ));
        }
        let envelope = if let Some(prior_path) = prior_signed_file_path {
            ensure_distinct_paths(prior_path, input_path)?;
            ensure_distinct_paths(prior_path, output_path)?;
            let prior_source = OpenedStreamFile::open(prior_path, None)?;
            validate_stream_input_size(&prior_source, stream)?;
            let prior_plan = build_rewrite_plan(&prior_source, stream.cancellation)?;
            let prior_envelope = parse_plan_envelope(&prior_plan)?.ok_or_else(|| {
                SignatureClientError::Invalid(
                    "The prior file does not contain an embedded Majik Signature envelope.".into(),
                )
            })?;
            let prior_hash =
                verify_prior_stream(&prior_source, &prior_plan, &prior_envelope, stream)?;
            backfill_initial_file_version(prior_envelope, &prior_hash)?
        } else {
            parse_plan_envelope(&plan)?.unwrap_or_else(MajikSignatureEnvelope::empty)
        };
        let digest = hash_reader_for_plan(&source, &plan, stream, true)?;
        let content_hash = bytes_to_base64(&digest);
        check_envelope_before_signing(&envelope, &content_hash)?;
        let canonical_len = plan.canonical_len()?;
        source.ensure_unchanged()?;

        let sign_result = self.with_signing_key(context.account_id.as_deref(), false, |key| {
            envelope.assert_can_sign(key)?;
            let timestamp = options
                .timestamp
                .clone()
                .unwrap_or_else(|| Timestamp::now().to_string());
            let last = envelope.last_file_version();
            let next_version = match last {
                Some(entry) => entry.version.checked_add(1).ok_or_else(|| {
                    SignatureClientError::Invalid("Embedded file version counter overflowed".into())
                })?,
                None => 1,
            };
            let version = FileVersion {
                version: next_version,
                timestamp: timestamp.clone(),
                content_hash: content_hash.clone(),
                previous_version_hash: last.map(MajikSignatureEnvelope::hash_file_version_entry),
                created_by: Some(key.fingerprint().to_string()),
                message: options
                    .message
                    .clone()
                    .filter(|message| !message.is_empty()),
            };
            let mut chain = envelope.file_versions().to_vec();
            chain.push(version.clone());
            let version_chain_hash = MajikSignatureEnvelope::hash_file_version_chain(&chain);
            let allowlist_hash =
                envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());
            let sign_options = SignOptions {
                content_type: options.content_type.clone(),
                timestamp: Some(timestamp),
                valid_until: options.valid_until.clone(),
                allowlist_hash,
                version_chain_hash: Some(version_chain_hash),
                ..Default::default()
            };
            let mut reader = RewrittenFileReader::new(source.try_clone_file()?, &plan)?;
            let signature = run_with_hash_options(stream, canonical_len, false, |hash_options| {
                MajikSignature::sign_reader_with_options(
                    &mut reader,
                    key,
                    Some(&sign_options),
                    hash_options,
                )
            })?;
            if signature.content_hash() != content_hash {
                return Err(SignatureClientError::Invalid(
                    "The source changed between the hashing and signing passes".into(),
                ));
            }
            let establishing = envelope.is_first_signer()
                && options
                    .expected_signers
                    .as_ref()
                    .map(|signers| !signers.is_empty())
                    .unwrap_or(false);
            let with_allowlist = if establishing {
                envelope.with_allowlist(
                    options.expected_signers.as_deref().unwrap_or(&[]),
                    key.fingerprint(),
                )?
            } else {
                envelope.clone()
            };
            let with_version = with_allowlist.with_file_version(version)?;
            let next = with_version.with_signature(signature.to_json())?;
            Ok((signature, next))
        });
        let ((signature, envelope), _) = self.report("signFileEmbeddedStream", sign_result)?;
        source.ensure_unchanged()?;
        let embedded_payload = serialize_embedded_envelope(&envelope)?;
        let output = if let Some(office_archive) = plan.office_archive.as_ref() {
            write_atomic_with(output_path, overwrite, |destination| {
                office::write_signed_archive(
                    office_archive,
                    &embedded_payload,
                    destination,
                    stream.cancellation,
                )
            })?
        } else {
            let replacement = pdf_or_mp4_output_replacement(&plan, &embedded_payload)?;
            write_atomic_with(output_path, overwrite, |destination| {
                let input = source.file_mut();
                write_rewritten_and_check(
                    input,
                    destination,
                    &plan,
                    &replacement,
                    signature.content_hash(),
                    stream,
                )
            })?
        };
        source.ensure_unchanged()?;
        sign_event_and_history(self, &signature, &envelope, context.source, false);
        Ok(StreamingEmbeddedSignResult {
            signature,
            envelope,
            output,
            source_size_bytes: source.length(),
            handler: plan.handler.to_string(),
            mime_type: if plan.handler == "PDF" {
                "application/pdf".into()
            } else {
                options
                    .mime_type
                    .clone()
                    .or_else(|| source.mime_type().map(str::to_owned))
                    .unwrap_or_else(|| plan.mime_type.clone())
            },
        })
    }

    /// Verify an embedded media/document path by reading its canonical unsigned representation.
    pub fn verify_file_embedded_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        target: &VerifyTarget<'_>,
        stream: &mut StreamingFileOptions<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        stream.validate()?;
        let file = OpenedStreamFile::open(&input_path, target.mime_type)?;
        if let Some(max) = stream.max_bytes {
            if file.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&file, stream.cancellation)?;
        if !matches!(
            plan.handler,
            "PDF"
                | "Office (DOCX/XLSX/PPTX/ODF)"
                | "MP4/MOV"
                | "PNG"
                | "JPEG"
                | "MP3"
                | "FLAC"
                | "WAV"
                | "Fallback (Universal Trailer)"
        ) {
            return Err(SignatureClientError::Invalid(
                "Embedded streaming verification is not available for this specialised container"
                    .into(),
            ));
        }
        let Some(envelope) = parse_plan_envelope(&plan)? else {
            let result = invalid_result("No embedded signature found");
            return Ok(self.finish_file_verify(result, false, false, false, source));
        };
        validate_envelope_commitments(&envelope)?;
        let current_hash = bytes_to_base64(&hash_reader_for_plan(&file, &plan, stream, true)?);
        let resolved = self.resolve_signer_public_keys(target)?;
        let signer_id = target
            .expected_signer_id
            .or_else(|| resolved.as_ref().map(|keys| keys.signer_id.as_str()));
        let selected = select_signature_for_content(&envelope, &current_hash, signer_id);
        let Some(selected) = selected else {
            let result = invalid_result(
                "No embedded signature matches the current file contents and requested signer",
            );
            return Ok(self.finish_file_verify(result, false, envelope.is_sealed(), false, source));
        };
        let signature = MajikSignature::from_json(selected)?;
        let keys = match resolved {
            Some(keys) => keys,
            None => signature.extract_public_keys()?,
        };
        let mut reader = RewrittenFileReader::new(file.try_clone_file()?, &plan)?;
        let result = run_with_hash_options(stream, plan.canonical_len()?, true, |hash_options| {
            MajikSignature::verify_reader_with_options(
                &mut reader,
                &signature,
                &keys,
                target.now,
                hash_options,
            )
        })?;
        file.ensure_unchanged()?;
        let tsa = signature.has_tsa();
        Ok(self.finish_file_verify(result, tsa, envelope.is_sealed(), false, source))
    }
}

fn read_small_envelope(path: &Path) -> Result<Vec<u8>> {
    let path_metadata = fs::metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => io_file_error("fileNotFound", path, error),
        io::ErrorKind::PermissionDenied => io_file_error("fileUnreadable", path, error),
        _ => io_file_error("fileUnreadable", path, error),
    })?;
    if !path_metadata.is_file() {
        return Err(file_error(
            "fileNotAFile",
            format!("Not a regular envelope file: {}", path.display()),
        ));
    }
    let file = File::open(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => io_file_error("fileNotFound", path, error),
        io::ErrorKind::PermissionDenied => io_file_error("fileUnreadable", path, error),
        _ => io_file_error("fileUnreadable", path, error),
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| io_file_error("fileUnreadable", path, error))?;
    if !metadata.is_file() {
        return Err(file_error(
            "fileNotAFile",
            format!("Not a regular envelope file: {}", path.display()),
        ));
    }
    if metadata.len() == 0 {
        return Err(file_error(
            "fileEmpty",
            format!("The detached envelope is empty: {}", path.display()),
        ));
    }
    if metadata.len() > MAX_EMBEDDED_ENVELOPE_BYTES {
        return Err(file_error(
            "fileTooLarge",
            format!(
                "Detached envelope exceeds the {} MiB safety limit",
                MAX_EMBEDDED_ENVELOPE_BYTES / (1024 * 1024)
            ),
        ));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| {
        file_error(
            "fileTooLarge",
            "Detached envelope size cannot be represented on this platform",
        )
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(MAX_EMBEDDED_ENVELOPE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_file_error("fileUnreadable", path, error))?;
    if bytes.len() as u64 != metadata.len() {
        return Err(file_error(
            "fileChanged",
            "The detached envelope changed while being read.",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp4_rewrite_round_trips_only_the_signature_box() {
        let ftyp = build_mp4_box(*b"ftyp", b"isom0000").unwrap();
        let udta = build_mp4_box(*b"udta", b"other metadata").unwrap();
        let moov = build_mp4_box(*b"moov", &udta).unwrap();
        let mdat = build_mp4_box(*b"mdat", b"large-media-payload").unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&ftyp);
        bytes.extend_from_slice(&moov);
        bytes.extend_from_slice(&mdat);
        let (stripped, found) = strip_mp4_moov(&moov).unwrap();
        assert!(found.is_none());
        let signed = embed_mp4_moov(&stripped, "MJKSIG:CBOR:2:dGVzdA==").unwrap();
        let (clean_again, payload) = strip_mp4_moov(&signed).unwrap();
        assert_eq!(payload.as_deref(), Some("MJKSIG:CBOR:2:dGVzdA=="));
        assert_eq!(clean_again, stripped);
        assert_eq!(
            bytes.len() - moov.len() + signed.len(),
            ftyp.len() + signed.len() + mdat.len()
        );
    }

    #[test]
    fn unsigned_pdf_with_arbitrary_footer_is_not_misclassified_as_signed() {
        let path =
            std::env::temp_dir().join(format!("majik-stream-pdf-{}.pdf", uuid::Uuid::new_v4()));
        fs::write(&path, b"%PDF-1.7\nordinary pdf bytes\xff\xff\xff\xff").unwrap();
        let mut file = File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        assert!(read_pdf_signature(&mut file, len, &path).unwrap().is_none());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn universal_trailer_is_removed_for_detached_canonical_bytes() {
        let path =
            std::env::temp_dir().join(format!("majik-stream-trailer-{}.bin", uuid::Uuid::new_v4()));
        let payload = "MJKSIG:CBOR:2:dGVzdA==";
        let mut bytes = b"original document".to_vec();
        bytes.extend_from_slice(payload.as_bytes());
        bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&UNIVERSAL_TRAILER_MAGIC);
        fs::write(&path, &bytes).unwrap();
        let source = OpenedStreamFile::open(&path, None).unwrap();
        let plan = build_rewrite_plan(&source, None).unwrap();
        assert_eq!(plan.envelope_payload.as_deref(), Some(payload));
        let mut reader = RewrittenFileReader::new(source.try_clone_file().unwrap(), &plan).unwrap();
        let mut canonical = Vec::new();
        reader.read_to_end(&mut canonical).unwrap();
        assert_eq!(canonical, b"original document");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn mp4_metadata_box_count_is_bounded() {
        let mut data = Vec::with_capacity((MAX_MP4_METADATA_BOXES + 1) * 8);
        for _ in 0..=MAX_MP4_METADATA_BOXES {
            data.extend_from_slice(&8u32.to_be_bytes());
            data.extend_from_slice(b"free");
        }
        assert!(parse_mp4_boxes(&data).is_err());
    }

    fn assert_media_round_trip(mime: &str, extension: &str, bytes: &[u8], handler: &str) {
        let source_path = std::env::temp_dir().join(format!(
            "majik-stream-media-source-{}.{extension}",
            uuid::Uuid::new_v4()
        ));
        let signed_path = std::env::temp_dir().join(format!(
            "majik-stream-media-signed-{}.{extension}",
            uuid::Uuid::new_v4()
        ));
        fs::write(&source_path, bytes).unwrap();

        let source = OpenedStreamFile::open(&source_path, Some(mime)).unwrap();
        let plan = build_rewrite_plan(&source, None).unwrap();
        assert_eq!(plan.handler, handler);
        let payload = "MJKSIG:CBOR:2:dGVzdA==";
        let replacement = pdf_or_mp4_output_replacement(&plan, payload).unwrap();
        let original = fs::read(&source_path).unwrap();
        let mut signed = Vec::with_capacity(
            original.len() - (plan.replace_end - plan.replace_start) as usize
                + replacement.len()
                + plan.canonical_replacement.len(),
        );
        signed.extend_from_slice(&original[..plan.replace_start as usize]);
        signed.extend_from_slice(&replacement);
        signed.extend_from_slice(&original[plan.replace_end as usize..]);
        if handler == "WAV" {
            let riff_size = u32::try_from(signed.len() - 8).unwrap();
            signed[4..8].copy_from_slice(&riff_size.to_le_bytes());
        }
        fs::write(&signed_path, &signed).unwrap();

        let signed_source = OpenedStreamFile::open(&signed_path, Some(mime)).unwrap();
        let signed_plan = build_rewrite_plan(&signed_source, None).unwrap();
        assert_eq!(signed_plan.envelope_payload.as_deref(), Some(payload));
        let mut actual_reader =
            RewrittenFileReader::new(signed_source.try_clone_file().unwrap(), &signed_plan)
                .unwrap();
        let mut actual_canonical = Vec::new();
        actual_reader.read_to_end(&mut actual_canonical).unwrap();

        let mut expected_reader =
            RewrittenFileReader::new(source.try_clone_file().unwrap(), &plan).unwrap();
        let mut expected_canonical = Vec::new();
        expected_reader
            .read_to_end(&mut expected_canonical)
            .unwrap();
        assert_eq!(
            actual_canonical, expected_canonical,
            "{handler} canonical bytes changed"
        );

        let _ = fs::remove_file(source_path);
        let _ = fs::remove_file(signed_path);
    }

    #[test]
    fn common_image_and_audio_containers_round_trip_through_streaming_handlers() {
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&[0; 13]);
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&0u32.to_be_bytes());
        assert_media_round_trip("image/png", "png", &png, "PNG");

        assert_media_round_trip("image/jpeg", "jpg", &[0xff, 0xd8, 0xff, 0xd9], "JPEG");
        assert_media_round_trip(
            "audio/mpeg",
            "mp3",
            &[0xff, 0xfb, 0x90, 0x64, 0, 0, 0],
            "MP3",
        );

        let mut flac = b"fLaC".to_vec();
        flac.extend_from_slice(&[0x80, 0, 0, 0]);
        flac.extend_from_slice(&[0xff, 0xf8, 0x00, 0x00]);
        assert_media_round_trip("audio/flac", "flac", &flac, "FLAC");

        let mut wav = b"RIFF\0\0\0\0WAVE".to_vec();
        wav.extend_from_slice(b"fmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&[0; 16]);
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&4u32.to_le_bytes());
        wav.extend_from_slice(&[1, 2, 3, 4]);
        let riff_size = u32::try_from(wav.len() - 8).unwrap();
        wav[4..8].copy_from_slice(&riff_size.to_le_bytes());
        assert_media_round_trip("audio/wav", "wav", &wav, "WAV");
    }

    #[test]
    fn matroska_and_webm_use_the_streamed_universal_trailer() {
        for (mime, extension) in [("video/x-matroska", "mkv"), ("video/webm", "webm")] {
            let path = std::env::temp_dir().join(format!(
                "majik-stream-ebml-{}.{}",
                uuid::Uuid::new_v4(),
                extension
            ));
            fs::write(&path, b"\x1a\x45\xdf\xa3\x00\x00\x00\x00").unwrap();
            let source = OpenedStreamFile::open(&path, Some(mime)).unwrap();
            let plan = build_rewrite_plan(&source, None).unwrap();
            assert_eq!(plan.handler, "Fallback (Universal Trailer)");
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn mp4_layout_records_whether_moov_is_after_mdat() {
        let ftyp = build_mp4_box(*b"ftyp", b"isom0000").unwrap();
        let mdat = build_mp4_box(*b"mdat", b"media").unwrap();
        let moov = build_mp4_box(*b"moov", b"\0\0\0\0").unwrap();
        for (name, bytes, expected) in [
            (
                "after",
                [ftyp.clone(), mdat.clone(), moov.clone()].concat(),
                true,
            ),
            ("before", [ftyp, moov, mdat].concat(), false),
        ] {
            let path = std::env::temp_dir().join(format!(
                "majik-stream-mp4-{name}-{}.mp4",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, bytes).unwrap();
            let source = OpenedStreamFile::open(&path, Some("video/mp4")).unwrap();
            let plan = build_rewrite_plan(&source, None).unwrap();
            assert_eq!(plan.mp4_moov_after_mdat, expected);
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn output_writer_failure_never_publishes_a_partial_file() {
        let path = std::env::temp_dir().join(format!(
            "majik-stream-output-{}.mjksig",
            uuid::Uuid::new_v4()
        ));
        let result = write_atomic_with(&path, false, |file| {
            file.write_all(b"incomplete")
                .map_err(|error| file_error("fileWriteFailed", error.to_string()))?;
            Err(SignatureClientError::Invalid("simulated failure".into()))
        });
        assert!(result.is_err());
        assert!(!path.exists());
    }

    #[test]
    fn output_writer_overwrite_replaces_the_previous_file_completely() {
        let path = std::env::temp_dir().join(format!(
            "majik-stream-overwrite-{}.mjksig",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, b"previous content").unwrap();

        let result = write_atomic_with(&path, true, |file| {
            file.write_all(b"replacement content")
                .map_err(|error| file_error("fileWriteFailed", error.to_string()))?;
            Ok(b"replacement content".len() as u64)
        })
        .unwrap();

        assert_eq!(result.size_bytes, b"replacement content".len() as u64);
        assert_eq!(fs::read(&path).unwrap(), b"replacement content");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn configured_max_bytes_also_applies_to_revision_prior_files() {
        let path = std::env::temp_dir().join(format!(
            "majik-stream-prior-limit-{}.bin",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, b"prior file").unwrap();
        let source = OpenedStreamFile::open(&path, None).unwrap();
        let stream = StreamingFileOptions {
            max_bytes: Some(4),
            ..Default::default()
        };

        let result = validate_stream_input_size(&source, &stream);
        assert!(matches!(
            result,
            Err(SignatureClientError::FileInput {
                kind: "fileTooLarge",
                ..
            })
        ));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn prepares_multiple_canonical_streaming_batch_readers() {
        let first_path = std::env::temp_dir().join(format!(
            "majik-stream-batch-first-{}.bin",
            uuid::Uuid::new_v4()
        ));
        let second_path = std::env::temp_dir().join(format!(
            "majik-stream-batch-second-{}.bin",
            uuid::Uuid::new_v4()
        ));
        let first = b"first canonical stream input".to_vec();
        let second = b"second canonical stream input".to_vec();
        fs::write(&first_path, &first).unwrap();
        fs::write(&second_path, &second).unwrap();

        let inputs = vec![
            StreamingBatchPathInput {
                manifest_path: "docs/first.bin".into(),
                source_path: first_path.clone(),
                mime_type: Some("application/octet-stream".into()),
            },
            StreamingBatchPathInput {
                manifest_path: "docs/second.bin".into(),
                source_path: second_path.clone(),
                mime_type: Some("application/octet-stream".into()),
            },
        ];
        let mut prepared =
            prepare_streaming_batch(&inputs, &BatchStreamingFileOptions::default()).unwrap();

        assert_eq!(prepared.sources.len(), 2);
        assert_eq!(prepared.readers.len(), 2);
        assert_eq!(prepared.metadata[0].0, "docs/first.bin");
        assert_eq!(prepared.metadata[0].1, first.len() as u64);
        assert_eq!(prepared.metadata[1].0, "docs/second.bin");
        assert_eq!(prepared.metadata[1].1, second.len() as u64);

        let mut first_read = Vec::new();
        let mut second_read = Vec::new();
        prepared.readers[0].read_to_end(&mut first_read).unwrap();
        prepared.readers[1].read_to_end(&mut second_read).unwrap();
        assert_eq!(first_read, first);
        assert_eq!(second_read, second);
        ensure_streaming_batch_sources_unchanged(&prepared.sources).unwrap();

        let _ = fs::remove_file(first_path);
        let _ = fs::remove_file(second_path);
    }

    #[test]
    fn batch_chunk_size_matches_the_core_sixty_four_mib_limit() {
        let maximum = BatchStreamingFileOptions {
            chunk_size: 64 * 1024 * 1024,
            ..Default::default()
        };
        assert!(maximum.validate().is_ok());

        let too_large = BatchStreamingFileOptions {
            chunk_size: 64 * 1024 * 1024 + 1,
            ..Default::default()
        };
        assert!(too_large.validate().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ten_gib_sparse_file_is_opened_without_materializing_its_contents() {
        let path =
            std::env::temp_dir().join(format!("majik-stream-sparse-{}.bin", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(10 * 1024 * 1024 * 1024).unwrap();
        drop(file);
        let source = OpenedStreamFile::open(&path, None).unwrap();
        assert_eq!(source.length(), 10 * 1024 * 1024 * 1024);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rewritten_reader_replaces_a_range_without_buffering_the_file() {
        let path =
            std::env::temp_dir().join(format!("majik-stream-test-{}.bin", uuid::Uuid::new_v4()));
        fs::write(&path, b"prefixOLDsuffix").unwrap();
        let file = File::open(&path).unwrap();
        let plan = RewritePlan {
            source_len: 15,
            replace_start: 6,
            replace_end: 9,
            canonical_replacement: b"new".to_vec(),
            envelope_payload: None,
            handler: "test",
            mime_type: "application/octet-stream".to_string(),
            has_mp4_moov: false,
            mp4_moov_after_mdat: false,
            riff_size_patch: None,
            office_archive: None,
        };
        let mut reader = RewrittenFileReader::new(file, &plan).unwrap();
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"prefixnewsuffix");
        let _ = fs::remove_file(path);
    }
}

#[cfg(test)]
mod adaptive_buffer_tests {
    use super::*;

    #[test]
    fn allocates_streaming_buffers_fallibly_and_initializes_them() {
        let buffer = allocate_stream_buffer(64 * 1024).expect("small streaming buffer");
        assert_eq!(buffer.len(), 64 * 1024);
        assert!(buffer.iter().all(|byte| *byte == 0));
    }
}
