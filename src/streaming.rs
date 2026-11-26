//! Path-backed, bounded-memory file operations.
//!
//! These APIs are intentionally separate from the legacy `FileInput::load()` path, which
//! materialises inputs into `Vec<u8>` and keeps its existing 1 GiB safety ceiling. Streaming
//! operations accept native paths, use fixed-size buffers, and never return the source file as
//! base64. Container rewriting is currently implemented for PDF and ISO-BMFF (MP4/MOV): only
//! the small container metadata is held in memory; media payloads are copied unchanged.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use jiff::Timestamp;
use majik_signature::{
    bytes_to_base64, parse_embedded_envelope, serialize_embedded_envelope, EnvelopeInput,
    FileVersion, MajikSignature, MajikSignatureEnvelope, SignOptions, StreamingHashOptions,
    StreamingHashProgress,
};
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
const MAX_CHUNK_SIZE: usize = 8 * 1024 * 1024;
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
                                Err(restore_error) => Err(io::Error::new(
                                    io::ErrorKind::Other,
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
}

impl RewritePlan {
    fn canonical_len(&self) -> Result<u64> {
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
    position: u64,
    virtual_len: u64,
}

impl RewrittenFileReader {
    fn new(file: File, plan: &RewritePlan) -> Result<Self> {
        let virtual_len = plan.canonical_len()?;
        Ok(Self {
            file,
            source_len: plan.source_len,
            replace_start: plan.replace_start,
            replace_end: plan.replace_end,
            replacement: plan.canonical_replacement.clone(),
            position: 0,
            virtual_len,
        })
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
) -> Result<u64> {
    file.seek(SeekFrom::Start(start)).map_err(|error| {
        file_error(
            "fileUnreadable",
            format!("Could not seek source file: {error}"),
        )
    })?;
    let mut remaining = length;
    let mut buffer = vec![0u8; options.chunk_size];
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
    })
}

fn detect_stream_format(source: &OpenedStreamFile) -> Result<&'static str> {
    let mut file = source.try_clone_file()?;
    let head_len = usize::try_from(source.length().min(12)).unwrap_or(12);
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
    // These formats have specialised in-memory handlers in `majik-signature`. Treating an
    // already-signed instance as opaque bytes would change canonical hashing semantics.
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
                | "image/png"
                | "image/jpeg"
                | "image/jpg"
                | "audio/flac"
                | "audio/x-flac"
                | "audio/mpeg"
                | "audio/mp3"
                | "audio/wav"
                | "audio/wave"
                | "audio/x-wav"
                | "video/x-matroska"
                | "audio/x-matroska"
                | "video/webm"
                | "audio/webm"
                | "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                | "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                | "application/vnd.openxmlformats-officedocument.presentationml.presentation"
                | "application/vnd.ms-word.document.macroEnabled.12"
                | "application/vnd.ms-excel.sheet.macroEnabled.12"
                | "application/vnd.ms-powerpoint.presentation.macroEnabled.12"
                | "application/vnd.oasis.opendocument.text"
                | "application/vnd.oasis.opendocument.spreadsheet"
                | "application/vnd.oasis.opendocument.presentation"
        );
    let specialised_magic = head.starts_with(b"\x89PNG\r\n\x1a\n")
        || head.starts_with(&[0xff, 0xd8, 0xff])
        || head.len() >= 2 && head[0] == 0xff && (head[1] & 0xe0) == 0xe0
        || head.starts_with(b"fLaC")
        || head.starts_with(b"ID3")
        || head.starts_with(b"OggS")
        || head.starts_with(b"RIFF") && head.len() >= 12 && &head[8..12] == b"WAVE"
        || head.starts_with(b"\x1aE\xdf\xa3")
        || head.starts_with(b"PK\x03\x04");
    if specialised_mime || specialised_magic {
        return Err(SignatureClientError::Invalid(format!(
            "Streaming operations do not yet support this specialised container handler (MIME: {}). Use the legacy in-memory API until the format has a streaming handler, or explicitly select application/octet-stream when signing literal raw bytes from a known-clean file.",
            if mime.is_empty() { "unknown" } else { mime }
        )));
    }
    Ok("raw")
}

fn build_rewrite_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    match detect_stream_format(source)? {
        "pdf" => parse_pdf_plan(source),
        "mp4" => parse_mp4_plan(source),
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
            })
        }
    }
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
        _ => Err(SignatureClientError::Invalid(
            "Embedded streaming is currently supported for PDF and MP4/MOV containers only".into(),
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
    /// Sign a native path into a detached `.mjksig` sidecar. Existing embedded PDF/MP4 signatures
    /// are removed from the logical input before hashing, matching the format handlers. Existing
    /// `prior_file` revision flows remain on the legacy in-memory API until the core revision API
    /// accepts path/reader inputs.
    pub fn sign_file_detached_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        envelope_output_path: impl AsRef<Path>,
        options: &SignDetachedFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingDetachedSignResult> {
        if options.prior_file.is_some() {
            return Err(SignatureClientError::Invalid(
                "Streaming detached revisions are not available yet: priorFile requires the legacy revision verifier. Use a new detached signature or the in-memory API for this revision.".into(),
            ));
        }
        stream.validate()?;
        let source = OpenedStreamFile::open(&input_path, options.mime_type.as_deref())?;
        ensure_distinct_paths(source.path(), envelope_output_path.as_ref())?;
        if let Some(max) = stream.max_bytes {
            if source.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&source)?;
        let envelope = match options.existing_envelope.clone() {
            Some(input) => MajikSignatureEnvelope::from_input(input)?,
            None => parse_plan_envelope(&plan)?.unwrap_or_else(MajikSignatureEnvelope::empty),
        };
        validate_envelope_commitments(&envelope)?;
        let total = plan.canonical_len()?;
        let sign_result = self.with_signing_key(context.account_id.as_deref(), false, |key| {
            envelope.assert_can_sign(key)?;
            let allowlist_hash =
                envelope.resolve_allowlist_hash_for(key, options.expected_signers.as_deref());
            let sign_options = SignOptions {
                content_type: options.content_type.clone(),
                timestamp: options.timestamp.clone(),
                valid_until: options.valid_until.clone(),
                allowlist_hash,
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
            let next = with_allowlist.with_signature(signature.to_json())?;

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
        let plan = build_rewrite_plan(&file)?;
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

    /// Sign and embed a signature in a PDF or MP4/MOV path without materialising the media file.
    /// PDF uses its append-only signature block; MP4/MOV rewrites only `moov/udta/majk`, leaving
    /// large `mdat` payloads streamed and byte-identical. MP4/MOV embedding requires `mdat` to
    /// precede a final `moov` box so absolute media chunk offsets remain valid. Other formats remain on the
    /// legacy in-memory handler until their container writers expose reader/writer APIs.
    pub fn sign_file_embedded_stream(
        &mut self,
        input_path: impl AsRef<Path>,
        output_path: impl AsRef<Path>,
        options: &SignFileOptions,
        context: &OpContext,
        stream: &mut StreamingFileOptions<'_>,
        overwrite: bool,
    ) -> Result<StreamingEmbeddedSignResult> {
        if options.prior_signed_file.is_some() {
            return Err(SignatureClientError::Invalid(
                "Streaming embedded revisions with priorSignedFile are not available yet. Use the legacy in-memory API for this revision.".into(),
            ));
        }
        stream.validate()?;
        let mut source = OpenedStreamFile::open(&input_path, options.mime_type.as_deref())?;
        ensure_distinct_paths(source.path(), output_path.as_ref())?;
        if let Some(max) = stream.max_bytes {
            if source.length() > max {
                return Err(file_error(
                    "fileTooLarge",
                    format!("Input exceeds the configured streaming limit of {max} bytes"),
                ));
            }
        }
        let plan = build_rewrite_plan(&source)?;
        if plan.handler != "PDF" && plan.handler != "MP4/MOV" {
            return Err(SignatureClientError::Invalid(
                "Large-file embedded signing is currently supported for PDF and MP4/MOV. Use detached streaming signing for this format; other embedded handlers are being migrated to bounded-memory readers.".into(),
            ));
        }
        if plan.has_mp4_moov && !plan.mp4_moov_after_mdat {
            return Err(SignatureClientError::Invalid(
                "This MP4/MOV places its moov metadata before media data. Expanding moov can shift absolute media chunk offsets; use detached streaming signing or a file with moov after mdat until chunk-offset rebasing is available.".into(),
            ));
        }
        let envelope = parse_plan_envelope(&plan)?.unwrap_or_else(MajikSignatureEnvelope::empty);
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
        let replacement = pdf_or_mp4_output_replacement(&plan, &embedded_payload)?;
        let output = write_atomic_with(output_path, overwrite, |destination| {
            let input = source.file_mut();
            write_rewritten_and_check(
                input,
                destination,
                &plan,
                &replacement,
                signature.content_hash(),
                stream,
            )
        })?;
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

    /// Verify an embedded PDF or MP4/MOV path by reading its canonical unsigned representation.
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
        let plan = build_rewrite_plan(&file)?;
        if plan.handler != "PDF" && plan.handler != "MP4/MOV" {
            return Err(SignatureClientError::Invalid(
                "Embedded streaming verification is currently supported for PDF and MP4/MOV only"
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
        let plan = build_rewrite_plan(&source).unwrap();
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

    #[test]
    fn specialised_image_handlers_are_not_silently_treated_as_raw() {
        let path =
            std::env::temp_dir().join(format!("majik-stream-png-{}.png", uuid::Uuid::new_v4()));
        fs::write(&path, b"\x89PNG\r\n\x1a\ncontent").unwrap();
        let source = OpenedStreamFile::open(&path, Some("image/png")).unwrap();
        assert!(detect_stream_format(&source).is_err());
        let _ = fs::remove_file(path);
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
            let plan = build_rewrite_plan(&source).unwrap();
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
        };
        let mut reader = RewrittenFileReader::new(file, &plan).unwrap();
        let mut result = Vec::new();
        reader.read_to_end(&mut result).unwrap();
        assert_eq!(result, b"prefixnewsuffix");
        let _ = fs::remove_file(path);
    }
}
