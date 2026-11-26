//! Disk-backed canonicalisation for OOXML and ODF ZIP containers.
//!
//! The core Office handler canonicalises an archive by inflating its entries, removing
//! majik-signature.json, then writing a deterministic stored ZIP with a fixed DOS timestamp.
//! This module stages entry contents and the central directory on disk. It never holds the
//! whole uncompressed archive in memory.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};

use zip::ZipArchive;

use super::{file_error, io_file_error, OpenedStreamFile, Result, RewritePlan, SignatureClientError};

const OFFICE_ENTRY: &str = "majik-signature.json";
const MAX_UNZIPPED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SIGNATURE_ENTRY_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ZIP_ENTRIES: usize = u16::MAX as usize;

const OFFICE_MIME_TYPES: &[&str] = &[
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
];
const MSIX_PACKAGE_ENTRIES: &[&str] = &["AppxManifest.xml", "AppxBlockMap.xml", "AppxSignature.p7x"];
const OOXML_ENTRIES: &[&str] = &["word/document.xml", "xl/workbook.xml", "ppt/presentation.xml"];
const ODF_MIME_TYPES: &[&str] = &[
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
];

struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn create() -> Result<Self> {
        let base = std::env::temp_dir();
        for _ in 0..8 {
            let path = base.join(format!("majik-office-stream-{}", uuid::Uuid::new_v4().simple()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_file_error("fileWriteFailed", &path, error)),
            }
        }
        Err(file_error(
            "fileWriteFailed",
            "Could not create a temporary workspace for Office streaming.",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct StagedEntry {
    name: String,
    path: PathBuf,
    size: u64,
    crc32: u32,
}

pub(super) struct OfficeArchivePlan {
    _workspace: TempWorkspace,
    canonical_path: PathBuf,
    canonical_size: u64,
    entries: Vec<StagedEntry>,
    envelope_payload: Option<String>,
}

impl OfficeArchivePlan {
    pub(super) fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    pub(super) fn canonical_size(&self) -> u64 {
        self.canonical_size
    }

    pub(super) fn envelope_payload(&self) -> Option<&str> {
        self.envelope_payload.as_deref()
    }
}

fn decode_name(raw: &[u8]) -> String {
    match std::str::from_utf8(raw) {
        Ok(name) => name.to_owned(),
        Err(_) => raw.iter().map(|byte| char::from(*byte)).collect(),
    }
}

fn is_msix_name(name: &str) -> bool {
    MSIX_PACKAGE_ENTRIES.contains(&name)
}

fn update_crc32(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

fn crc32(bytes: &[u8]) -> u32 {
    !update_crc32(!0u32, bytes)
}

fn dos_time_date() -> (u16, u16) {
    // MajikSignature core CANONICAL_MTIME = 1995-10-26T00:00:00Z.
    let (year, month, day, hour, minute, second) = (1995u16, 10u8, 26u8, 0u8, 0u8, 0u8);
    let time = ((hour as u16) << 11) | ((minute as u16) << 5) | ((second as u16) >> 1);
    let date = ((year - 1980) << 9) | ((month as u16) << 5) | day as u16;
    (time, date)
}

fn write_u16(output: &mut impl Write, value: u16) -> Result<()> {
    output.write_all(&value.to_le_bytes()).map_err(|error| {
        SignatureClientError::Invalid(format!("Could not write canonical Office ZIP: {error}"))
    })
}

fn write_u32(output: &mut impl Write, value: u32) -> Result<()> {
    output.write_all(&value.to_le_bytes()).map_err(|error| {
        SignatureClientError::Invalid(format!("Could not write canonical Office ZIP: {error}"))
    })
}

fn copy_staged_entry(source: &Path, output: &mut File, expected_size: u64) -> Result<()> {
    let mut input = File::open(source).map_err(|error| io_file_error("fileUnreadable", source, error))?;
    let copied = io::copy(&mut input, output)
        .map_err(|error| io_file_error("fileWriteFailed", source, error))?;
    if copied != expected_size {
        return Err(file_error(
            "fileChanged",
            format!(
                "A staged Office ZIP entry changed size while being written (expected {expected_size}, copied {copied})."
            ),
        ));
    }
    Ok(())
}

fn write_stored_archive(
    entries: &[StagedEntry],
    signature: Option<&[u8]>,
    output: &mut File,
    workspace: &TempWorkspace,
) -> Result<u64> {
    if entries.len() + usize::from(signature.is_some()) > MAX_ZIP_ENTRIES {
        return Err(file_error(
            "fileTooLarge",
            "Office ZIP has too many entries for the canonical non-ZIP64 representation.",
        ));
    }

    let central_path = workspace.path().join(format!(
        "central-directory-{}.bin",
        uuid::Uuid::new_v4().simple()
    ));
    let mut central = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&central_path)
        .map_err(|error| io_file_error("fileWriteFailed", &central_path, error))?;
    let (dos_time, dos_date) = dos_time_date();
    output
        .seek(SeekFrom::Start(0))
        .map_err(|error| io_file_error("fileWriteFailed", Path::new("<output>"), error))?;

    let mut output_position = 0u64;
    let mut central_size = 0u64;

    let mut write_entry = |name: &str, path: Option<&Path>, bytes: Option<&[u8]>, size: u64, crc: u32| -> Result<()> {
        let name_bytes = name.as_bytes();
        if name_bytes.len() > u16::MAX as usize {
            return Err(file_error("fileTooLarge", "Office ZIP entry name exceeds 65,535 bytes."));
        }
        let utf16_len = name.encode_utf16().count();
        let flags_hi: u8 = if name_bytes.len() != utf16_len { 8 } else { 0 };
        let local_offset = u32::try_from(output_position).map_err(|_| {
            file_error("fileTooLarge", "Canonical Office ZIP exceeds the 32-bit local-header offset limit.")
        })?;
        let size32 = u32::try_from(size).map_err(|_| {
            file_error("fileTooLarge", "An Office ZIP entry exceeds the 32-bit stored-size limit.")
        })?;

        write_u32(output, 0x0403_4b50)?;
        write_u16(output, 20)?;
        output.write_all(&[0, flags_hi]).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not write canonical Office ZIP: {error}"))
        })?;
        write_u16(output, 0)?;
        write_u16(output, dos_time)?;
        write_u16(output, dos_date)?;
        write_u32(output, crc)?;
        write_u32(output, size32)?;
        write_u32(output, size32)?;
        write_u16(output, name_bytes.len() as u16)?;
        write_u16(output, 0)?;
        output.write_all(name_bytes).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not write canonical Office ZIP: {error}"))
        })?;
        output_position = output_position
            .checked_add(30 + name_bytes.len() as u64)
            .ok_or_else(|| file_error("fileTooLarge", "Canonical Office ZIP size overflowed."))?;

        if let Some(path) = path {
            copy_staged_entry(path, output, size)?;
        } else if let Some(data) = bytes {
            output.write_all(data).map_err(|error| {
                SignatureClientError::Invalid(format!("Could not write canonical Office ZIP: {error}"))
            })?;
        }
        output_position = output_position
            .checked_add(size)
            .ok_or_else(|| file_error("fileTooLarge", "Canonical Office ZIP size overflowed."))?;

        write_u32(&mut central, 0x0201_4b50)?;
        central.write_all(&[20, 0]).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not write Office ZIP central directory: {error}"))
        })?;
        write_u16(&mut central, 20)?;
        central.write_all(&[0, flags_hi]).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not write Office ZIP central directory: {error}"))
        })?;
        write_u16(&mut central, 0)?;
        write_u16(&mut central, dos_time)?;
        write_u16(&mut central, dos_date)?;
        write_u32(&mut central, crc)?;
        write_u32(&mut central, size32)?;
        write_u32(&mut central, size32)?;
        write_u16(&mut central, name_bytes.len() as u16)?;
        write_u16(&mut central, 0)?;
        write_u16(&mut central, 0)?;
        write_u16(&mut central, 0)?;
        write_u16(&mut central, 0)?;
        write_u32(&mut central, 0)?;
        write_u32(&mut central, local_offset)?;
        central.write_all(name_bytes).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not write Office ZIP central directory: {error}"))
        })?;
        central_size = central_size
            .checked_add(46 + name_bytes.len() as u64)
            .ok_or_else(|| file_error("fileTooLarge", "Office ZIP central directory size overflowed."))?;
        if central_size > MAX_CENTRAL_DIRECTORY_BYTES {
            return Err(file_error(
                "fileTooLarge",
                "Office ZIP central directory exceeds the 32 MiB metadata safety limit.",
            ));
        }
        Ok(())
    };

    for entry in entries {
        write_entry(&entry.name, Some(&entry.path), None, entry.size, entry.crc32)?;
    }
    if let Some(signature) = signature {
        if signature.len() as u64 > MAX_SIGNATURE_ENTRY_BYTES {
            return Err(file_error(
                "fileTooLarge",
                "Majik Signature JSON entry exceeds the 8 MiB Office extraction limit.",
            ));
        }
        write_entry(
            OFFICE_ENTRY,
            None,
            Some(signature),
            signature.len() as u64,
            crc32(signature),
        )?;
    }
    drop(write_entry);

    if output_position > u32::MAX as u64 || central_size > u32::MAX as u64 {
        return Err(file_error(
            "fileTooLarge",
            "Canonical Office ZIP exceeds the classic ZIP 32-bit size limit.",
        ));
    }
    central.flush()
        .map_err(|error| io_file_error("fileWriteFailed", &central_path, error))?;
    central.seek(SeekFrom::Start(0))
        .map_err(|error| io_file_error("fileUnreadable", &central_path, error))?;
    let central_offset = output_position;
    let copied = io::copy(&mut central, output)
        .map_err(|error| io_file_error("fileWriteFailed", &central_path, error))?;
    if copied != central_size {
        return Err(file_error("fileWriteFailed", "Office ZIP central directory was truncated while copying."));
    }
    output_position = output_position
        .checked_add(copied)
        .ok_or_else(|| file_error("fileTooLarge", "Canonical Office ZIP size overflowed."))?;

    let count = u16::try_from(entries.len() + usize::from(signature.is_some())).map_err(|_| {
        file_error("fileTooLarge", "Office ZIP has too many entries for its end record.")
    })?;
    write_u32(output, 0x0605_4b50)?;
    write_u16(output, 0)?;
    write_u16(output, 0)?;
    write_u16(output, count)?;
    write_u16(output, count)?;
    write_u32(output, central_size as u32)?;
    write_u32(output, central_offset as u32)?;
    write_u16(output, 0)?;
    output_position = output_position
        .checked_add(22)
        .ok_or_else(|| file_error("fileTooLarge", "Canonical Office ZIP size overflowed."))?;
    Ok(output_position)
}

fn stage_archive(
    source: &OpenedStreamFile,
    workspace: &TempWorkspace,
) -> Result<(Vec<StagedEntry>, Option<String>)> {
    let mut archive = ZipArchive::new(source.try_clone_file()?).map_err(|error| {
        SignatureClientError::Invalid(format!("Invalid Office ZIP archive: {error}"))
    })?;
    if archive.len() > MAX_ZIP_ENTRIES {
        return Err(file_error("fileTooLarge", "Office ZIP has too many entries."));
    }

    let mut declared_total = 0u64;
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).map_err(|error| {
            SignatureClientError::Invalid(format!("Invalid Office ZIP directory: {error}"))
        })?;
        declared_total = declared_total.checked_add(entry.size()).ok_or_else(|| {
            file_error("fileTooLarge", "Office ZIP uncompressed size overflowed.")
        })?;
        if declared_total > MAX_UNZIPPED_BYTES {
            return Err(file_error(
                "fileTooLarge",
                "Office ZIP uncompressed content exceeds the core 512 MiB safety limit.",
            ));
        }
    }

    let mut entries: Vec<StagedEntry> = Vec::new();
    let mut positions: HashMap<String, usize> = HashMap::new();
    let mut signature_payload = None;
    let mut actual_total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];

    for index in 0..archive.len() {
        let (name, declared_size) = {
            let entry = archive.by_index_raw(index).map_err(|error| {
                SignatureClientError::Invalid(format!("Invalid Office ZIP directory: {error}"))
            })?;
            (decode_name(entry.name_raw()), entry.size())
        };
        if name == OFFICE_ENTRY {
            if declared_size <= MAX_SIGNATURE_ENTRY_BYTES {
                let mut entry = archive.by_index(index).map_err(|error| {
                    SignatureClientError::Invalid(format!("Could not read Office signature entry: {error}"))
                })?;
                let mut payload = Vec::with_capacity(declared_size as usize);
                entry.read_to_end(&mut payload).map_err(|error| {
                    SignatureClientError::Invalid(format!("Could not inflate Office signature entry: {error}"))
                })?;
                if payload.len() as u64 != declared_size {
                    return Err(file_error("fileInvalid", "Office signature entry size does not match its ZIP directory."));
                }
                signature_payload = Some(String::from_utf8_lossy(&payload).into_owned());
            }
            continue;
        }

        let staged_path = workspace.path().join(format!("entry-{index:05}.bin"));
        let mut staged = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_path)
            .map_err(|error| io_file_error("fileWriteFailed", &staged_path, error))?;
        let mut entry = archive.by_index(index).map_err(|error| {
            SignatureClientError::Invalid(format!("Could not open Office ZIP entry {name}: {error}"))
        })?;
        let mut size = 0u64;
        let mut crc_state = !0u32;
        loop {
            let count = entry.read(&mut buffer).map_err(|error| {
                SignatureClientError::Invalid(format!("Could not inflate Office ZIP entry {name}: {error}"))
            })?;
            if count == 0 {
                break;
            }
            size = size.checked_add(count as u64).ok_or_else(|| {
                file_error("fileTooLarge", "Office ZIP entry size overflowed.")
            })?;
            actual_total = actual_total.checked_add(count as u64).ok_or_else(|| {
                file_error("fileTooLarge", "Office ZIP uncompressed size overflowed.")
            })?;
            if actual_total > MAX_UNZIPPED_BYTES || size > declared_size {
                return Err(file_error(
                    "fileTooLarge",
                    "Inflated Office ZIP content exceeded its declared or configured size limit.",
                ));
            }
            crc_state = update_crc32(crc_state, &buffer[..count]);
            staged.write_all(&buffer[..count]).map_err(|error| {
                io_file_error("fileWriteFailed", &staged_path, error)
            })?;
        }
        if size != declared_size {
            return Err(file_error(
                "fileInvalid",
                format!("Office ZIP entry {name} did not inflate to its declared size."),
            ));
        }
        staged.sync_all().map_err(|error| io_file_error("fileWriteFailed", &staged_path, error))?;
        drop(staged);

        let staged_entry = StagedEntry {
            name: name.clone(),
            path: staged_path,
            size,
            crc32: !crc_state,
        };
        if let Some(position) = positions.get(&name).copied() {
            entries[position] = staged_entry;
        } else {
            positions.insert(name, entries.len());
            entries.push(staged_entry);
        }
    }
    Ok((entries, signature_payload))
}

/// Returns true only for containers the core OfficeHandler recognises. Malformed PK archives
/// return an error rather than being silently reinterpreted as opaque bytes.
pub(super) fn detect_office_input(source: &OpenedStreamFile, head: &[u8]) -> Result<bool> {
    let mime = source.mime_type().unwrap_or_default();
    if OFFICE_MIME_TYPES.contains(&mime) {
        return Ok(true);
    }
    if !head.starts_with(b"PK\x03\x04") {
        return Ok(false);
    }

    let mut archive = ZipArchive::new(source.try_clone_file()?).map_err(|error| {
        SignatureClientError::Invalid(format!("Invalid ZIP-based file: {error}"))
    })?;
    let mut odf_mimetype = None;
    let mut has_msix_marker = false;
    let mut has_ooxml_marker = false;
    for index in 0..archive.len() {
        let (name, size) = {
            let entry = archive.by_index_raw(index).map_err(|error| {
                SignatureClientError::Invalid(format!("Invalid ZIP directory: {error}"))
            })?;
            (decode_name(entry.name_raw()), entry.size())
        };
        has_msix_marker |= is_msix_name(&name);
        has_ooxml_marker |= OOXML_ENTRIES.contains(&name.as_str());
        if name == "mimetype" && size <= MAX_SIGNATURE_ENTRY_BYTES {
            let mut entry = archive.by_index(index).map_err(|error| {
                SignatureClientError::Invalid(format!("Could not read ODF mimetype entry: {error}"))
            })?;
            let mut bytes = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut bytes).map_err(|error| {
                SignatureClientError::Invalid(format!("Could not inflate ODF mimetype entry: {error}"))
            })?;
            odf_mimetype = Some(String::from_utf8_lossy(&bytes).trim().to_owned());
        }
    }
    if has_msix_marker {
        return Ok(false);
    }
    if has_ooxml_marker {
        return Ok(true);
    }
    Ok(odf_mimetype
        .as_deref()
        .map(|mime| ODF_MIME_TYPES.contains(&mime))
        .unwrap_or(false))
}

/// Build the canonical unsigned archive on disk and retain only its staged entries and metadata.
pub(super) fn build_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    let workspace = TempWorkspace::create()?;
    let (entries, envelope_payload) = stage_archive(source, &workspace)?;
    let canonical_path = workspace.path().join("canonical-unsigned.zip");
    let mut canonical = OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .open(&canonical_path)
        .map_err(|error| io_file_error("fileWriteFailed", &canonical_path, error))?;
    let canonical_size = write_stored_archive(&entries, None, &mut canonical, &workspace)?;
    canonical.sync_all().map_err(|error| io_file_error("fileWriteFailed", &canonical_path, error))?;

    let archive = OfficeArchivePlan {
        _workspace: workspace,
        canonical_path,
        canonical_size,
        entries,
        envelope_payload,
    };
    let source_len = source.length();
    Ok(RewritePlan {
        source_len,
        replace_start: 0,
        replace_end: source_len,
        canonical_replacement: Vec::new(),
        envelope_payload: archive.envelope_payload().map(str::to_owned),
        handler: "Office (DOCX/XLSX/PPTX/ODF)",
        mime_type: source
            .mime_type()
            .unwrap_or("application/zip")
            .to_owned(),
        has_mp4_moov: false,
        mp4_moov_after_mdat: false,
        riff_size_patch: None,
        office_archive: Some(archive),
    })
}

/// Write a signed canonical archive. The Majik entry is appended last, matching ZipEntries.set().
pub(super) fn write_signed_archive(
    plan: &OfficeArchivePlan,
    signature_payload: &str,
    output: &mut File,
) -> Result<u64> {
    if signature_payload.len() as u64 > MAX_SIGNATURE_ENTRY_BYTES {
        return Err(file_error(
            "fileTooLarge",
            "Majik Signature JSON entry exceeds the 8 MiB Office extraction limit.",
        ));
    }
    write_stored_archive(
        &plan.entries,
        Some(signature_payload.as_bytes()),
        output,
        &plan._workspace,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_office_zip_is_stored_and_deterministic() {
        let workspace = TempWorkspace::create().unwrap();
        let entry_path = workspace.path().join("word-document.xml");
        fs::write(&entry_path, b"<document/>").unwrap();
        let entries = vec![StagedEntry {
            name: "word/document.xml".into(),
            path: entry_path,
            size: 11,
            crc32: crc32(b"<document/>"),
        }];
        let mut first = File::create(workspace.path().join("first.zip")).unwrap();
        let first_len = write_stored_archive(&entries, None, &mut first, &workspace).unwrap();
        first.sync_all().unwrap();
        let mut second = File::create(workspace.path().join("second.zip")).unwrap();
        let second_len = write_stored_archive(&entries, None, &mut second, &workspace).unwrap();
        second.sync_all().unwrap();
        let first_bytes = fs::read(workspace.path().join("first.zip")).unwrap();
        let second_bytes = fs::read(workspace.path().join("second.zip")).unwrap();
        assert_eq!(first_len, second_len);
        assert_eq!(first_bytes, second_bytes);
    }

    #[test]
    fn office_streaming_canonical_archive_matches_the_core_handler() {
        use super::super::MajikSignature;

        let workspace = TempWorkspace::create().unwrap();
        let mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
        let mut make_entry = |name: &str, bytes: &[u8], index: usize| {
            let path = workspace.path().join(format!("input-entry-{index}.bin"));
            fs::write(&path, bytes).unwrap();
            StagedEntry {
                name: name.to_owned(),
                path,
                size: bytes.len() as u64,
                crc32: crc32(bytes),
            }
        };

        // Include a duplicate to assert ZipEntries.set() semantics (replace in its original slot),
        // and a prior signature which must be stripped before calculating the canonical digest.
        let entries = vec![
            make_entry("[Content_Types].xml", b"<types/>", 0),
            make_entry("word/document.xml", b"<old/>", 1),
            make_entry("word/document.xml", b"<document/>", 2),
            make_entry("docProps/core.xml", b"<core/>", 3),
        ];
        let source_path = workspace.path().join("sample.docx");
        let mut source_zip = File::create(&source_path).unwrap();
        write_stored_archive(&entries, Some(b"old-signature"), &mut source_zip, &workspace).unwrap();
        source_zip.sync_all().unwrap();
        drop(source_zip);

        let source_bytes = fs::read(&source_path).unwrap();
        let source = OpenedStreamFile::open(&source_path, Some(mime)).unwrap();
        let plan = build_plan(&source).unwrap();
        assert_eq!(plan.envelope_payload(), Some("old-signature"));
        let canonical = fs::read(plan.canonical_path()).unwrap();
        let expected = MajikSignature::strip_from(&source_bytes, Some(mime)).unwrap();
        assert_eq!(canonical, expected);

        let signed_path = workspace.path().join("signed.docx");
        let mut signed_zip = File::create(&signed_path).unwrap();
        write_signed_archive(plan.office_archive.as_ref().unwrap(), "new-signature", &mut signed_zip).unwrap();
        signed_zip.sync_all().unwrap();
        drop(signed_zip);

        let signed_bytes = fs::read(&signed_path).unwrap();
        let stripped = MajikSignature::strip_from(&signed_bytes, Some(mime)).unwrap();
        assert_eq!(stripped, expected);

        let signed_source = OpenedStreamFile::open(&signed_path, Some(mime)).unwrap();
        let signed_plan = build_plan(&signed_source).unwrap();
        assert_eq!(signed_plan.envelope_payload(), Some("new-signature"));
        assert_eq!(fs::read(signed_plan.canonical_path()).unwrap(), expected);
    }
}
