//! Bounded-memory parsers for Majik Signature's existing media metadata formats.
//! Payload data is never materialized: only bounded container metadata is read into memory.

use super::*;
use std::io::{Read, Seek, SeekFrom};

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const PNG_KEYWORD: &[u8] = b"majik-signature";
const JPEG_SOI: &[u8; 2] = b"\xff\xd8";
const JPEG_APP15: &[u8; 2] = b"\xff\xef";
const JPEG_MAJIK_IDENTIFIER: &[u8] = b"MAJIK\0";
const ID3_DESCRIPTION: &[u8] = b"MAJIK-SIGNATURE";
const FLAC_MAGIC: &[u8; 4] = b"fLaC";
const FLAC_APPLICATION_ID: &[u8; 4] = b"MAJK";
const MAX_MEDIA_METADATA_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MEDIA_CHUNKS: usize = 65_536;

fn read_at(source: &OpenedStreamFile, offset: u64, length: usize) -> Result<Vec<u8>> {
    let mut file = source.try_clone_file()?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|error| io_file_error("fileUnreadable", source.path(), error))?;
    let mut bytes = vec![0u8; length];
    file.read_exact(&mut bytes)
        .map_err(|error| io_file_error("fileUnreadable", source.path(), error))?;
    Ok(bytes)
}

fn make_plan(
    source: &OpenedStreamFile,
    start: u64,
    end: u64,
    canonical_replacement: Vec<u8>,
    envelope_payload: Option<String>,
    handler: &'static str,
    mime_type: &str,
) -> RewritePlan {
    RewritePlan {
        source_len: source.length(),
        replace_start: start,
        replace_end: end,
        canonical_replacement,
        envelope_payload,
        handler,
        mime_type: mime_type.to_owned(),
        has_mp4_moov: false,
        mp4_moov_after_mdat: false,
    }
}

pub(super) fn detect_format(source: &OpenedStreamFile, head: &[u8]) -> Option<&'static str> {
    let mime = source.mime_type().unwrap_or_default();
    if mime == "image/png" || head.starts_with(PNG_SIGNATURE) {
        return Some("png");
    }
    if matches!(mime, "image/jpeg" | "image/jpg") || head.starts_with(&[0xff, 0xd8, 0xff]) {
        return Some("jpeg");
    }
    if matches!(mime, "audio/mpeg" | "audio/mp3")
        || head.starts_with(b"ID3")
        || (head.len() >= 2 && head[0] == 0xff && (head[1] & 0xe0) == 0xe0)
    {
        return Some("mp3");
    }
    if matches!(mime, "audio/flac" | "audio/x-flac") || head.starts_with(FLAC_MAGIC) {
        return Some("flac");
    }
    if matches!(
        mime,
        "video/x-matroska" | "audio/x-matroska" | "video/webm" | "audio/webm"
    ) || head.starts_with(b"\x1aE\xdf\xa3")
    {
        return Some("mkv");
    }
    None
}

pub(super) fn build_plan(source: &OpenedStreamFile, format: &str) -> Result<RewritePlan> {
    match format {
        "png" => parse_png_plan(source),
        "jpeg" => parse_jpeg_plan(source),
        "mp3" => parse_mp3_plan(source),
        "flac" => parse_flac_plan(source),
        _ => Err(SignatureClientError::Invalid(format!(
            "No streaming media handler exists for {format}"
        ))),
    }
}

pub(super) fn output_replacement(plan: &RewritePlan, payload: &str) -> Result<Option<Vec<u8>>> {
    let output = match plan.handler {
        "PNG" => Some(build_png_signature_chunk(payload)?),
        "JPEG" => Some(build_jpeg_signature_segment(payload)?),
        "MP3" => Some(build_mp3_signature_tag(&plan.canonical_replacement, payload)?),
        "FLAC" => Some(build_flac_signature_metadata(&plan.canonical_replacement, payload)?),
        _ => None,
    };
    Ok(output)
}

// PNG: Majik's iTXt chunk is inserted immediately before IEND.
fn parse_png_itxt(data: &[u8]) -> Result<Option<String>> {
    let Some(keyword_end) = data.iter().position(|byte| *byte == 0) else {
        return Ok(None);
    };
    if &data[..keyword_end] != PNG_KEYWORD {
        return Ok(None);
    }

    let mut cursor = keyword_end + 1;
    if data.len() < cursor + 2 {
        return Err(SignatureClientError::Invalid("PNG Majik iTXt metadata is truncated".into()));
    }
    if data[cursor] != 0 || data[cursor + 1] != 0 {
        return Err(SignatureClientError::Invalid(
            "PNG Majik signature metadata must use uncompressed iTXt".into(),
        ));
    }
    cursor += 2;
    let language_end = data[cursor..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| cursor + index)
        .ok_or_else(|| SignatureClientError::Invalid("PNG iTXt language field is malformed".into()))?;
    cursor = language_end + 1;
    let translated_end = data[cursor..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| cursor + index)
        .ok_or_else(|| SignatureClientError::Invalid("PNG iTXt translated keyword is malformed".into()))?;
    cursor = translated_end + 1;
    let text = std::str::from_utf8(&data[cursor..])
        .map_err(|error| SignatureClientError::Invalid(format!("PNG signature payload is not UTF-8: {error}")))?;
    Ok(Some(text.to_owned()))
}

fn parse_png_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    if source.length() < 8 || read_at(source, 0, 8)?.as_slice() != PNG_SIGNATURE {
        return Err(SignatureClientError::Invalid("Invalid PNG signature".into()));
    }

    let mut offset = 8u64;
    let mut signature: Option<(u64, u64, String)> = None;
    let mut iend_offset = None;
    let mut chunks = 0usize;

    while offset < source.length() {
        chunks += 1;
        if chunks > MAX_MEDIA_CHUNKS {
            return Err(SignatureClientError::Invalid(format!(
                "PNG contains more than {MAX_MEDIA_CHUNKS} chunks"
            )));
        }
        if offset.checked_add(12).map(|end| end > source.length()).unwrap_or(true) {
            return Err(SignatureClientError::Invalid("PNG chunk header is truncated".into()));
        }
        let header = read_at(source, offset, 8)?;
        let data_len = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as u64;
        let kind = &header[4..8];
        let end = offset
            .checked_add(12)
            .and_then(|value| value.checked_add(data_len))
            .ok_or_else(|| SignatureClientError::Invalid("PNG chunk size overflowed".into()))?;
        if end > source.length() {
            return Err(SignatureClientError::Invalid("PNG chunk extends beyond the source file".into()));
        }

        if kind == b"iTXt" && data_len >= (PNG_KEYWORD.len() + 5) as u64 {
            let probe_len = usize::try_from(data_len.min((PNG_KEYWORD.len() + 8) as u64))
                .unwrap_or(PNG_KEYWORD.len() + 8);
            let probe = read_at(source, offset + 8, probe_len)?;
            if probe.starts_with(PNG_KEYWORD) && probe.get(PNG_KEYWORD.len()) == Some(&0) {
                if data_len > MAX_EMBEDDED_ENVELOPE_BYTES {
                    return Err(file_error("fileTooLarge", "PNG signature metadata exceeds 16 MiB"));
                }
                let data = read_at(
                    source,
                    offset + 8,
                    usize::try_from(data_len)
                        .map_err(|_| file_error("fileTooLarge", "PNG metadata length is unsupported"))?,
                )?;
                if let Some(payload) = parse_png_itxt(&data)? {
                    if signature.is_some() {
                        return Err(SignatureClientError::Invalid(
                            "PNG contains multiple Majik signature chunks".into(),
                        ));
                    }
                    signature = Some((offset, end, payload));
                }
            }
        }

        if kind == b"IEND" {
            if data_len != 0 {
                return Err(SignatureClientError::Invalid("PNG IEND chunk must be empty".into()));
            }
            iend_offset = Some(offset);
            break;
        }
        offset = end;
    }

    let iend = iend_offset
        .ok_or_else(|| SignatureClientError::Invalid("PNG is missing its IEND chunk".into()))?;
    let (start, end, payload) = match signature {
        Some((start, end, payload)) => {
            if end != iend {
                return Err(SignatureClientError::Invalid(
                    "Existing PNG signature is not immediately before IEND; refusing non-canonical rewrite".into(),
                ));
            }
            (start, end, Some(payload))
        }
        None => (iend, iend, None),
    };
    Ok(make_plan(source, start, end, Vec::new(), payload, "PNG", "image/png"))
}

fn build_png_signature_chunk(payload: &str) -> Result<Vec<u8>> {
    let mut data = Vec::with_capacity(PNG_KEYWORD.len() + payload.len() + 5);
    data.extend_from_slice(PNG_KEYWORD);
    data.extend_from_slice(&[0, 0, 0, 0, 0]);
    data.extend_from_slice(payload.as_bytes());
    let data_len = u32::try_from(data.len())
        .map_err(|_| SignatureClientError::Invalid("PNG iTXt chunk exceeds its 32-bit length field".into()))?;

    let mut crc_input = Vec::with_capacity(4 + data.len());
    crc_input.extend_from_slice(b"iTXt");
    crc_input.extend_from_slice(&data);
    let crc = crc32(&crc_input);

    let mut chunk = Vec::with_capacity(12 + data.len());
    chunk.extend_from_slice(&data_len.to_be_bytes());
    chunk.extend_from_slice(b"iTXt");
    chunk.extend_from_slice(&data);
    chunk.extend_from_slice(&crc.to_be_bytes());
    Ok(chunk)
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

// JPEG: Majik's APP15 segment is placed directly after SOI.
fn parse_jpeg_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    if source.length() < 3 || read_at(source, 0, 2)?.as_slice() != JPEG_SOI {
        return Err(SignatureClientError::Invalid("Invalid JPEG SOI marker".into()));
    }
    let mut offset = 2u64;
    let mut signature: Option<(u64, u64, String)> = None;

    while offset.checked_add(2).map(|end| end <= source.length()).unwrap_or(false) {
        let marker_bytes = read_at(source, offset, 2)?;
        if marker_bytes[0] != 0xff {
            break;
        }
        let marker = marker_bytes[1];
        if marker == 0xd9 {
            break;
        }
        if marker == 0x01 || (0xd0..=0xd8).contains(&marker) {
            offset += 2;
            continue;
        }
        if offset.checked_add(4).map(|end| end > source.length()).unwrap_or(true) {
            return Err(SignatureClientError::Invalid("JPEG segment header is truncated".into()));
        }
        let header = read_at(source, offset, 4)?;
        let segment_len = u16::from_be_bytes([header[2], header[3]]) as u64;
        if segment_len < 2 {
            return Err(SignatureClientError::Invalid("JPEG segment length is invalid".into()));
        }
        let end = offset
            .checked_add(2)
            .and_then(|value| value.checked_add(segment_len))
            .ok_or_else(|| SignatureClientError::Invalid("JPEG segment size overflowed".into()))?;
        if end > source.length() {
            return Err(SignatureClientError::Invalid("JPEG segment extends beyond the file".into()));
        }

        if marker == 0xef && segment_len >= (2 + JPEG_MAJIK_IDENTIFIER.len()) as u64 {
            let data_len = usize::try_from(segment_len - 2)
                .map_err(|_| SignatureClientError::Invalid("JPEG APP15 metadata is too large".into()))?;
            let data = read_at(source, offset + 4, data_len)?;
            if data.starts_with(JPEG_MAJIK_IDENTIFIER) {
                if offset != 2 {
                    return Err(SignatureClientError::Invalid(
                        "Existing JPEG Majik APP15 segment is not immediately after SOI".into(),
                    ));
                }
                if signature.is_some() {
                    return Err(SignatureClientError::Invalid("JPEG contains duplicate Majik APP15 segments".into()));
                }
                let payload = std::str::from_utf8(&data[JPEG_MAJIK_IDENTIFIER.len()..])
                    .map_err(|error| SignatureClientError::Invalid(format!("JPEG signature payload is not UTF-8: {error}")))?
                    .to_owned();
                signature = Some((offset, end, payload));
            }
        }

        offset = end;
        if marker == 0xda {
            break;
        }
    }

    let (start, end, payload) = signature
        .map(|(start, end, payload)| (start, end, Some(payload)))
        .unwrap_or((2, 2, None));
    Ok(make_plan(source, start, end, Vec::new(), payload, "JPEG", "image/jpeg"))
}

fn build_jpeg_signature_segment(payload: &str) -> Result<Vec<u8>> {
    let data_len = JPEG_MAJIK_IDENTIFIER
        .len()
        .checked_add(payload.len())
        .ok_or_else(|| SignatureClientError::Invalid("JPEG signature size overflowed".into()))?;
    let segment_len = u16::try_from(data_len + 2).map_err(|_| {
        SignatureClientError::Invalid("JPEG APP15 signature exceeds the 65,535-byte segment limit".into())
    })?;
    let mut output = Vec::with_capacity(4 + data_len);
    output.extend_from_slice(JPEG_APP15);
    output.extend_from_slice(&segment_len.to_be_bytes());
    output.extend_from_slice(JPEG_MAJIK_IDENTIFIER);
    output.extend_from_slice(payload.as_bytes());
    Ok(output)
}

// MP3: only the bounded ID3v2 tag is parsed; MPEG audio frames are streamed unchanged.
fn read_syncsafe(bytes: &[u8]) -> Result<usize> {
    if bytes.len() != 4 || bytes.iter().any(|byte| byte & 0x80 != 0) {
        return Err(SignatureClientError::Invalid("Invalid ID3 syncsafe integer".into()));
    }
    Ok(((bytes[0] as usize) << 21)
        | ((bytes[1] as usize) << 14)
        | ((bytes[2] as usize) << 7)
        | bytes[3] as usize)
}

fn write_syncsafe(value: usize) -> Result<[u8; 4]> {
    if value > 0x0fff_ffff {
        return Err(SignatureClientError::Invalid("ID3 tag exceeds its 28-bit size limit".into()));
    }
    Ok([
        ((value >> 21) & 0x7f) as u8,
        ((value >> 14) & 0x7f) as u8,
        ((value >> 7) & 0x7f) as u8,
        (value & 0x7f) as u8,
    ])
}

fn build_id3_tag(frames: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(10 + frames.len());
    output.extend_from_slice(b"ID3");
    output.extend_from_slice(&[3, 0, 0]);
    output.extend_from_slice(&write_syncsafe(frames.len())?);
    output.extend_from_slice(frames);
    Ok(output)
}

fn read_txxx_signature(data: &[u8]) -> Option<Result<String>> {
    if data.first() != Some(&3) {
        return None;
    }
    let separator = data[1..].iter().position(|byte| *byte == 0).map(|i| i + 1)?;
    if &data[1..separator] != ID3_DESCRIPTION {
        return None;
    }
    Some(
        String::from_utf8(data[separator + 1..].to_vec())
            .map_err(|error| SignatureClientError::Invalid(format!("MP3 signature frame is not UTF-8: {error}"))),
    )
}

fn parse_mp3_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    let has_id3 = source.length() >= 10 && read_at(source, 0, 3)?.as_slice() == b"ID3";
    if !has_id3 {
        return Ok(make_plan(source, 0, 0, Vec::new(), None, "MP3", "audio/mpeg"));
    }

    let header = read_at(source, 0, 10)?;
    let major_version = header[3];
    if major_version != 3 && major_version != 4 {
        return Err(SignatureClientError::Invalid(format!(
            "ID3v2.{major_version} is not supported by the streaming MP3 handler"
        )));
    }
    if header[5] != 0 {
        return Err(SignatureClientError::Invalid(
            "ID3 tags with extended headers, unsynchronisation, compression, or experimental flags are not supported by streaming signing".into(),
        ));
    }
    let tag_size = read_syncsafe(&header[6..10])?;
    if tag_size as u64 > MAX_MEDIA_METADATA_BYTES {
        return Err(file_error("fileTooLarge", "MP3 ID3 metadata exceeds the 32 MiB limit"));
    }
    let tag_end = 10u64
        .checked_add(tag_size as u64)
        .ok_or_else(|| SignatureClientError::Invalid("ID3 tag size overflowed".into()))?;
    if tag_end > source.length() {
        return Err(SignatureClientError::Invalid("ID3 tag extends beyond the MP3 file".into()));
    }
    let tag = read_at(
        source,
        0,
        usize::try_from(tag_end).map_err(|_| file_error("fileTooLarge", "ID3 tag size is unsupported"))?,
    )?;

    let mut offset = 10usize;
    let mut kept_frames = Vec::new();
    let mut signature_payload = None;

    // Match the core handler's current frame walk and v2.3 canonical tag output.
    while offset < tag_size && offset < tag.len() {
        if offset + 10 > tag.len() || tag[offset] == 0 {
            break;
        }
        let frame_id = &tag[offset..offset + 4];
        let frame_size = if major_version == 4 {
            read_syncsafe(&tag[offset + 4..offset + 8])?
        } else {
            let size = u32::from_be_bytes([
                tag[offset + 4], tag[offset + 5], tag[offset + 6], tag[offset + 7],
            ]);
            if size >= 0x8000_0000 {
                break;
            }
            size as usize
        };
        let frame_end = offset
            .checked_add(10)
            .and_then(|value| value.checked_add(frame_size))
            .ok_or_else(|| SignatureClientError::Invalid("ID3 frame size overflowed".into()))?;
        if frame_end > tag.len() {
            return Err(SignatureClientError::Invalid("ID3 frame extends beyond the declared tag".into()));
        }

        let frame_data = &tag[offset + 10..frame_end];
        let is_majik = if frame_id == b"TXXX" {
            read_txxx_signature(frame_data)
        } else {
            None
        };
        if let Some(parsed) = is_majik {
            if signature_payload.is_some() {
                return Err(SignatureClientError::Invalid("MP3 contains duplicate Majik TXXX frames".into()));
            }
            signature_payload = Some(parsed?);
        } else {
            kept_frames.extend_from_slice(&tag[offset..frame_end]);
        }
        offset = frame_end;
    }

    let canonical_prefix = if kept_frames.is_empty() {
        Vec::new()
    } else {
        build_id3_tag(&kept_frames)?
    };
    Ok(make_plan(
        source,
        0,
        tag_end,
        canonical_prefix,
        signature_payload,
        "MP3",
        "audio/mpeg",
    ))
}

fn build_mp3_signature_tag(canonical_prefix: &[u8], payload: &str) -> Result<Vec<u8>> {
    let mut frames = Vec::new();
    if !canonical_prefix.is_empty() {
        if canonical_prefix.len() < 10 || &canonical_prefix[..3] != b"ID3" {
            return Err(SignatureClientError::Invalid("MP3 canonical ID3 prefix is malformed".into()));
        }
        frames.extend_from_slice(&canonical_prefix[10..]);
    }

    let mut frame_data = Vec::with_capacity(1 + ID3_DESCRIPTION.len() + 1 + payload.len());
    frame_data.push(3);
    frame_data.extend_from_slice(ID3_DESCRIPTION);
    frame_data.push(0);
    frame_data.extend_from_slice(payload.as_bytes());

    let frame_size = u32::try_from(frame_data.len())
        .map_err(|_| SignatureClientError::Invalid("MP3 TXXX frame is too large".into()))?;
    frames.extend_from_slice(b"TXXX");
    frames.extend_from_slice(&frame_size.to_be_bytes());
    frames.extend_from_slice(&[0, 0]);
    frames.extend_from_slice(&frame_data);
    build_id3_tag(&frames)
}

// FLAC: all metadata blocks are bounded; audio frames are streamed unchanged.
#[derive(Clone)]
struct FlacBlock {
    kind: u8,
    raw: Vec<u8>,
    data: Vec<u8>,
}

fn parse_flac_plan(source: &OpenedStreamFile) -> Result<RewritePlan> {
    if source.length() < 8 || read_at(source, 0, 4)?.as_slice() != FLAC_MAGIC {
        return Err(SignatureClientError::Invalid("Invalid FLAC magic header".into()));
    }
    let mut offset = 4u64;
    let mut blocks = Vec::new();
    let mut metadata_bytes = 4u64;
    let mut signature_payload = None;
    let mut saw_last = false;

    while !saw_last {
        if blocks.len() >= MAX_MEDIA_CHUNKS {
            return Err(SignatureClientError::Invalid(format!(
                "FLAC metadata contains more than {MAX_MEDIA_CHUNKS} blocks"
            )));
        }
        if offset.checked_add(4).map(|end| end > source.length()).unwrap_or(true) {
            return Err(SignatureClientError::Invalid("FLAC metadata block header is truncated".into()));
        }
        let header = read_at(source, offset, 4)?;
        let kind = header[0] & 0x7f;
        let is_last = header[0] & 0x80 != 0;
        let size = ((header[1] as u64) << 16) | ((header[2] as u64) << 8) | header[3] as u64;
        let end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(size))
            .ok_or_else(|| SignatureClientError::Invalid("FLAC metadata size overflowed".into()))?;
        if end > source.length() {
            return Err(SignatureClientError::Invalid("FLAC metadata block extends beyond the file".into()));
        }
        metadata_bytes = metadata_bytes
            .checked_add(4 + size)
            .ok_or_else(|| SignatureClientError::Invalid("FLAC metadata size overflowed".into()))?;
        if metadata_bytes > MAX_MEDIA_METADATA_BYTES {
            return Err(file_error("fileTooLarge", "FLAC metadata exceeds the 32 MiB limit"));
        }
        let raw = read_at(
            source,
            offset,
            usize::try_from(4 + size).map_err(|_| file_error("fileTooLarge", "FLAC metadata is too large"))?,
        )?;
        let data = raw[4..].to_vec();
        if kind == 2 && data.len() >= 4 && &data[..4] == FLAC_APPLICATION_ID {
            if signature_payload.is_some() {
                return Err(SignatureClientError::Invalid("FLAC contains duplicate Majik APPLICATION blocks".into()));
            }
            let text = String::from_utf8(data[4..].to_vec())
                .map_err(|error| SignatureClientError::Invalid(format!("FLAC signature payload is not UTF-8: {error}")))?;
            signature_payload = Some(text.trim_end_matches('\0').to_owned());
        }
        blocks.push(FlacBlock { kind, raw, data });
        offset = end;
        saw_last = is_last;
    }

    if blocks.is_empty() || blocks[0].kind != 0 {
        return Err(SignatureClientError::Invalid("FLAC metadata must begin with STREAMINFO".into()));
    }
    if offset >= source.length() {
        return Err(SignatureClientError::Invalid("FLAC audio stream is missing".into()));
    }

    // The core handler leaves unsigned FLAC byte-for-byte unchanged.
    let canonical_prefix = if signature_payload.is_none() {
        read_at(
            source,
            0,
            usize::try_from(offset).map_err(|_| file_error("fileTooLarge", "FLAC metadata length is unsupported"))?,
        )?
    } else {
        let kept: Vec<&FlacBlock> = blocks
            .iter()
            .filter(|block| !(block.kind == 2 && block.data.starts_with(FLAC_APPLICATION_ID)))
            .collect();
        if kept.is_empty() {
            return Err(SignatureClientError::Invalid("Cannot strip the FLAC signature without STREAMINFO".into()));
        }
        let mut canonical = Vec::new();
        canonical.extend_from_slice(FLAC_MAGIC);
        for (index, block) in kept.iter().enumerate() {
            let mut raw = block.raw.clone();
            if index + 1 == kept.len() {
                raw[0] |= 0x80;
            } else {
                raw[0] &= 0x7f;
            }
            canonical.extend_from_slice(&raw);
        }
        canonical
    };

    Ok(make_plan(
        source,
        0,
        offset,
        canonical_prefix,
        signature_payload,
        "FLAC",
        "audio/flac",
    ))
}

fn build_flac_signature_metadata(canonical_prefix: &[u8], payload: &str) -> Result<Vec<u8>> {
    if canonical_prefix.len() < 8 || &canonical_prefix[..4] != FLAC_MAGIC {
        return Err(SignatureClientError::Invalid("FLAC canonical metadata prefix is malformed".into()));
    }
    let mut output = canonical_prefix.to_vec();
    let mut offset = 4usize;
    let mut count = 0usize;
    while offset + 4 <= output.len() {
        let header = output[offset];
        let size = ((output[offset + 1] as usize) << 16)
            | ((output[offset + 2] as usize) << 8)
            | output[offset + 3] as usize;
        let end = offset
            .checked_add(4)
            .and_then(|value| value.checked_add(size))
            .ok_or_else(|| SignatureClientError::Invalid("FLAC metadata block size overflowed".into()))?;
        if end > output.len() {
            return Err(SignatureClientError::Invalid("FLAC metadata block is truncated".into()));
        }
        output[offset] = header & 0x7f;
        offset = end;
        count += 1;
    }
    if offset != output.len() || count == 0 {
        return Err(SignatureClientError::Invalid("FLAC metadata block list is malformed".into()));
    }

    let payload_len = FLAC_APPLICATION_ID.len()
        .checked_add(payload.len())
        .ok_or_else(|| SignatureClientError::Invalid("FLAC signature block size overflowed".into()))?;
    if payload_len > 0x00ff_ffff {
        return Err(SignatureClientError::Invalid("FLAC signature block exceeds its 24-bit length field".into()));
    }
    let mut block = Vec::with_capacity(4 + payload_len);
    block.push(0x80 | 2);
    block.push(((payload_len >> 16) & 0xff) as u8);
    block.push(((payload_len >> 8) & 0xff) as u8);
    block.push((payload_len & 0xff) as u8);
    block.extend_from_slice(FLAC_APPLICATION_ID);
    block.extend_from_slice(payload.as_bytes());
    output.extend_from_slice(&block);

    if output.len() as u64 > MAX_MEDIA_METADATA_BYTES {
        return Err(file_error("fileTooLarge", "FLAC metadata plus signature exceeds 32 MiB"));
    }
    Ok(output)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(extension: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "majik-stream-media-{}.{extension}",
            uuid::Uuid::new_v4()
        ))
    }

    fn assert_streaming_round_trip(
        format: &str,
        mime: &str,
        extension: &str,
        unsigned: Vec<u8>,
    ) {
        let input_path = fixture_path(extension);
        std::fs::write(&input_path, &unsigned).unwrap();

        let input = OpenedStreamFile::open(&input_path, Some(mime)).unwrap();
        let plan = build_plan(&input, format).unwrap();
        let payload = "streaming-test-envelope";
        let replacement = output_replacement(&plan, payload)
            .unwrap()
            .expect("media handler should produce an embedded replacement");

        let start = usize::try_from(plan.replace_start).unwrap();
        let end = usize::try_from(plan.replace_end).unwrap();
        let mut signed = Vec::with_capacity(
            unsigned.len() - (end - start) + replacement.len(),
        );
        signed.extend_from_slice(&unsigned[..start]);
        signed.extend_from_slice(&replacement);
        signed.extend_from_slice(&unsigned[end..]);

        // The core implementation must recognise and strip the streaming writer's metadata
        // exactly, otherwise the reader hash would diverge in production verification.
        let core_canonical = MajikSignature::strip_from(&signed, Some(mime)).unwrap();
        assert_eq!(core_canonical, unsigned, "{format}: core canonical bytes");

        std::fs::write(&input_path, &signed).unwrap();
        let signed_input = OpenedStreamFile::open(&input_path, Some(mime)).unwrap();
        let signed_plan = build_plan(&signed_input, format).unwrap();
        assert_eq!(
            signed_plan.envelope_payload.as_deref(),
            Some(payload),
            "{format}: signature metadata extraction"
        );
        let mut reader = RewrittenFileReader::new(
            signed_input.try_clone_file().unwrap(),
            &signed_plan,
        )
        .unwrap();
        let mut streamed_canonical = Vec::new();
        reader.read_to_end(&mut streamed_canonical).unwrap();
        assert_eq!(
            streamed_canonical, core_canonical,
            "{format}: streaming canonical reader must match core strip()"
        );

        let _ = std::fs::remove_file(input_path);
    }

    #[test]
    fn png_streaming_metadata_matches_core_handler() {
        let mut png = PNG_SIGNATURE.to_vec();
        // A minimal IEND chunk (zero length, valid CRC).
        png.extend_from_slice(&0u32.to_be_bytes());
        png.extend_from_slice(b"IEND");
        png.extend_from_slice(&0xae42_6082u32.to_be_bytes());
        assert_streaming_round_trip("png", "image/png", "png", png);
    }

    #[test]
    fn jpeg_streaming_metadata_matches_core_handler() {
        assert_streaming_round_trip(
            "jpeg",
            "image/jpeg",
            "jpg",
            vec![0xff, 0xd8, 0xff, 0xd9],
        );
    }

    #[test]
    fn mp3_streaming_metadata_matches_core_handler() {
        // A small MPEG frame-sync fixture; media bytes are not buffered by the parser.
        assert_streaming_round_trip(
            "mp3",
            "audio/mpeg",
            "mp3",
            vec![0xff, 0xfb, 0x90, 0x64, 0x00, 0x00],
        );
    }

    #[test]
    fn flac_streaming_metadata_matches_core_handler() {
        let mut flac = FLAC_MAGIC.to_vec();
        // STREAMINFO is the required first metadata block and is the final block here.
        flac.extend_from_slice(&[0x80, 0, 0, 34]);
        flac.extend_from_slice(&[0u8; 34]);
        // A small frame-sync prefix so the stream has audio data after metadata.
        flac.extend_from_slice(&[0xff, 0xf8, 0x00, 0x00]);
        assert_streaming_round_trip("flac", "audio/flac", "flac", flac);
    }

    #[cfg(unix)]
    #[test]
    fn mp3_metadata_parser_does_not_materialise_large_audio_payloads() {
        let path = fixture_path("mp3");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        // Empty ID3v2.3 tag followed by a sparse 10 GiB audio payload.
        file.write_all(b"ID3\\x03\\x00\\x00\\x00\\x00\\x00\\x00")
            .unwrap();
        file.set_len(10 * 1024 * 1024 * 1024).unwrap();
        drop(file);

        let source = OpenedStreamFile::open(&path, Some("audio/mpeg")).unwrap();
        let plan = build_plan(&source, "mp3").unwrap();
        assert_eq!(plan.canonical_len().unwrap(), source.length());
        assert!(plan.canonical_replacement.len() < 1024);
        let _ = std::fs::remove_file(path);
    }
}
