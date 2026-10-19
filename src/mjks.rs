//! `.mjksmap` batch operations (one detached envelope per file, keyed by path) and signing-order
//! verification.

use jiff::Timestamp;
use majik_signature::{
    BatchFileInput, BatchSignFailure, BatchSignOptions, BatchSignResult, BatchVerifyInput,
    BatchVerifyOptions, BatchVerifySummary, EmbedOptions, EnvelopeInfo, EnvelopeInput,
    FileVerifyResult, FileVerifyStatus, MajikSignature, MajikSignatureEnvelope, MajikSignatureMap,
    MjksMapEntry, MjksMapJSON, MjksMapResolveStatus, OrderEntry, OrderOptions, SignDetachedOptions,
    SignatureOrderResult,
};

use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::logs::{HistorySource, HistoryType};
use crate::signing::{invalid_result, OpContext, OpNote, SignerRef, VerifyTarget};

/// A signature map in any of the forms the TS API accepts.
#[derive(Debug, Clone)]
pub enum MjksMapInput {
    Map(MajikSignatureMap),
    /// `.mjksmap` bytes.
    Bytes(Vec<u8>),
    Json(MjksMapJSON),
}

impl MjksMapInput {
    pub fn resolve(self) -> Result<MajikSignatureMap> {
        Ok(match self {
            Self::Map(m) => m,
            Self::Bytes(b) => MajikSignatureMap::from_mjksmap(&b)?,
            Self::Json(j) => MajikSignatureMap::from_json(&j)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct MjksMapFileInfo {
    pub path: String,
    pub content_hash: String,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub info: EnvelopeInfo,
}

#[derive(Debug, Clone, Default)]
pub struct CosignOptions {
    pub valid_until: Option<String>,
    pub continue_on_error: bool,
}

pub struct CosignResult {
    pub map: MajikSignatureMap,
    pub map_blob: Vec<u8>,
    pub failures: Vec<BatchSignFailure>,
}

pub struct MapVerifyResult {
    pub results: Vec<FileVerifyResult>,
    pub summary: BatchVerifySummary,
    /// Map entries with no matching file in the batch (only filled when all must be present).
    pub missing_from_batch: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct OrderCheckOptions {
    pub mime_type: Option<String>,
    /// Every expected signer must have signed, in order, and nobody else may have.
    pub strict: bool,
}

pub struct MapOrderFileResult {
    pub path: String,
    pub resolve_status: MjksMapResolveStatus,
    pub order: Option<SignatureOrderResult>,
    pub reason: Option<String>,
}

impl SignatureClient {
    // ── Map basics ───────────────────────────────────────────────────────────

    pub fn read_mjks_map(&self, bytes: &[u8]) -> Result<MajikSignatureMap> {
        Ok(MajikSignatureMap::from_mjksmap(bytes)?)
    }

    pub fn is_mjks_map(&self, bytes: &[u8]) -> bool {
        MajikSignatureMap::is_mjksmap(bytes)
    }

    /// Per-file summary (signatories, seal, ...) of every entry in a map.
    pub fn describe_mjks_map(&self, map: MjksMapInput) -> Result<Vec<MjksMapFileInfo>> {
        let map = map.resolve()?;
        map.entries()
            .iter()
            .map(|e| {
                let envelope = MajikSignatureEnvelope::from_json(&e.envelope)?;
                Ok(MjksMapFileInfo {
                    path: e.path.clone(),
                    content_hash: e.content_hash.clone(),
                    size: e.size,
                    mime_type: e.mime_type.clone(),
                    info: envelope.get_envelope_info(),
                })
            })
            .collect()
    }

    // ── Sign ─────────────────────────────────────────────────────────────────

    /// Sign many files with detached envelopes, as one `.mjksmap` or as separate `.mjksig`s.
    pub fn sign_batch_detached(
        &mut self,
        files: &[BatchFileInput],
        options: &BatchSignOptions,
        ctx: &OpContext,
    ) -> Result<BatchSignResult> {
        let signed = self.with_signing_key(ctx.account_id.as_deref(), false, |key| {
            Ok(MajikSignature::sign_batch_detached(
                files,
                key,
                Some(options),
            )?)
        });
        let (result, sctx) = self.report("signBatchDetached", signed)?;

        let digests: Vec<(String, String)> = match &result {
            BatchSignResult::Map { map, .. } => map
                .entries()
                .iter()
                .map(|e| (e.path.clone(), e.content_hash.clone()))
                .collect(),
            BatchSignResult::Separate { signatures, .. } => signatures
                .iter()
                .filter_map(|s| {
                    let env = MajikSignatureEnvelope::from_mjksig(&s.blob).ok()?;
                    let sig = env.signatures().first()?;
                    Some((s.path.clone(), sig.content_hash.clone()))
                })
                .collect(),
        };
        for (_path, digest) in digests {
            let mut note = OpNote::new(&digest, HistoryType::Sign, ctx.source);
            note.detached = true;
            self.note_history(Some(&sctx.fingerprint), note, &digest, None);
        }
        let failures = match &result {
            BatchSignResult::Map { failures, .. } | BatchSignResult::Separate { failures, .. } => {
                failures.clone()
            }
        };
        for f in failures {
            self.emit_error(
                "signBatchDetached",
                &SignatureClientError::Invalid(format!("{}: {}", f.path, f.error)),
            );
        }
        Ok(result)
    }

    /// Add this account's signature to every listed file's entry in an existing map.
    pub fn cosign_mjks_map(
        &mut self,
        map: MjksMapInput,
        files: &[BatchVerifyInput],
        options: &CosignOptions,
        ctx: &OpContext,
    ) -> Result<CosignResult> {
        let map = map.resolve()?;
        let signed = self.with_signing_key(ctx.account_id.as_deref(), false, |key| {
            let mut current = map.clone();
            let mut failures: Vec<BatchSignFailure> = Vec::new();
            let mut signed_digests: Vec<String> = Vec::new();
            for f in files {
                let attempt = (|| -> Result<(MajikSignatureMap, String)> {
                    let found = current.find_entry(&f.path, &f.blob);
                    let entry = match (found.found, found.entry) {
                        (true, Some(e)) => e,
                        _ => {
                            return Err(SignatureClientError::Invalid(
                                "file is not in the signature map".into(),
                            ))
                        }
                    };
                    if found.hash_matches == Some(false) {
                        return Err(SignatureClientError::Invalid(
                            "file content does not match the map (tampered)".into(),
                        ));
                    }
                    let detached = SignDetachedOptions {
                        embed: EmbedOptions {
                            mime_type: entry.mime_type.clone(),
                            force_fallback: false,
                        },
                        valid_until: options.valid_until.clone(),
                        existing_envelope: Some(EnvelopeInput::Json(entry.envelope.clone())),
                        ..Default::default()
                    };
                    let result = MajikSignature::sign_file_detached(&f.blob, key, Some(&detached))?;
                    let digest = result.signature.content_hash().to_string();
                    let updated = MjksMapEntry {
                        envelope: result.envelope.to_json(),
                        ..entry
                    };
                    Ok((current.with_entry(updated)?, digest))
                })();
                match attempt {
                    Ok((next, digest)) => {
                        current = next;
                        signed_digests.push(digest);
                    }
                    Err(e) => {
                        failures.push(BatchSignFailure {
                            path: f.path.clone(),
                            error: e.to_string(),
                        });
                        if !options.continue_on_error {
                            break;
                        }
                    }
                }
            }
            Ok((current, failures, signed_digests))
        });
        let ((map, failures, digests), sctx) = self.report("cosignMjksMap", signed)?;
        for digest in digests {
            let mut note = OpNote::new(&digest, HistoryType::Sign, ctx.source);
            note.detached = true;
            self.note_history(Some(&sctx.fingerprint), note, &digest, None);
        }
        let map_blob = map.to_mjksmap_bytes();
        Ok(CosignResult {
            map,
            map_blob,
            failures,
        })
    }

    // ── Verify ───────────────────────────────────────────────────────────────

    /// Verify a batch of files against a signature map. With a trusted source in `target` the
    /// signatures are checked against those keys; without one each envelope's own keys are used.
    pub fn verify_mjks_map(
        &mut self,
        map: MjksMapInput,
        files: &[BatchVerifyInput],
        target: &VerifyTarget<'_>,
        require_all_present: bool,
        source: HistorySource,
    ) -> Result<MapVerifyResult> {
        let map = map.resolve()?;
        let outcome = (|| -> Result<Vec<FileVerifyResult>> {
            if let Some(keys) = self.resolve_signer_public_keys(target)? {
                let opts = BatchVerifyOptions {
                    expected_signer_id: target.expected_signer_id.map(str::to_string),
                    now: target.now,
                    require_all_present,
                };
                return Ok(MajikSignature::verify_files_from_mjksmap(
                    &map,
                    files,
                    &keys,
                    Some(&opts),
                )?);
            }
            let mut out = Vec::with_capacity(files.len());
            for f in files {
                let resolved = map.resolve_entry(&f.path, &f.blob);
                let entry = match (resolved.status, resolved.entry) {
                    (MjksMapResolveStatus::NotFound, _) | (_, None) => {
                        out.push(FileVerifyResult {
                            path: f.path.clone(),
                            status: FileVerifyStatus::NotInMap,
                            results: None,
                            reason: Some("File is not in the signature map".into()),
                            relocated_from: None,
                        });
                        continue;
                    }
                    (MjksMapResolveStatus::PathTampered, _) => {
                        out.push(FileVerifyResult {
                            path: f.path.clone(),
                            status: FileVerifyStatus::Tampered,
                            results: None,
                            reason: Some(
                                "Content does not match the map entry for this path".into(),
                            ),
                            relocated_from: None,
                        });
                        continue;
                    }
                    (_, Some(entry)) => entry,
                };
                let envelope = EnvelopeInput::Json(entry.envelope.clone());
                let per_file = VerifyTarget {
                    expected_signer_id: target.expected_signer_id,
                    mime_type: entry.mime_type.as_deref(),
                    now: target.now,
                    ..Default::default()
                };
                let verified = self.verify_file_detached_inner_pub(&f.blob, &envelope, &per_file);
                let relocated_from = if resolved.status == MjksMapResolveStatus::Relocated {
                    resolved.original_path.clone()
                } else {
                    None
                };
                match verified {
                    Ok(result) => out.push(FileVerifyResult {
                        path: f.path.clone(),
                        status: if result.valid {
                            FileVerifyStatus::Verified
                        } else {
                            FileVerifyStatus::Invalid
                        },
                        reason: result.reason.clone(),
                        results: Some(vec![result]),
                        relocated_from,
                    }),
                    Err(e) => out.push(FileVerifyResult {
                        path: f.path.clone(),
                        status: FileVerifyStatus::Invalid,
                        results: Some(vec![invalid_result(&e.to_string())]),
                        reason: Some(e.to_string()),
                        relocated_from,
                    }),
                }
            }
            Ok(out)
        })();
        let results = self.report("verifyMjksMap", outcome)?;

        let missing_from_batch = if require_all_present {
            map.entries()
                .iter()
                .filter(|e| !files.iter().any(|f| f.path == e.path))
                .map(|e| e.path.clone())
                .collect()
        } else {
            Vec::new()
        };
        let summary = MajikSignature::summarize_batch_verification(&results);

        let fp = self.active_fingerprint();
        for r in &results {
            if let Some(first) = r.results.as_ref().and_then(|v| v.first()) {
                if let Some(hash) = first.content_hash.clone().filter(|h| !h.is_empty()) {
                    let mut note = OpNote::new(&hash, HistoryType::Verify, source);
                    note.detached = true;
                    note.valid = Some(first.valid);
                    self.note_history(fp.as_deref(), note, &hash, None);
                }
            }
        }
        Ok(MapVerifyResult {
            results,
            summary,
            missing_from_batch,
        })
    }

    /// First verification result for a detached envelope, without events or history.
    fn verify_file_detached_inner_pub(
        &self,
        file: &[u8],
        envelope: &EnvelopeInput,
        target: &VerifyTarget<'_>,
    ) -> Result<majik_signature::VerificationResult> {
        Ok(self.verify_detached_core(file, envelope, target)?.0)
    }

    // ── Order ────────────────────────────────────────────────────────────────

    fn order_entries(
        &self,
        expected: &[SignerRef<'_>],
    ) -> Result<Vec<majik_signature::ExpectedSigner>> {
        self.build_expected_signers(expected)
    }

    fn note_order_history(
        &mut self,
        digest: Option<String>,
        valid: bool,
        detached: bool,
        source: HistorySource,
    ) {
        if let Some(digest) = digest.filter(|d| !d.is_empty()) {
            let fp = self.active_fingerprint();
            let mut note = OpNote::new(&digest, HistoryType::Verify, source);
            note.detached = detached;
            note.valid = Some(valid);
            self.note_history(fp.as_deref(), note, &digest, None);
        }
    }

    /// Check that `file`'s embedded signatures were made by `expected`, in that order.
    pub fn verify_file_order(
        &mut self,
        file: &[u8],
        expected: &[SignerRef<'_>],
        options: &OrderCheckOptions,
        source: HistorySource,
    ) -> Result<SignatureOrderResult> {
        let outcome = (|| -> Result<(SignatureOrderResult, Option<String>)> {
            let signers = self.order_entries(expected)?;
            let entries: Vec<OrderEntry<'_>> = signers.iter().map(OrderEntry::Signer).collect();
            let opts = OrderOptions {
                mime_type: options.mime_type.clone(),
                strict: options.strict,
            };
            let digest = MajikSignature::extract_from(file, options.mime_type.as_deref())
                .ok()
                .and_then(|s| s.first().map(|x| x.content_hash().to_string()));
            Ok((
                MajikSignature::verify_file_order(file, &entries, Some(&opts))?,
                digest,
            ))
        })();
        let (result, digest) = self.report("verifyFileOrder", outcome)?;
        self.note_order_history(digest, result.valid, false, source);
        Ok(result)
    }

    pub fn verify_file_detached_order(
        &mut self,
        file: &[u8],
        envelope: EnvelopeInput,
        expected: &[SignerRef<'_>],
        options: &OrderCheckOptions,
        source: HistorySource,
    ) -> Result<SignatureOrderResult> {
        let outcome = (|| -> Result<(SignatureOrderResult, Option<String>)> {
            let signers = self.order_entries(expected)?;
            let entries: Vec<OrderEntry<'_>> = signers.iter().map(OrderEntry::Signer).collect();
            let opts = OrderOptions {
                mime_type: options.mime_type.clone(),
                strict: options.strict,
            };
            let digest = MajikSignatureEnvelope::from_input(envelope.clone())
                .ok()
                .and_then(|e| e.signatures().first().map(|s| s.content_hash.clone()));
            Ok((
                MajikSignature::verify_file_detached_order(
                    file,
                    envelope.clone(),
                    &entries,
                    Some(&opts),
                )?,
                digest,
            ))
        })();
        let (result, digest) = self.report("verifyFileDetachedOrder", outcome)?;
        self.note_order_history(digest, result.valid, true, source);
        Ok(result)
    }

    /// Check signing order per file in a map. `expected_for` returns the expected signers for a
    /// path (build them with `build_expected_signers` / `expected_signer_from_key`).
    pub fn verify_mjks_map_order(
        &mut self,
        map: MjksMapInput,
        files: &[BatchVerifyInput],
        expected_for: &dyn Fn(&str) -> Vec<majik_signature::ExpectedSigner>,
        strict: bool,
        source: HistorySource,
    ) -> Result<Vec<MapOrderFileResult>> {
        let map = map.resolve()?;
        let mut out = Vec::with_capacity(files.len());
        for f in files {
            let resolved = map.resolve_entry(&f.path, &f.blob);
            let entry = match (resolved.status, resolved.entry.clone()) {
                (MjksMapResolveStatus::NotFound, _) | (_, None) => {
                    out.push(MapOrderFileResult {
                        path: f.path.clone(),
                        resolve_status: resolved.status,
                        order: None,
                        reason: Some("File is not in the signature map".into()),
                    });
                    continue;
                }
                (MjksMapResolveStatus::PathTampered, _) => {
                    out.push(MapOrderFileResult {
                        path: f.path.clone(),
                        resolve_status: resolved.status,
                        order: None,
                        reason: Some("Content does not match the map entry".into()),
                    });
                    continue;
                }
                (_, Some(e)) => e,
            };
            let signers = expected_for(&f.path);
            let entries: Vec<OrderEntry<'_>> = signers.iter().map(OrderEntry::Signer).collect();
            let opts = OrderOptions {
                mime_type: entry.mime_type.clone(),
                strict,
            };
            let envelope = EnvelopeInput::Json(entry.envelope.clone());
            let result = MajikSignature::verify_file_detached_order(
                &f.blob,
                envelope,
                &entries,
                Some(&opts),
            );
            match result {
                Ok(order) => {
                    let digest = entry
                        .envelope
                        .signatures
                        .first()
                        .map(|s| s.content_hash.clone());
                    self.note_order_history(digest, order.valid, true, source);
                    out.push(MapOrderFileResult {
                        path: f.path.clone(),
                        resolve_status: resolved.status,
                        order: Some(order),
                        reason: None,
                    });
                }
                Err(e) => out.push(MapOrderFileResult {
                    path: f.path.clone(),
                    resolve_status: resolved.status,
                    order: None,
                    reason: Some(e.to_string()),
                }),
            }
        }
        Ok(out)
    }

    pub fn now_for_verification() -> Timestamp {
        Timestamp::now()
    }
}
