//! File-level operations: embedded and detached signing, verification, chains and revisions,
//! allowlists, signatories, seals and envelope queries.

use jiff::Timestamp;
use majik_signature::{
    CanSignResult, EmbedOptions, EnvelopeInfo, EnvelopeInput, ExpectedSigner, FileChainVerification,
    MajikSignature, MajikSignatureEnvelope, MajikSignatureError, MajikSignerPublicKeys,
    MajikTimestamp, RevisionSetVerification, SealResult, SignAndEmbedOptions, SignAndEmbedResult,
    SignDetachedOptions, SignDetachedResult, SignatoriesFilter, SignatoriesResult, SignatoryInfo,
    SealInfo, VerificationResult, VerifyFileOptions, VerifyRevisionsOptions,
};

use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::events::SigOnlyEvent;
use crate::logs::{HistorySource, HistoryType, LogEnvelope};
use crate::signing::{
    invalid_result, OpContext, OpNote, SignEventPayload, SignResult, VerifyResult, VerifyTarget,
};

#[derive(Debug, Clone, Default)]
pub struct SignFileOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<String>,
    pub mime_type: Option<String>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<String>,
    pub prior_signed_file: Option<Vec<u8>>,
    pub message: Option<String>,
    /// Keep an encrypted copy of the output in the history (default `true`).
    pub save_history: Option<bool>,
}

impl SignFileOptions {
    fn to_embed(&self) -> SignAndEmbedOptions {
        SignAndEmbedOptions {
            embed: EmbedOptions {
                mime_type: self.mime_type.clone(),
                force_fallback: false,
            },
            content_type: self.content_type.clone(),
            timestamp: self.timestamp.clone(),
            expected_signers: self.expected_signers.clone(),
            valid_until: self.valid_until.clone(),
            message: self.message.clone(),
            prior_signed_file: self.prior_signed_file.clone(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct SignDetachedFileOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<String>,
    pub mime_type: Option<String>,
    pub expected_signers: Option<Vec<ExpectedSigner>>,
    pub valid_until: Option<String>,
    /// Co-sign an existing detached envelope instead of starting a new one.
    pub existing_envelope: Option<EnvelopeInput>,
    pub tsa: Option<MajikTimestamp>,
    pub save_history: Option<bool>,
}

impl SignDetachedFileOptions {
    fn to_detached(&self) -> SignDetachedOptions {
        SignDetachedOptions {
            embed: EmbedOptions {
                mime_type: self.mime_type.clone(),
                force_fallback: false,
            },
            content_type: self.content_type.clone(),
            timestamp: self.timestamp.clone(),
            valid_until: self.valid_until.clone(),
            expected_signers: self.expected_signers.clone(),
            existing_envelope: self.existing_envelope.clone(),
            tsa: self.tsa.clone(),
        }
    }
}

/// One file in a batch signing run and what happened to it.
pub struct BatchSignOutcome {
    pub path: String,
    pub result: std::result::Result<SignAndEmbedResult, String>,
}

fn first(mut results: Vec<VerificationResult>) -> Result<VerificationResult> {
    if results.is_empty() {
        return Err(SignatureClientError::Invalid(
            "verification produced no result".into(),
        ));
    }
    Ok(results.remove(0))
}

impl SignatureClient {
    // ── Sign ─────────────────────────────────────────────────────────────────

    /// Sign `file` and embed the signature in it (or in its fallback container).
    pub fn sign_file(
        &mut self,
        file: &[u8],
        options: &SignFileOptions,
        ctx: &OpContext,
    ) -> Result<SignAndEmbedResult> {
        let embed = options.to_embed();
        let want_envelope = options.save_history.unwrap_or(true);
        let signed = self.with_signing_key(ctx.account_id.as_deref(), want_envelope, |key| {
            Ok(MajikSignature::sign_file(file, key, Some(&embed))?)
        });
        let (result, sctx) = self.report("signFile", signed)?;
        self.after_embedded_sign(&result, &sctx, want_envelope, ctx.source);
        Ok(result)
    }

    fn after_embedded_sign(
        &mut self,
        result: &SignAndEmbedResult,
        sctx: &crate::signing::SigningCtx,
        want_envelope: bool,
        source: HistorySource,
    ) {
        let sign_result = SignResult {
            signature: result.signature.clone(),
            signer_id: result.signature.signer_id().to_string(),
            content_hash: result.signature.content_hash().to_string(),
            timestamp: result.signature.timestamp().to_string(),
            content_type: result.signature.content_type().map(str::to_string),
        };
        self.emit(SigOnlyEvent::Sign(SignEventPayload::from(&sign_result)));
        let digest = sign_result.content_hash.clone();
        let mut note = OpNote::new(&digest, HistoryType::Sign, source);
        note.tsa = result.signature.has_tsa();
        note.signer_count = Some(result.envelope.signatures().len() as u32);
        let envelope = match (&sctx.identity, want_envelope) {
            (Some(identity), true) => Some(LogEnvelope {
                data: result.blob.clone(),
                identity: identity.clone(),
            }),
            _ => None,
        };
        self.note_history(Some(&sctx.fingerprint), note, &digest, envelope);
    }

    /// Sign `file` and return the signature as a separate `.mjksig` envelope.
    pub fn sign_file_detached(
        &mut self,
        file: &[u8],
        options: &SignDetachedFileOptions,
        ctx: &OpContext,
    ) -> Result<SignDetachedResult> {
        let detached = options.to_detached();
        let want_envelope = options.save_history.unwrap_or(true);
        let signed = self.with_signing_key(ctx.account_id.as_deref(), want_envelope, |key| {
            Ok(MajikSignature::sign_file_detached(file, key, Some(&detached))?)
        });
        let (result, sctx) = self.report("signFileDetached", signed)?;
        self.after_detached_sign(&result, &sctx, want_envelope, ctx.source);
        Ok(result)
    }

    pub(crate) fn after_detached_sign(
        &mut self,
        result: &SignDetachedResult,
        sctx: &crate::signing::SigningCtx,
        want_envelope: bool,
        source: HistorySource,
    ) {
        let sign_result = SignResult {
            signature: result.signature.clone(),
            signer_id: result.signature.signer_id().to_string(),
            content_hash: result.signature.content_hash().to_string(),
            timestamp: result.signature.timestamp().to_string(),
            content_type: result.signature.content_type().map(str::to_string),
        };
        self.emit(SigOnlyEvent::Sign(SignEventPayload::from(&sign_result)));
        let digest = sign_result.content_hash.clone();
        let mut note = OpNote::new(&digest, HistoryType::Sign, source);
        note.detached = true;
        note.tsa = result.signature.has_tsa();
        note.signer_count = Some(result.envelope.signatures().len() as u32);
        let envelope = match (&sctx.identity, want_envelope) {
            (Some(identity), true) => Some(LogEnvelope {
                data: result.blob.clone(),
                identity: identity.clone(),
            }),
            _ => None,
        };
        self.note_history(Some(&sctx.fingerprint), note, &digest, envelope);
    }

    /// Sign several files under one unlock. Each file succeeds or fails on its own.
    pub fn batch_sign_files(
        &mut self,
        files: &[(String, Vec<u8>, Option<String>)],
        options: &SignFileOptions,
        ctx: &OpContext,
    ) -> Result<Vec<BatchSignOutcome>> {
        let want_envelope = options.save_history.unwrap_or(true);
        let signed = self.with_signing_key(ctx.account_id.as_deref(), want_envelope, |key| {
            let mut outcomes = Vec::with_capacity(files.len());
            for (path, blob, mime) in files {
                let mut embed = options.to_embed();
                if mime.is_some() {
                    embed.embed.mime_type = mime.clone();
                }
                let result = MajikSignature::sign_file(blob, key, Some(&embed))
                    .map_err(|e| e.to_string());
                outcomes.push(BatchSignOutcome {
                    path: path.clone(),
                    result,
                });
            }
            Ok(outcomes)
        });
        let (outcomes, sctx) = self.report("batchSignFiles", signed)?;
        for outcome in &outcomes {
            match &outcome.result {
                Ok(result) => self.after_embedded_sign(result, &sctx, want_envelope, ctx.source),
                Err(message) => self.emit_error(
                    "batchSignFiles",
                    &SignatureClientError::Invalid(format!("{}: {message}", outcome.path)),
                ),
            }
        }
        Ok(outcomes)
    }

    // ── Verify ───────────────────────────────────────────────────────────────

    pub(crate) fn finish_file_verify(
        &mut self,
        result: VerificationResult,
        tsa: bool,
        sealed: bool,
        detached: bool,
        source: HistorySource,
    ) -> VerifyResult {
        let signer_label = result
            .signer_id
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .map(|s| self.resolve_signer_label(s));
        let verified = VerifyResult {
            result,
            signer_label,
        };
        self.emit(SigOnlyEvent::Verify(verified.clone()));
        if let Some(hash) = verified.result.content_hash.clone().filter(|h| !h.is_empty()) {
            let fp = self.active_fingerprint();
            let mut note = OpNote::new(&hash, HistoryType::Verify, source);
            note.detached = detached;
            note.sealed = sealed;
            note.tsa = tsa;
            note.valid = Some(verified.result.valid);
            self.note_history(fp.as_deref(), note, &hash, None);
        }
        verified
    }

    fn verify_options(target: &VerifyTarget<'_>) -> VerifyFileOptions {
        VerifyFileOptions {
            mime_type: target.mime_type.map(str::to_string),
            expected_signer_id: target.expected_signer_id.map(str::to_string),
            now: target.now,
            require_canonical: false,
        }
    }

    fn verify_file_inner(
        &self,
        file: &[u8],
        target: &VerifyTarget<'_>,
    ) -> Result<(VerificationResult, bool, bool)> {
        let keys = self.resolve_signer_public_keys(target)?;
        let mut opts = Self::verify_options(target);
        let extracted = MajikSignature::extract_from(file, target.mime_type)?;
        let tsa = extracted.first().map(|s| s.has_tsa()).unwrap_or(false);
        let result = match keys {
            Some(k) => first(MajikSignature::verify_file(file, &k, Some(&opts))?)?,
            None => {
                if extracted.is_empty() {
                    invalid_result("No embedded signature found")
                } else {
                    let chosen = target
                        .expected_signer_id
                        .and_then(|id| extracted.iter().find(|s| s.signer_id() == id))
                        .unwrap_or(&extracted[0]);
                    let k = chosen.extract_public_keys()?;
                    opts.expected_signer_id = Some(chosen.signer_id().to_string());
                    first(MajikSignature::verify_file(file, &k, Some(&opts))?)?
                }
            }
        };
        let sealed = MajikSignature::is_sealed(file, target.mime_type).unwrap_or(false);
        Ok((result, tsa, sealed))
    }

    /// Verify the (first matching) embedded signature of `file`.
    pub fn verify_file(
        &mut self,
        file: &[u8],
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let outcome = self.verify_file_inner(file, target);
        let (result, tsa, sealed) = self.report("verifyFile", outcome)?;
        Ok(self.finish_file_verify(result, tsa, sealed, false, source))
    }

    pub(crate) fn verify_detached_core(
        &self,
        file: &[u8],
        envelope: &EnvelopeInput,
        target: &VerifyTarget<'_>,
    ) -> Result<(VerificationResult, bool, bool)> {
        let keys = self.resolve_signer_public_keys(target)?;
        let mut opts = Self::verify_options(target);
        let parsed = MajikSignatureEnvelope::from_input(envelope.clone())?;
        let tsa = parsed.signatures().first().map(|s| s.tsa.is_some()).unwrap_or(false);
        let result = match keys {
            Some(k) => first(MajikSignature::verify_file_detached(
                file,
                envelope.clone(),
                &k,
                Some(&opts),
            )?)?,
            None => match parsed.signatures().first() {
                None => invalid_result("No signature found in envelope"),
                Some(sig_json) => {
                    let sig = MajikSignature::from_json(sig_json)?;
                    let k = sig.extract_public_keys()?;
                    opts.expected_signer_id = Some(sig.signer_id().to_string());
                    first(MajikSignature::verify_file_detached(
                        file,
                        envelope.clone(),
                        &k,
                        Some(&opts),
                    )?)?
                }
            },
        };
        Ok((result, tsa, parsed.is_sealed()))
    }

    /// Verify `file` against a detached `.mjksig` envelope.
    pub fn verify_file_detached(
        &mut self,
        file: &[u8],
        envelope: EnvelopeInput,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let outcome = self.verify_detached_core(file, &envelope, target);
        let (result, tsa, sealed) = self.report("verifyFileDetached", outcome)?;
        Ok(self.finish_file_verify(result, tsa, sealed, true, source))
    }

    /// Verify every embedded signature (multi-signature files).
    pub fn verify_file_all_signatures(
        &mut self,
        file: &[u8],
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<Vec<VerifyResult>> {
        let outcome = (|| -> Result<(Vec<VerificationResult>, bool, bool)> {
            let keys = self.resolve_signer_public_keys(target)?;
            let opts = Self::verify_options(target);
            let extracted = MajikSignature::extract_from(file, target.mime_type)?;
            let tsa = extracted.first().map(|s| s.has_tsa()).unwrap_or(false);
            let results = match keys {
                Some(k) => MajikSignature::verify_file(file, &k, Some(&opts))?,
                None if extracted.is_empty() => vec![invalid_result("No embedded signature found")],
                None => {
                    let mut all = Vec::new();
                    for sig in &extracted {
                        let k = sig.extract_public_keys()?;
                        let mut per = opts.clone();
                        per.expected_signer_id = Some(sig.signer_id().to_string());
                        all.push(first(MajikSignature::verify_file(file, &k, Some(&per))?)?);
                    }
                    all
                }
            };
            let sealed = MajikSignature::is_sealed(file, target.mime_type).unwrap_or(false);
            Ok((results, tsa, sealed))
        })();
        let (results, tsa, sealed) = self.report("verifyFileAllSignatures", outcome)?;
        Ok(results
            .into_iter()
            .map(|r| self.finish_file_verify(r, tsa, sealed, false, source))
            .collect())
    }

    /// Verify every signature in a detached envelope.
    pub fn verify_file_detached_all_signatures(
        &mut self,
        file: &[u8],
        envelope: EnvelopeInput,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<Vec<VerifyResult>> {
        let outcome = (|| -> Result<(Vec<VerificationResult>, bool, bool)> {
            let keys = self.resolve_signer_public_keys(target)?;
            let opts = Self::verify_options(target);
            let parsed = MajikSignatureEnvelope::from_input(envelope.clone())?;
            let tsa = parsed.signatures().first().map(|s| s.tsa.is_some()).unwrap_or(false);
            let results = match keys {
                Some(k) => {
                    MajikSignature::verify_file_detached(file, envelope.clone(), &k, Some(&opts))?
                }
                None if parsed.signatures().is_empty() => {
                    vec![invalid_result("No signature found in envelope")]
                }
                None => {
                    let mut all = Vec::new();
                    for sig_json in parsed.signatures() {
                        let sig = MajikSignature::from_json(sig_json)?;
                        let k = sig.extract_public_keys()?;
                        let mut per = opts.clone();
                        per.expected_signer_id = Some(sig.signer_id().to_string());
                        all.push(first(MajikSignature::verify_file_detached(
                            file,
                            envelope.clone(),
                            &k,
                            Some(&per),
                        )?)?);
                    }
                    all
                }
            };
            Ok((results, tsa, parsed.is_sealed()))
        })();
        let (results, tsa, sealed) = self.report("verifyFileDetachedAllSignatures", outcome)?;
        Ok(results
            .into_iter()
            .map(|r| self.finish_file_verify(r, tsa, sealed, true, source))
            .collect())
    }

    /// Verify a file's version chain (latest signature plus the commitments of earlier ones).
    pub fn verify_file_chain(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
        now: Option<Timestamp>,
    ) -> Result<FileChainVerification> {
        self.report(
            "verifyFileChain",
            Ok(MajikSignature::verify_file_chain(file, mime_type, now)?),
        )
    }

    /// Verify `final_file` against its earlier `revisions`. When `options` has no
    /// `resolve_public_keys`, signers are resolved from your own accounts, then your contacts.
    pub fn verify_file_revisions(
        &self,
        final_file: &[u8],
        revisions: &[&[u8]],
        options: Option<VerifyRevisionsOptions<'_>>,
    ) -> Result<RevisionSetVerification> {
        let own_or_contact = |signer_id: &str| -> std::result::Result<
            MajikSignerPublicKeys,
            MajikSignatureError,
        > {
            if let Some(key) = self.keys.key_manager().get(signer_id) {
                return MajikSignature::public_keys_from_majik_key(key);
            }
            if let Ok(contacts) = self.shared.lock_contacts() {
                if let Some(c) = contacts.get_contact_by_fingerprint(signer_id) {
                    if !c.ed_public_key_base64().is_empty()
                        && !c.ml_dsa_public_key_base64().is_empty()
                    {
                        return Ok(MajikSignerPublicKeys {
                            signer_id: c.fingerprint().to_string(),
                            ed_public_key: majik_signature::base64_to_bytes(c.ed_public_key_base64())?,
                            ml_dsa_public_key: majik_signature::base64_to_bytes(
                                c.ml_dsa_public_key_base64(),
                            )?,
                        });
                    }
                }
            }
            Err(MajikSignatureError::key(format!(
                "No public keys known for signer \"{signer_id}\""
            )))
        };
        let result = match options {
            Some(o) if o.resolve_public_keys.is_some() => {
                MajikSignature::verify_file_revisions(final_file, revisions, Some(&o))
            }
            other => {
                let mime = other.and_then(|o| o.mime_type);
                let opts = VerifyRevisionsOptions {
                    mime_type: mime,
                    now: None,
                    resolve_public_keys: Some(&own_or_contact),
                };
                MajikSignature::verify_file_revisions(final_file, revisions, Some(&opts))
            }
        };
        self.report("verifyFileRevisions", Ok(result?))
    }

    // ── Inspect / strip ──────────────────────────────────────────────────────

    pub fn extract_signature(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Vec<MajikSignature>> {
        Ok(MajikSignature::extract_from(file, mime_type)?)
    }

    pub fn strip_signature(&self, file: &[u8], mime_type: Option<&str>) -> Result<Vec<u8>> {
        Ok(MajikSignature::strip_from(file, mime_type)?)
    }

    pub fn is_file_signed(&self, file: &[u8], mime_type: Option<&str>) -> Result<bool> {
        Ok(MajikSignature::is_signed(file, mime_type)?)
    }

    pub fn get_allowlist(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Option<Vec<ExpectedSigner>>> {
        Ok(MajikSignature::get_allowlist(file, mime_type)?)
    }

    /// Whether the context account may sign `file` (allowlist, seal, ordering).
    pub fn can_sign(
        &self,
        file: &[u8],
        account_id: Option<&str>,
        mime_type: Option<&str>,
    ) -> Result<CanSignResult> {
        let id = self.resolve_account_id(account_id)?;
        let key = self.keys.key_manager().get(&id).ok_or_else(|| {
            SignatureClientError::Invalid(format!("Account not found in keystore: \"{id}\""))
        })?;
        Ok(MajikSignature::can_sign(file, key, mime_type)?)
    }

    pub fn is_multi_sig(&self, file: &[u8], mime_type: Option<&str>) -> Result<bool> {
        Ok(MajikSignature::is_multi_sig(file, mime_type)?)
    }

    pub fn get_signatories(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
        filter: Option<SignatoriesFilter>,
    ) -> Result<Option<SignatoriesResult>> {
        Ok(MajikSignature::get_signatories(file, mime_type, filter)?)
    }

    pub fn get_signed_signatories(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Option<SignatoriesResult>> {
        Ok(MajikSignature::get_signed_signatories(file, mime_type)?)
    }

    pub fn get_pending_signatories(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Option<SignatoriesResult>> {
        Ok(MajikSignature::get_pending_signatories(file, mime_type)?)
    }

    pub fn get_all_signatories(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Option<SignatoriesResult>> {
        Ok(MajikSignature::get_all_signatories(file, mime_type)?)
    }

    pub fn get_issuer(&self, file: &[u8], mime_type: Option<&str>) -> Result<Option<SignatoryInfo>> {
        Ok(MajikSignature::get_issuer(file, mime_type)?)
    }

    pub fn get_envelope_info(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<Option<EnvelopeInfo>> {
        Ok(MajikSignature::get_envelope_info(file, mime_type)?)
    }

    // ── Seal ─────────────────────────────────────────────────────────────────

    /// Seal `file`: no further signatures can be added.
    pub fn seal(
        &mut self,
        file: &[u8],
        mime_type: Option<&str>,
        timestamp: Option<&str>,
        ctx: &OpContext,
    ) -> Result<SealResult> {
        let sealed = self.with_signing_key(ctx.account_id.as_deref(), true, |key| {
            Ok(MajikSignature::seal(file, key, mime_type, timestamp)?)
        });
        let (result, sctx) = self.report("seal", sealed)?;
        let digest = result.seal_info.seal_hash.clone();
        let mut note = OpNote::new(&digest, HistoryType::Seal, ctx.source);
        note.sealed = true;
        let envelope = sctx.identity.clone().map(|identity| LogEnvelope {
            data: result.blob.clone(),
            identity,
        });
        self.note_history(Some(&sctx.fingerprint), note, &digest, envelope);
        Ok(result)
    }

    pub fn verify_seal(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<majik_signature::SealVerificationResult> {
        Ok(MajikSignature::verify_seal(file, mime_type)?)
    }

    pub fn get_seal_info(&self, file: &[u8], mime_type: Option<&str>) -> Result<Option<SealInfo>> {
        Ok(MajikSignature::get_seal_info(file, mime_type)?)
    }

    pub fn is_sealed(&self, file: &[u8], mime_type: Option<&str>) -> Result<bool> {
        Ok(MajikSignature::is_sealed(file, mime_type)?)
    }

    /// Add this account's signature to a file that already carries others (embedded, multi-sig).
    /// The previous signed file is passed so the version chain extends it.
    pub fn resign_file(
        &mut self,
        previous_signed_file: &[u8],
        new_file: &[u8],
        options: &SignFileOptions,
        ctx: &OpContext,
    ) -> Result<SignAndEmbedResult> {
        let mut opts = options.clone();
        opts.prior_signed_file = Some(previous_signed_file.to_vec());
        self.sign_file(new_file, &opts, ctx)
    }

    /// Everything worth showing about a file's signatures in one call.
    pub fn get_file_signature_info(
        &self,
        file: &[u8],
        mime_type: Option<&str>,
    ) -> Result<FileSignatureInfo> {
        let signatures = MajikSignature::extract_from(file, mime_type).unwrap_or_default();
        Ok(FileSignatureInfo {
            is_signed: !signatures.is_empty(),
            signatures: signatures
                .iter()
                .map(|s| FileSignatureSummary {
                    signer_id: s.signer_id().to_string(),
                    signer_label: self.resolve_signer_label(s.signer_id()),
                    content_hash: s.content_hash().to_string(),
                    timestamp: s.timestamp().to_string(),
                    has_tsa: s.has_tsa(),
                    is_expired: s.is_expired(None),
                })
                .collect(),
            envelope: MajikSignature::get_envelope_info(file, mime_type).unwrap_or(None),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FileSignatureSummary {
    pub signer_id: String,
    pub signer_label: String,
    pub content_hash: String,
    pub timestamp: String,
    pub has_tsa: bool,
    pub is_expired: bool,
}

#[derive(Debug, Clone)]
pub struct FileSignatureInfo {
    pub is_signed: bool,
    pub signatures: Vec<FileSignatureSummary>,
    pub envelope: Option<EnvelopeInfo>,
}
