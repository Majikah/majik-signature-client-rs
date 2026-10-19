//! Signing core: the signing-session counter, `with_signing_key`, signer resolution, and the
//! content-level sign/verify methods of `MajikSignatureClient`.
//!
//! Unlocking never prompts. If the account is locked, operations fail with the key client's
//! `unlockRequired` error; the UI collects the passphrase, calls `keys_mut().unlock_account(..)`
//! and retries.

use jiff::Timestamp;
use majik_file::MajikFileIdentity;
use majik_key::{KeyId, MajikKey};
use majik_signature::{
    base64_to_bytes, ExpectedSigner, MajikSignature, MajikSignatureJSON, MajikSignerPublicKeys,
    SignOptions, VerificationResult,
};
use serde::Serialize;

use crate::client::SignatureClient;
use crate::contacts::majik_contact::MajikContact;
use crate::error::{Result, SignatureClientError};
use crate::events::SigOnlyEvent;
use crate::file_identity::identity_from_key;
use crate::logs::types::now_iso;
use crate::logs::{
    CreateHistoryLog, HistorySource, HistoryStatus, HistoryType, LogEnvelope, SignatureOperation,
};

// ─── Context and result types ────────────────────────────────────────────────

/// Which account performs an operation and where the request came from (recorded in history).
#[derive(Debug, Clone)]
pub struct OpContext {
    /// `None` = the active account.
    pub account_id: Option<String>,
    pub source: HistorySource,
}

impl Default for OpContext {
    fn default() -> Self {
        Self {
            account_id: None,
            source: HistorySource::System,
        }
    }
}

impl OpContext {
    pub fn new(source: HistorySource) -> Self {
        Self {
            account_id: None,
            source,
        }
    }
    pub fn with_account(mut self, id: impl Into<String>) -> Self {
        self.account_id = Some(id.into());
        self
    }
}

#[derive(Debug, Clone)]
pub struct SignResult {
    pub signature: MajikSignature,
    pub signer_id: String,
    pub content_hash: String,
    pub timestamp: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignEventPayload {
    pub signature: MajikSignatureJSON,
    pub signer_id: String,
    pub content_hash: String,
    pub timestamp: String,
    pub content_type: Option<String>,
}

impl From<&SignResult> for SignEventPayload {
    fn from(r: &SignResult) -> Self {
        Self {
            signature: r.signature.to_json(),
            signer_id: r.signer_id.clone(),
            content_hash: r.content_hash.clone(),
            timestamp: r.timestamp.clone(),
            content_type: r.content_type.clone(),
        }
    }
}

/// A verification result plus the signer's display label (own account or contact).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResult {
    #[serde(flatten)]
    pub result: VerificationResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_label: Option<String>,
}

/// A signature in any of the forms the TS API accepts.
#[derive(Debug, Clone)]
pub enum SigInput {
    Signature(MajikSignature),
    Json(MajikSignatureJSON),
    /// Base64 `serialize()` output, or a JSON string.
    Serialized(String),
}

impl SigInput {
    pub fn resolve(self) -> Result<MajikSignature> {
        match self {
            Self::Signature(s) => Ok(s),
            Self::Json(j) => Ok(MajikSignature::from_json(&j)?),
            Self::Serialized(s) => match MajikSignature::deserialize(&s) {
                Ok(sig) => Ok(sig),
                Err(_) => Ok(MajikSignature::from_json_str(&s)?),
            },
        }
    }
}

/// Where the verifying public keys come from. Precedence: `key`, `contact_id`, `address`;
/// with none of them the keys are read from the signature itself (self-asserted).
#[derive(Clone, Default)]
pub struct VerifyTarget<'a> {
    pub contact_id: Option<&'a str>,
    /// Base64 X25519 public key of a known contact.
    pub address: Option<&'a str>,
    pub key: Option<&'a MajikKey>,
    pub expected_signer_id: Option<&'a str>,
    pub mime_type: Option<&'a str>,
    pub now: Option<Timestamp>,
}

/// A way to name a signer when building allowlists / expected orders.
#[derive(Clone)]
pub enum SignerRef<'a> {
    Contact(&'a str),
    Expected(ExpectedSigner),
    Key(&'a MajikKey),
}

/// What `with_signing_key` hands back besides the closure's result.
#[derive(Debug)]
pub struct SigningCtx {
    pub fingerprint: String,
    pub identity: Option<MajikFileIdentity>,
}

#[derive(Debug, Clone, Default)]
pub struct ContentSignOptions {
    pub content_type: Option<String>,
    pub timestamp: Option<String>,
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureMetadata {
    pub signer_id: String,
    pub content_hash: String,
    pub content_type: Option<String>,
    pub timestamp: String,
    pub version: u8,
    pub is_expired: bool,
    pub has_tsa: bool,
}

pub(crate) fn invalid_result(reason: &str) -> VerificationResult {
    VerificationResult {
        valid: false,
        signer_id: Some(String::new()),
        content_hash: Some(String::new()),
        timestamp: now_iso(),
        content_type: None,
        handler: None,
        reason: Some(reason.to_string()),
        ..Default::default()
    }
}

/// What a history entry records about an operation.
pub(crate) struct OpNote<'a> {
    pub reference: &'a str,
    pub history_type: HistoryType,
    pub status: HistoryStatus,
    pub source: HistorySource,
    pub detached: bool,
    pub sealed: bool,
    pub tsa: bool,
    pub signer_count: Option<u32>,
    pub valid: Option<bool>,
}

impl<'a> OpNote<'a> {
    pub(crate) fn new(reference: &'a str, history_type: HistoryType, source: HistorySource) -> Self {
        Self {
            reference,
            history_type,
            status: HistoryStatus::Success,
            source,
            detached: false,
            sealed: false,
            tsa: false,
            signer_count: None,
            valid: None,
        }
    }
}

impl SignatureClient {
    // ── Signing session ──────────────────────────────────────────────────────

    pub fn is_signing_session_active(&self) -> bool {
        self.signing_session_depth > 0
    }

    /// Abort a session after a crash: resets the counter and re-locks per the preferences.
    pub fn force_end_signing_session(&mut self) {
        self.signing_session_depth = 0;
        let id = self
            .session_account_id
            .take()
            .or_else(|| self.keys.get_active_account().map(|a| a.id().to_string()));
        if let Some(id) = id {
            self.relock_unless_onetime(&id);
        }
    }

    /// Run `f` with the account unlocked for the whole closure, however many signing operations
    /// it performs. Sessions nest; the account is re-locked (unless one-time unlock is on) when
    /// the outermost session ends, including when `f` fails.
    pub fn with_signing_session<T>(
        &mut self,
        account_id: Option<&str>,
        f: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let id = self.resolve_account_id(account_id)?;
        self.keys.ensure_identity_unlocked(&id)?;
        self.signing_session_depth += 1;
        let outcome = f(self);
        self.signing_session_depth = self.signing_session_depth.saturating_sub(1);
        if self.signing_session_depth == 0 {
            self.relock_unless_onetime(&id);
        }
        outcome
    }

    /// Explicit session for callers that cannot pass a closure (e.g. across IPC): unlock once,
    /// sign as often as needed, then call [`end_signing_session`](Self::end_signing_session).
    /// Sessions nest; the account chosen by the outermost `begin` is the one re-locked at the end.
    pub fn begin_signing_session(&mut self, account_id: Option<&str>) -> Result<()> {
        let id = self.resolve_account_id(account_id)?;
        self.keys.ensure_identity_unlocked(&id)?;
        if self.signing_session_depth == 0 {
            self.session_account_id = Some(id);
        }
        self.signing_session_depth += 1;
        Ok(())
    }

    /// Ends one level of an explicit session; the outermost end re-locks (unless one-time unlock).
    pub fn end_signing_session(&mut self) {
        if self.signing_session_depth == 0 {
            return;
        }
        self.signing_session_depth -= 1;
        if self.signing_session_depth == 0 {
            if let Some(id) = self.session_account_id.take() {
                self.relock_unless_onetime(&id);
            }
        }
    }

    pub(crate) fn resolve_account_id(&self, account_id: Option<&str>) -> Result<String> {
        match account_id {
            Some(id) => Ok(id.to_string()),
            None => self
                .keys
                .get_active_account()
                .map(|a| a.id().to_string())
                .ok_or(SignatureClientError::NoActiveAccount),
        }
    }

    pub(crate) fn relock_unless_onetime(&mut self, id: &str) {
        // Fail closed: if the preferences cannot be read, lock.
        let onetime = self
            .get_user_app_preferences()
            .map(|p| p.is_onetime_unlock_enabled())
            .unwrap_or(false);
        if !onetime {
            self.keys.lock_account(id);
        }
    }

    /// Unlocked, signing-capable key for the duration of `f`. Re-locks afterwards unless a
    /// session is open or one-time unlock is enabled. `want_identity` also builds a
    /// `MajikFileIdentity` (for encrypting log envelopes) while the key is borrowed.
    pub(crate) fn with_signing_key<T>(
        &mut self,
        account_id: Option<&str>,
        want_identity: bool,
        f: impl FnOnce(&MajikKey) -> Result<T>,
    ) -> Result<(T, SigningCtx)> {
        let id = self.resolve_account_id(account_id)?;
        self.keys.ensure_identity_unlocked(&id)?;
        self.signing_session_depth += 1;
        let outcome = (|| -> Result<(T, SigningCtx)> {
            let key = self.keys.key_manager().get(&id).ok_or_else(|| {
                SignatureClientError::Invalid(format!("Account not found in keystore: \"{id}\""))
            })?;
            if !key.has_keys(&[KeyId::Ed25519, KeyId::MlDsa87]) {
                return Err(SignatureClientError::Invalid(
                    "This account has no signing keys. Re-import via \
                     importAccountFromMnemonicBackup() to upgrade it."
                        .into(),
                ));
            }
            let value = f(key)?;
            let ctx = SigningCtx {
                fingerprint: key.fingerprint().to_string(),
                identity: if want_identity {
                    identity_from_key(key).ok()
                } else {
                    None
                },
            };
            Ok((value, ctx))
        })();
        self.signing_session_depth = self.signing_session_depth.saturating_sub(1);
        if self.signing_session_depth == 0 {
            self.relock_unless_onetime(&id);
        }
        outcome
    }

    /// Emit an `error` event if `r` failed, then hand `r` back unchanged.
    pub(crate) fn report<T>(&self, context: &str, r: Result<T>) -> Result<T> {
        if let Err(e) = &r {
            self.emit_error(context, e);
        }
        r
    }

    /// Record one operation in the history (honouring the history preferences).
    pub(crate) fn note_history(
        &mut self,
        fingerprint: Option<&str>,
        note: OpNote<'_>,
        digest: &str,
        envelope: Option<LogEnvelope>,
    ) {
        let mut input = CreateHistoryLog::new(
            note.reference,
            note.history_type,
            note.status,
            note.source,
            SignatureOperation {
                digest: digest.to_string(),
                detached: note.detached,
                sealed: note.sealed,
                tsa: note.tsa,
            },
        );
        input.signer_count = note.signer_count;
        input.valid = note.valid;
        input.envelope = envelope;
        self.record_history(fingerprint, input);
    }

    // ── Signer resolution ────────────────────────────────────────────────────

    /// Public signing keys of an unlocked-or-not own account.
    pub fn get_signing_public_keys(&self, account_id: Option<&str>) -> Result<MajikSignerPublicKeys> {
        let id = self.resolve_account_id(account_id)?;
        let key = self.keys.key_manager().get(&id).ok_or_else(|| {
            SignatureClientError::Invalid(format!("Account not found in keystore: \"{id}\""))
        })?;
        Ok(MajikSignature::public_keys_from_majik_key(key)?)
    }

    pub fn expected_signer_from_key(key: &MajikKey) -> Result<ExpectedSigner> {
        Ok(MajikSignature::expected_signer_from_key(key)?)
    }

    fn contact_to_expected_signer(contact: &MajikContact) -> Result<ExpectedSigner> {
        if contact.ed_public_key_base64().is_empty() || contact.ml_dsa_public_key_base64().is_empty() {
            return Err(SignatureClientError::Invalid(format!(
                "Contact \"{}\" has no signing public keys",
                contact.id()
            )));
        }
        Ok(ExpectedSigner {
            signer_id: contact.fingerprint().to_string(),
            ed_public_key: contact.ed_public_key_base64().to_string(),
            ml_dsa_public_key: contact.ml_dsa_public_key_base64().to_string(),
        })
    }

    fn contact_to_public_keys(contact: &MajikContact) -> Result<MajikSignerPublicKeys> {
        if contact.ed_public_key_base64().is_empty() || contact.ml_dsa_public_key_base64().is_empty() {
            return Err(SignatureClientError::Invalid(format!(
                "Contact \"{}\" has no signing public keys",
                contact.id()
            )));
        }
        Ok(MajikSignerPublicKeys {
            signer_id: contact.fingerprint().to_string(),
            ed_public_key: base64_to_bytes(contact.ed_public_key_base64())?,
            ml_dsa_public_key: base64_to_bytes(contact.ml_dsa_public_key_base64())?,
        })
    }

    /// Turn contacts, raw signers and keys into the `ExpectedSigner`s an allowlist or order needs.
    pub fn build_expected_signers(&self, refs: &[SignerRef<'_>]) -> Result<Vec<ExpectedSigner>> {
        let mut out = Vec::with_capacity(refs.len());
        for r in refs {
            out.push(match r {
                SignerRef::Expected(s) => s.clone(),
                SignerRef::Key(k) => MajikSignature::expected_signer_from_key(k)?,
                SignerRef::Contact(id) => {
                    let contacts = self.shared.lock_contacts()?;
                    let contact = contacts.get_contact(id).ok_or_else(|| {
                        SignatureClientError::Invalid(format!("Contact not found: \"{id}\""))
                    })?;
                    Self::contact_to_expected_signer(contact)?
                }
            });
        }
        Ok(out)
    }

    /// `Ok(None)` when no source is given (the caller then trusts the signature's own keys).
    pub fn resolve_signer_public_keys(
        &self,
        target: &VerifyTarget<'_>,
    ) -> Result<Option<MajikSignerPublicKeys>> {
        if let Some(key) = target.key {
            return Ok(Some(MajikSignature::public_keys_from_majik_key(key)?));
        }
        if let Some(id) = target.contact_id {
            let contacts = self.shared.lock_contacts()?;
            let contact = contacts.get_contact(id).ok_or_else(|| {
                SignatureClientError::Invalid(format!("Contact not found: \"{id}\""))
            })?;
            return Ok(Some(Self::contact_to_public_keys(contact)?));
        }
        if let Some(address) = target.address {
            let contacts = self.shared.lock_contacts()?;
            let contact = contacts.get_contact_by_address(address).ok_or_else(|| {
                SignatureClientError::Invalid("No contact found for that public key".into())
            })?;
            return Ok(Some(Self::contact_to_public_keys(contact)?));
        }
        Ok(None)
    }

    // ── Sign ─────────────────────────────────────────────────────────────────

    /// Sign `content` with the context account's hybrid key.
    pub fn sign(
        &mut self,
        content: &[u8],
        options: Option<&SignOptions>,
        ctx: &OpContext,
    ) -> Result<SignResult> {
        let signed = self.with_signing_key(ctx.account_id.as_deref(), false, |key| {
            Ok(MajikSignature::sign(content, key, options)?)
        });
        let (signature, sctx) = self.report("sign", signed)?;
        let result = SignResult {
            signer_id: signature.signer_id().to_string(),
            content_hash: signature.content_hash().to_string(),
            timestamp: signature.timestamp().to_string(),
            content_type: signature.content_type().map(str::to_string),
            signature,
        };
        self.emit(SigOnlyEvent::Sign(SignEventPayload::from(&result)));
        let reference = result.content_hash.clone();
        self.note_history(
            Some(&sctx.fingerprint),
            OpNote::new(&reference, HistoryType::Sign, ctx.source),
            &reference,
            None,
        );
        Ok(result)
    }

    /// Sign and return the base64 `serialize()` form.
    pub fn sign_and_serialize(
        &mut self,
        content: &[u8],
        options: Option<&SignOptions>,
        ctx: &OpContext,
    ) -> Result<String> {
        Ok(self.sign(content, options, ctx)?.signature.serialize()?)
    }

    pub fn sign_to_json(
        &mut self,
        content: &[u8],
        options: Option<&SignOptions>,
        ctx: &OpContext,
    ) -> Result<MajikSignatureJSON> {
        Ok(self.sign(content, options, ctx)?.signature.to_json())
    }

    pub fn sign_text(
        &mut self,
        text: &str,
        options: Option<&SignOptions>,
        ctx: &OpContext,
    ) -> Result<SignResult> {
        let mut opts = options.cloned().unwrap_or_default();
        if opts.content_type.is_none() {
            opts.content_type = Some("text/plain".to_string());
        }
        self.sign(text.as_bytes(), Some(&opts), ctx)
    }

    /// Sign and produce a detached-signature JSON string (TS `signAndDetach`).
    pub fn sign_and_detach(
        &mut self,
        content: &[u8],
        options: Option<&SignOptions>,
        ctx: &OpContext,
    ) -> Result<String> {
        Ok(self.sign(content, options, ctx)?.signature.to_json_string()?)
    }

    pub fn sign_content(
        &mut self,
        content: &[u8],
        options: &ContentSignOptions,
        ctx: &OpContext,
    ) -> Result<SignResult> {
        let sign_options = SignOptions {
            content_type: options.content_type.clone(),
            timestamp: options.timestamp.clone(),
            valid_until: options.valid_until.clone(),
            ..Default::default()
        };
        self.sign(content, Some(&sign_options), ctx)
    }

    // ── Verify ───────────────────────────────────────────────────────────────

    /// Verify `content` against `signature`. With `public_keys` the signature is checked against
    /// those trusted keys; without them the keys embedded in the signature are used (which only
    /// proves self-consistency, not identity).
    pub fn verify(
        &mut self,
        content: &[u8],
        signature: SigInput,
        public_keys: Option<&MajikSignerPublicKeys>,
        now: Option<Timestamp>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let outcome = (|| -> Result<VerificationResult> {
            let sig = signature.resolve()?;
            let embedded;
            let keys = match public_keys {
                Some(k) => k,
                None => {
                    embedded = sig.extract_public_keys()?;
                    &embedded
                }
            };
            Ok(MajikSignature::verify(content, &sig, keys, now)?)
        })();
        let result = self.report("verify", outcome)?;
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
            note.status = HistoryStatus::Success;
            note.valid = Some(verified.result.valid);
            self.note_history(fp.as_deref(), note, &hash, None);
        }
        Ok(verified)
    }

    /// Verify against one of your own accounts' keys (own keys are always trusted).
    pub fn verify_with_account(
        &mut self,
        content: &[u8],
        signature: SigInput,
        account_id: Option<&str>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let keys = self.get_signing_public_keys(account_id)?;
        self.verify(content, signature, Some(&keys), None, source)
    }

    pub fn verify_with_contact(
        &mut self,
        content: &[u8],
        signature: SigInput,
        contact_id: &str,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let target = VerifyTarget {
            contact_id: Some(contact_id),
            ..Default::default()
        };
        let keys = self.resolve_signer_public_keys(&target)?;
        self.verify(content, signature, keys.as_ref(), None, source)
    }

    /// Verify with whichever source `target` names (see [`VerifyTarget`]).
    pub fn verify_content(
        &mut self,
        content: &[u8],
        signature: SigInput,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        let keys = self.resolve_signer_public_keys(target)?;
        self.verify(content, signature, keys.as_ref(), target.now, source)
    }

    pub fn verify_text(
        &mut self,
        text: &str,
        signature: SigInput,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        self.verify_content(text.as_bytes(), signature, target, source)
    }

    /// `signature` may be base64 `serialize()` output or a JSON string.
    pub fn verify_detached(
        &mut self,
        content: &[u8],
        signature: &str,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Result<VerifyResult> {
        self.verify_content(content, SigInput::Serialized(signature.to_string()), target, source)
    }

    /// Verify many (content, signature) pairs. Individual failures become `Err` entries.
    pub fn verify_batch(
        &mut self,
        items: Vec<(Vec<u8>, SigInput)>,
        target: &VerifyTarget<'_>,
        source: HistorySource,
    ) -> Vec<Result<VerifyResult>> {
        items
            .into_iter()
            .map(|(content, sig)| self.verify_content(&content, sig, target, source))
            .collect()
    }

    pub fn deserialize_signature(&self, serialized: &str) -> Result<MajikSignature> {
        SigInput::Serialized(serialized.to_string()).resolve()
    }

    /// Non-cryptographic summary of a signature (no verification is performed).
    pub fn get_signature_metadata(&self, input: SigInput) -> Result<SignatureMetadata> {
        let sig = input.resolve()?;
        Ok(SignatureMetadata {
            signer_id: sig.signer_id().to_string(),
            content_hash: sig.content_hash().to_string(),
            content_type: sig.content_type().map(str::to_string),
            timestamp: sig.timestamp().to_string(),
            version: sig.version(),
            is_expired: sig.is_expired(None),
            has_tsa: sig.has_tsa(),
        })
    }
}
