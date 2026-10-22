//! One function per IPC operation over a `SignatureClient`. The Tauri plugin is a thin shell that
//! locks the client and calls these. Account-level commands (create / unlock / ...) come from
//! `majik_key_client::ipc`, called on `client.keys_mut()`.

use crate::contacts;
use crate::contacts::majik_contact::{
    MajikContact, MajikContactMeta, SerializedMajikContact, SerializedMajikContactGroup,
};
use jiff::Timestamp;
use majik_key_client::ipc::Snapshot;
use majik_signature::{
    BatchFileInput, BatchSignMode, BatchSignOptions, BatchSignResult, BatchVerifyInput,
    EnvelopeInfo, EnvelopeInput, ExpectedSigner, MajikChainAnchor, MajikSignature,
    MajikSignatureJSON, MajikTimestamp, SealInfo, SignOptions, SignatoriesFilter,
    SignatoriesResult, SignatoryInfo, VerificationResult,
};
use serde::Serialize;

use super::dto::*;
use super::input::{
    deliver, join_output_dir, mime_from_name, BytesOutput, FileInput, IntoMjksig, OutputTarget,
};
use crate::backup::{BackupType, RestoreContactsOptions, SelectiveRestoreOptions};
use crate::client::{HydrateReport, SignatureClient};
use crate::error::{Result, SignatureClientError};
use crate::files::{SignDetachedFileOptions, SignFileOptions};
use crate::logs::{HistoryLog, HistorySource, UserActivityLog};
use crate::mjks::{CosignOptions, MjksMapInput, OrderCheckOptions};
use crate::prefs::UserAppPreferences;
use crate::signing::{SigInput, SignatureMetadata, SignerRef, VerifyResult};
use crate::stamps::{StampAssetKind, StampMeta};

fn invalid(msg: impl Into<String>) -> SignatureClientError {
    SignatureClientError::Invalid(msg.into())
}

// ─── Session ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigOpenedSession {
    /// Present only for the call that actually hydrated.
    pub report: Option<HydrateReport>,
    pub snapshot: Snapshot,
}

pub fn snapshot(c: &SignatureClient) -> Snapshot {
    majik_key_client::ipc::snapshot(c.keys())
}

/// Hydrates once (contacts, logs, stamps, then keys); later calls just snapshot.
pub fn open_session(c: &mut SignatureClient) -> Result<SigOpenedSession> {
    let report = if c.is_hydrated() {
        None
    } else {
        Some(c.hydrate()?)
    };
    Ok(SigOpenedSession {
        report,
        snapshot: snapshot(c),
    })
}

/// Reloads everything from storage. **This re-locks every key.**
pub fn hydrate(c: &mut SignatureClient) -> Result<HydrateReport> {
    c.hydrate()
}

pub fn begin_signing_session(c: &mut SignatureClient, account_id: Option<&str>) -> Result<()> {
    c.begin_signing_session(account_id)
}
pub fn end_signing_session(c: &mut SignatureClient) {
    c.end_signing_session();
}
pub fn force_end_signing_session(c: &mut SignatureClient) {
    c.force_end_signing_session();
}
pub fn is_signing_session_active(c: &SignatureClient) -> bool {
    c.is_signing_session_active()
}

// ─── Preferences & logs ──────────────────────────────────────────────────────

pub fn get_user_app_preferences(c: &mut SignatureClient) -> Result<UserAppPreferences> {
    c.get_user_app_preferences()
}
pub fn set_user_app_preferences(c: &mut SignatureClient, p: UserAppPreferences) -> Result<()> {
    c.set_user_app_preferences(&p)
}
pub fn reset_user_app_preferences(c: &mut SignatureClient) -> Result<()> {
    c.reset_user_app_preferences()
}
pub fn list_history_logs(c: &SignatureClient) -> Vec<HistoryLog> {
    c.list_history_for_active_account()
}
pub fn list_activity_logs(c: &SignatureClient) -> Vec<UserActivityLog> {
    c.list_activity_for_active_account()
}
pub fn clear_history_logs(c: &mut SignatureClient) -> Result<()> {
    c.clear_history_logs_for_active_account()
}
pub fn clear_activity_logs(c: &mut SignatureClient) -> Result<()> {
    c.clear_activity_logs_for_active_account()
}
pub fn restart_logs(c: &mut SignatureClient) -> Result<()> {
    c.restart_logs_for_active_account()
}
pub fn hydrate_logs(c: &mut SignatureClient) -> Result<()> {
    c.hydrate_logs_for_active_account()
}

// ─── Own account meta ────────────────────────────────────────────────────────

pub fn update_account_label(c: &mut SignatureClient, id: &str, label: &str) -> Result<()> {
    c.update_account_label(id, label)
}
pub fn update_own_account_meta(
    c: &mut SignatureClient,
    id: &str,
    meta: MajikContactMeta,
) -> Result<()> {
    c.update_own_account_meta(id, &meta)
}
pub fn resolve_signer_label(c: &SignatureClient, signer_id: &str) -> String {
    c.resolve_signer_label(signer_id)
}
pub fn reset_data(c: &mut SignatureClient) -> Result<()> {
    c.reset_data()
}

// ─── Contacts ────────────────────────────────────────────────────────────────

pub fn list_contacts(
    c: &SignatureClient,
    sorted_by_label: bool,
    majikah_only: bool,
) -> Result<Vec<SerializedMajikContact>> {
    c.with_contacts(|m| {
        m.list_contacts(sorted_by_label, majikah_only)
            .into_iter()
            .map(|x| x.to_json())
            .collect()
    })
}
pub fn get_contact(c: &SignatureClient, id: &str) -> Result<Option<SerializedMajikContact>> {
    c.with_contacts(|m| m.get_contact(id).map(|x| x.to_json()))
}
pub fn get_contact_by_fingerprint(
    c: &SignatureClient,
    fp: &str,
) -> Result<Option<SerializedMajikContact>> {
    c.with_contacts(|m| m.get_contact_by_fingerprint(fp).map(|x| x.to_json()))
}
pub fn get_contact_by_address(
    c: &SignatureClient,
    address: &str,
) -> Result<Option<SerializedMajikContact>> {
    c.with_contacts(|m| m.get_contact_by_address(address).map(|x| x.to_json()))
}
pub fn add_contact(c: &mut SignatureClient, contact: SerializedMajikContact) -> Result<()> {
    let contact = MajikContact::from_json(contact).map_err(contacts::ContactManagerError::from)?;
    c.add_contact(contact)
}
pub fn remove_contact(c: &mut SignatureClient, id: &str) -> Result<()> {
    c.remove_contact(id)
}
pub fn update_contact_meta(
    c: &mut SignatureClient,
    id: &str,
    meta: MajikContactMeta,
) -> Result<()> {
    c.update_contact_meta(id, &meta)
}
pub fn import_contact_from_json(c: &mut SignatureClient, json: &str) -> ApiResponseDto {
    c.import_contact_from_json(json).into()
}
pub fn import_contact_from_string(c: &mut SignatureClient, s: &str) -> ApiResponseDto {
    c.import_contact_from_string(s).into()
}
pub fn export_contact_json(c: &SignatureClient, id: &str) -> Result<Option<String>> {
    c.with_contacts(|m| m.export_contact_as_json(id))?
        .map_err(Into::into)
}
pub fn export_contact_string(c: &SignatureClient, id: &str) -> Result<Option<String>> {
    c.with_contacts(|m| m.export_contact_as_string(id))?
        .map_err(Into::into)
}
pub fn clear_directory(c: &mut SignatureClient) -> Result<()> {
    c.clear_directory()
}
pub fn set_majikah_status(
    c: &SignatureClient,
    id: &str,
    status: bool,
) -> Result<SerializedMajikContact> {
    c.with_contacts(|m| m.set_majikah_status(id, status).map(|x| x.to_json()))?
        .map_err(Into::into)
}
pub fn block_contact(c: &SignatureClient, id: &str) -> Result<SerializedMajikContact> {
    c.with_contacts(|m| m.block_contact(id).map(|x| x.to_json()))?
        .map_err(Into::into)
}
pub fn unblock_contact(c: &SignatureClient, id: &str) -> Result<SerializedMajikContact> {
    c.with_contacts(|m| m.unblock_contact(id).map(|x| x.to_json()))?
        .map_err(Into::into)
}

// ─── Contact groups ──────────────────────────────────────────────────────────

pub fn list_groups(
    c: &SignatureClient,
    include_system: bool,
    sorted_by_name: bool,
) -> Result<Vec<SerializedMajikContactGroup>> {
    c.with_contacts(|m| {
        m.list_groups(include_system, sorted_by_name)
            .into_iter()
            .map(|g| g.to_json())
            .collect()
    })
}
pub fn get_group(c: &SignatureClient, id: &str) -> Result<Option<SerializedMajikContactGroup>> {
    c.with_contacts(|m| m.get_group(id).map(|g| g.to_json()))
}
pub fn get_contacts_in_group(c: &SignatureClient, id: &str) -> Result<Vec<SerializedMajikContact>> {
    c.with_contacts(|m| {
        m.get_contacts_in_group(id)
            .map(|v| v.into_iter().map(|x| x.to_json()).collect::<Vec<_>>())
    })?
    .map_err(Into::into)
}
pub fn create_group(
    c: &mut SignatureClient,
    a: CreateGroupArgs,
) -> Result<SerializedMajikContactGroup> {
    c.create_group(&a.id, &a.name, a.meta, a.initial_member_ids)
}
pub fn remove_group(c: &mut SignatureClient, id: &str) -> Result<ApiResponseDto> {
    Ok(c.remove_group(id)?.into())
}
pub fn update_group_meta(
    c: &mut SignatureClient,
    a: UpdateGroupMetaArgs,
) -> Result<SerializedMajikContactGroup> {
    c.update_group_meta(
        &a.id,
        a.name.as_deref(),
        a.description.as_deref(),
        a.color.as_deref(),
    )
}
pub fn add_contact_to_group(
    c: &mut SignatureClient,
    group_id: &str,
    contact_id: &str,
) -> Result<SerializedMajikContactGroup> {
    c.add_contact_to_group(group_id, contact_id)
}
pub fn add_contacts_to_group(
    c: &mut SignatureClient,
    group_id: &str,
    contact_ids: Vec<String>,
) -> Result<SerializedMajikContactGroup> {
    c.add_contacts_to_group(group_id, &contact_ids)
}
pub fn remove_contact_from_group(
    c: &mut SignatureClient,
    group_id: &str,
    contact_id: &str,
) -> Result<SerializedMajikContactGroup> {
    c.remove_contact_from_group(group_id, contact_id)
}
pub fn move_contact_between_groups(
    c: &mut SignatureClient,
    contact_id: &str,
    from: &str,
    to: &str,
) -> Result<SerializedMajikContactGroup> {
    c.move_contact_between_groups(contact_id, from, to)
}
pub fn add_contact_to_favorites(
    c: &mut SignatureClient,
    contact_id: &str,
) -> Result<SerializedMajikContactGroup> {
    c.add_contact_to_favorites(contact_id)
}
pub fn remove_contact_from_favorites(
    c: &mut SignatureClient,
    contact_id: &str,
) -> Result<SerializedMajikContactGroup> {
    c.remove_contact_from_favorites(contact_id)
}

// ─── Stamps ──────────────────────────────────────────────────────────────────

pub fn create_stamp(c: &mut SignatureClient, a: CreateStampArgs) -> Result<StampMeta> {
    let file = a.input.load()?;
    let mime = a.mime_type.or(file.mime_type.clone());
    let opts = crate::stamps_api::StampOptions {
        mime_type: mime,
        account_id: a.account_id,
    };
    Ok(c.create_stamp(file.bytes, a.kind, &a.name, &opts)?.meta())
}
pub fn list_stamps(c: &SignatureClient, kind: Option<StampAssetKind>) -> Result<Vec<StampMeta>> {
    c.list_stamps(kind)
}
pub fn list_stamps_for_active_account(c: &SignatureClient) -> Result<Vec<StampMeta>> {
    c.list_stamps_for_active_account()
}
pub fn hydrate_stamps(c: &mut SignatureClient) -> Result<Vec<crate::stamps::SkippedStamp>> {
    c.hydrate_stamps_for_active_account()
}
pub fn lock_stamps(c: &mut SignatureClient) -> Result<usize> {
    c.lock_stamps()
}
pub fn get_stamp(c: &SignatureClient, id: &str) -> Result<Option<StampMeta>> {
    c.get_stamp(id)
}
/// Plaintext of a stamp already decrypted into memory; `None` if it is not hydrated.
pub fn get_decrypted_stamp(
    c: &SignatureClient,
    id: &str,
    output: Option<&OutputTarget>,
) -> Result<Option<BytesOutput>> {
    match c.get_decrypted_stamp_bytes(id)? {
        Some(bytes) => Ok(Some(deliver(bytes, output)?)),
        None => Ok(None),
    }
}
pub fn decrypt_stamp_content(
    c: &mut SignatureClient,
    id: &str,
    account_id: Option<&str>,
    output: Option<&OutputTarget>,
) -> Result<BytesOutput> {
    deliver(c.decrypt_stamp_content(id, account_id)?, output)
}
pub fn rename_stamp(c: &mut SignatureClient, id: &str, name: &str) -> Result<StampMeta> {
    c.rename_stamp(id, name)
}
pub fn replace_stamp_content(
    c: &mut SignatureClient,
    id: &str,
    input: FileInput,
    mime_type: Option<String>,
    account_id: Option<&str>,
) -> Result<StampMeta> {
    let file = input.load()?;
    c.replace_stamp_content(id, file.bytes, mime_type.or(file.mime_type), account_id)
}
pub fn remove_stamp(c: &mut SignatureClient, id: &str) -> Result<()> {
    c.remove_stamp(id)
}
pub fn inspect_stamp(c: &SignatureClient, input: &FileInput) -> Result<StampInspectDto> {
    let r = c.inspect_stamp(&input.load()?.bytes);
    Ok(StampInspectDto {
        has_pixel_row: r.has_pixel_row,
        has_dct: r.has_dct,
    })
}
pub fn is_stamped(c: &SignatureClient, input: &FileInput) -> Result<bool> {
    Ok(c.is_stamped(&input.load()?.bytes))
}

// ─── Content signing ─────────────────────────────────────────────────────────

pub fn sign_text(
    c: &mut SignatureClient,
    text: &str,
    options: SignTextOptionsDto,
    ctx: CtxDto,
) -> Result<SignTextDto> {
    let opts = SignOptions {
        content_type: options.content_type,
        timestamp: options.timestamp,
        valid_until: options.valid_until,
        ..Default::default()
    };
    let r = c.sign_text(text, Some(&opts), &ctx.to_ctx())?;
    Ok(SignTextDto {
        serialized: r.signature.serialize()?,
        signature: r.signature.to_json(),
        signer_id: r.signer_id,
        content_hash: r.content_hash,
        timestamp: r.timestamp,
        content_type: r.content_type,
    })
}

pub fn verify_text(c: &mut SignatureClient, a: VerifyTextArgs) -> Result<VerifyResult> {
    let resolved = ResolvedTarget::new(c, &a.target)?;
    let source = a.source.unwrap_or(HistorySource::Gui);
    c.verify_text(
        &a.text,
        SigInput::Serialized(a.signature),
        &resolved.target(None),
        source,
    )
}

pub fn get_signature_metadata(c: &SignatureClient, serialized: &str) -> Result<SignatureMetadata> {
    c.get_signature_metadata(SigInput::Serialized(serialized.to_string()))
}

// ─── File signing ────────────────────────────────────────────────────────────

fn signers(
    c: &SignatureClient,
    refs: &Option<Vec<SignerRefDto>>,
) -> Result<Option<Vec<ExpectedSigner>>> {
    match refs {
        Some(r) => Ok(Some(resolve_signers(c, r)?)),
        None => Ok(None),
    }
}

fn sign_file_options(
    c: &SignatureClient,
    dto: &SignFileOptionsDto,
    file_mime: Option<&str>,
) -> Result<SignFileOptions> {
    let prior = match &dto.prior_signed_file {
        Some(f) => Some(f.load()?.bytes),
        None => None,
    };
    Ok(SignFileOptions {
        content_type: dto.content_type.clone(),
        timestamp: dto.timestamp.clone(),
        mime_type: dto.mime_type.clone().or(file_mime.map(str::to_string)),
        expected_signers: signers(c, &dto.expected_signers)?,
        valid_until: dto.valid_until.clone(),
        prior_signed_file: prior,
        message: dto.message.clone(),
        save_history: dto.save_history,
    })
}

fn detached_options(
    c: &SignatureClient,
    dto: &SignDetachedOptionsDto,
    file_mime: Option<&str>,
) -> Result<SignDetachedFileOptions> {
    let existing = match &dto.existing_envelope {
        Some(f) => Some(EnvelopeInput::Bytes(f.load()?.bytes)),
        None => None,
    };
    Ok(SignDetachedFileOptions {
        content_type: dto.content_type.clone(),
        timestamp: dto.timestamp.clone(),
        mime_type: dto.mime_type.clone().or(file_mime.map(str::to_string)),
        expected_signers: signers(c, &dto.expected_signers)?,
        valid_until: dto.valid_until.clone(),
        existing_envelope: existing,
        tsa: dto.tsa.clone(),
        save_history: dto.save_history,
    })
}

pub fn sign_file(c: &mut SignatureClient, a: SignFileArgs) -> Result<SignedFileDto> {
    let file = a.input.load()?;
    let opts = sign_file_options(c, &a.options, file.mime_type.as_deref())?;
    let r = c.sign_file(&file.bytes, &opts, &a.ctx.to_ctx())?;
    Ok(SignedFileDto {
        file: deliver(r.blob, a.output.as_ref())?,
        signature: r.signature.to_json(),
        handler: r.handler,
        mime_type: r.mime_type,
    })
}

pub fn sign_file_detached(
    c: &mut SignatureClient,
    a: SignDetachedArgs,
) -> Result<DetachedSignedDto> {
    let file = a.input.load()?;
    let opts = detached_options(c, &a.options, file.mime_type.as_deref())?;
    let r = c.sign_file_detached(&file.bytes, &opts, &a.ctx.to_ctx())?;
    let envelope = deliver(
        r.envelope.to_mjksig_bytes().into_mjksig()?,
        a.output.as_ref(),
    )?;
    let stripped = match &a.stripped_output {
        Some(t) => Some(deliver(r.blob.clone(), Some(t))?),
        None => None,
    };
    Ok(DetachedSignedDto {
        envelope,
        stripped,
        signature: r.signature.to_json(),
        handler: r.handler,
        mime_type: r.mime_type,
    })
}

pub fn resign_file(c: &mut SignatureClient, a: ResignArgs) -> Result<SignedFileDto> {
    let previous = a.previous_signed_file.load()?;
    let new_file = a.new_file.load()?;
    let opts = sign_file_options(c, &a.options, new_file.mime_type.as_deref())?;
    let r = c.resign_file(&previous.bytes, &new_file.bytes, &opts, &a.ctx.to_ctx())?;
    Ok(SignedFileDto {
        file: deliver(r.blob, a.output.as_ref())?,
        signature: r.signature.to_json(),
        handler: r.handler,
        mime_type: r.mime_type,
    })
}

/// Sign several files under one unlock; each is written to `<outputDir>/<its file name>`.
pub fn batch_sign_files(
    c: &mut SignatureClient,
    a: BatchSignFilesArgs,
) -> Result<Vec<BatchSignOutcomeDto>> {
    let mut outcomes: Vec<BatchSignOutcomeDto> = Vec::new();
    let mut batch: Vec<(String, Vec<u8>, Option<String>)> = Vec::new();
    for (i, input) in a.inputs.iter().enumerate() {
        match input.load() {
            Ok(f) => batch.push((
                f.name.clone().unwrap_or_else(|| format!("file-{i}")),
                f.bytes,
                f.mime_type,
            )),
            Err(e) => outcomes.push(BatchSignOutcomeDto {
                name: format!("file-{i}"),
                ok: false,
                output: None,
                error: Some(e.to_string()),
            }),
        }
    }
    let opts = sign_file_options(c, &a.options, None)?;
    let results = c.batch_sign_files(&batch, &opts, &a.ctx.to_ctx())?;
    for r in results {
        let target = join_output_dir(&a.output_dir, &r.path).map(|p| OutputTarget {
            path: Some(p),
            overwrite: a.overwrite,
        });
        outcomes.push(match (r.result, target) {
            (Ok(signed), Ok(t)) => match deliver(signed.blob, Some(&t)) {
                Ok(out) => BatchSignOutcomeDto {
                    name: r.path,
                    ok: true,
                    output: Some(out),
                    error: None,
                },
                Err(e) => BatchSignOutcomeDto {
                    name: r.path,
                    ok: false,
                    output: None,
                    error: Some(e.to_string()),
                },
            },
            (Err(message), _) => BatchSignOutcomeDto {
                name: r.path,
                ok: false,
                output: None,
                error: Some(message),
            },
            (Ok(_), Err(e)) => BatchSignOutcomeDto {
                name: r.path,
                ok: false,
                output: None,
                error: Some(e.to_string()),
            },
        });
    }
    Ok(outcomes)
}

// ─── Two-step trusted timestamp ──────────────────────────────────────────────

pub fn begin_sign_file_with_tsa(c: &mut SignatureClient, a: SignFileArgs) -> Result<TsaBeginDto> {
    let file = a.input.load()?;
    let opts = sign_file_options(c, &a.options, file.mime_type.as_deref())?;
    let (token, request) = c.begin_sign_file_with_tsa(&file.bytes, &opts, &a.ctx.to_ctx())?;
    Ok(TsaBeginDto {
        token,
        tsa_request: request,
    })
}

pub fn complete_sign_file_with_tsa(
    c: &mut SignatureClient,
    token: &str,
    timestamp: MajikTimestamp,
    output: Option<&OutputTarget>,
) -> Result<SignedFileDto> {
    let done = c.complete_sign_file_with_tsa(token, timestamp)?;
    let mime = done
        .signature
        .content_type()
        .unwrap_or_default()
        .to_string();
    Ok(SignedFileDto {
        file: deliver(done.blob, output)?,
        signature: done.signature.to_json(),
        handler: String::new(),
        mime_type: mime,
    })
}

pub fn begin_sign_file_detached_with_tsa(
    c: &mut SignatureClient,
    a: SignDetachedArgs,
) -> Result<TsaBeginDto> {
    let file = a.input.load()?;
    let opts = detached_options(c, &a.options, file.mime_type.as_deref())?;
    let (token, request) =
        c.begin_sign_file_detached_with_tsa(&file.bytes, &opts, &a.ctx.to_ctx())?;
    Ok(TsaBeginDto {
        token,
        tsa_request: request,
    })
}

pub fn complete_sign_file_detached_with_tsa(
    c: &mut SignatureClient,
    token: &str,
    timestamp: MajikTimestamp,
    output: Option<&OutputTarget>,
) -> Result<DetachedSignedDto> {
    let done = c.complete_sign_file_detached_with_tsa(token, timestamp)?;
    Ok(DetachedSignedDto {
        envelope: deliver(done.envelope.to_mjksig_bytes().into_mjksig()?, output)?,
        stripped: None,
        signature: done.signature.to_json(),
        handler: String::new(),
        mime_type: String::new(),
    })
}

pub fn cancel_pending_tsa(c: &mut SignatureClient, token: &str) {
    c.cancel_pending_tsa(token);
}

// ─── Verify ──────────────────────────────────────────────────────────────────

pub fn verify_file(c: &mut SignatureClient, a: VerifyFileArgs) -> Result<VerifyResult> {
    let file = a.input.load()?;
    let resolved = ResolvedTarget::new(c, &a.target)?;
    c.verify_file(
        &file.bytes,
        &resolved.target(file.mime_type.as_deref()),
        a.source.unwrap_or(HistorySource::Gui),
    )
}

pub fn verify_file_all_signatures(
    c: &mut SignatureClient,
    a: VerifyFileArgs,
) -> Result<Vec<VerifyResult>> {
    let file = a.input.load()?;
    let resolved = ResolvedTarget::new(c, &a.target)?;
    c.verify_file_all_signatures(
        &file.bytes,
        &resolved.target(file.mime_type.as_deref()),
        a.source.unwrap_or(HistorySource::Gui),
    )
}

pub fn verify_file_detached(
    c: &mut SignatureClient,
    a: VerifyDetachedArgs,
) -> Result<VerifyResult> {
    let file = a.input.load()?;
    let envelope = EnvelopeInput::Bytes(a.envelope.load()?.bytes);
    let resolved = ResolvedTarget::new(c, &a.target)?;
    c.verify_file_detached(
        &file.bytes,
        envelope,
        &resolved.target(file.mime_type.as_deref()),
        a.source.unwrap_or(HistorySource::Gui),
    )
}

pub fn verify_file_detached_all_signatures(
    c: &mut SignatureClient,
    a: VerifyDetachedArgs,
) -> Result<Vec<VerifyResult>> {
    let file = a.input.load()?;
    let envelope = EnvelopeInput::Bytes(a.envelope.load()?.bytes);
    let resolved = ResolvedTarget::new(c, &a.target)?;
    c.verify_file_detached_all_signatures(
        &file.bytes,
        envelope,
        &resolved.target(file.mime_type.as_deref()),
        a.source.unwrap_or(HistorySource::Gui),
    )
}

pub fn verify_file_chain(
    c: &SignatureClient,
    input: &FileInput,
    now: Option<&str>,
) -> Result<ChainDto> {
    let file = input.load()?;
    let now = parse_now(now)?;
    let r = c.verify_file_chain(&file.bytes, file.mime_type.as_deref(), now)?;
    Ok(ChainDto {
        latest: r.latest,
        history: r.history,
        chain_valid: r.chain_valid,
    })
}

pub fn verify_file_revisions(
    c: &SignatureClient,
    final_file: &FileInput,
    revisions: &[FileInput],
) -> Result<RevisionSetDto> {
    let last = final_file.load()?;
    let loaded: Vec<Vec<u8>> = revisions
        .iter()
        .map(|r| r.load().map(|f| f.bytes))
        .collect::<Result<_>>()?;
    let refs: Vec<&[u8]> = loaded.iter().map(|v| v.as_slice()).collect();
    let opts = majik_signature::VerifyRevisionsOptions {
        mime_type: last.mime_type.clone(),
        now: None,
        resolve_public_keys: None,
    };
    let r = c.verify_file_revisions(&last.bytes, &refs, Some(opts))?;
    Ok(RevisionSetDto {
        all_valid: r.all_valid,
        is_complete_set: r.is_complete_set,
        results: r
            .results
            .into_iter()
            .map(|x| RevisionCheckDto {
                version: x.version,
                status: x.status,
                signer_id: x.signer_id,
                reason: x.reason,
            })
            .collect(),
    })
}

fn parse_now(now: Option<&str>) -> Result<Option<Timestamp>> {
    match now {
        Some(s) => s
            .parse::<Timestamp>()
            .map(Some)
            .map_err(|_| invalid(format!("Invalid \"now\" timestamp: {s}"))),
        None => Ok(None),
    }
}

// ─── Inspect / seal ──────────────────────────────────────────────────────────

pub fn extract_signatures(
    c: &SignatureClient,
    input: &FileInput,
) -> Result<Vec<MajikSignatureJSON>> {
    let file = input.load()?;
    Ok(c.extract_signature(&file.bytes, file.mime_type.as_deref())?
        .iter()
        .map(MajikSignature::to_json)
        .collect())
}
pub fn strip_signature(
    c: &SignatureClient,
    input: &FileInput,
    output: Option<&OutputTarget>,
) -> Result<BytesOutput> {
    let file = input.load()?;
    deliver(
        c.strip_signature(&file.bytes, file.mime_type.as_deref())?,
        output,
    )
}
pub fn is_file_signed(c: &SignatureClient, input: &FileInput) -> Result<bool> {
    let f = input.load()?;
    c.is_file_signed(&f.bytes, f.mime_type.as_deref())
}
pub fn get_allowlist(
    c: &SignatureClient,
    input: &FileInput,
) -> Result<Option<Vec<ExpectedSigner>>> {
    let f = input.load()?;
    c.get_allowlist(&f.bytes, f.mime_type.as_deref())
}
pub fn can_sign(
    c: &SignatureClient,
    input: &FileInput,
    account_id: Option<&str>,
) -> Result<PermitDto> {
    let f = input.load()?;
    let r = c.can_sign(&f.bytes, account_id, f.mime_type.as_deref())?;
    Ok(PermitDto {
        permitted: r.permitted,
        reason: r.reason,
    })
}
pub fn is_multi_sig(c: &SignatureClient, input: &FileInput) -> Result<bool> {
    let f = input.load()?;
    c.is_multi_sig(&f.bytes, f.mime_type.as_deref())
}
pub fn get_signatories(
    c: &SignatureClient,
    input: &FileInput,
    filter: Option<SignatoriesFilter>,
) -> Result<Option<SignatoriesResult>> {
    let f = input.load()?;
    c.get_signatories(&f.bytes, f.mime_type.as_deref(), filter)
}
pub fn get_issuer(c: &SignatureClient, input: &FileInput) -> Result<Option<SignatoryInfo>> {
    let f = input.load()?;
    c.get_issuer(&f.bytes, f.mime_type.as_deref())
}
pub fn get_envelope_info(c: &SignatureClient, input: &FileInput) -> Result<Option<EnvelopeInfo>> {
    let f = input.load()?;
    c.get_envelope_info(&f.bytes, f.mime_type.as_deref())
}
pub fn get_file_signature_info(
    c: &SignatureClient,
    input: &FileInput,
) -> Result<FileSignatureInfoDto> {
    let f = input.load()?;
    let info = c.get_file_signature_info(&f.bytes, f.mime_type.as_deref())?;
    Ok(FileSignatureInfoDto {
        is_signed: info.is_signed,
        signatures: info
            .signatures
            .into_iter()
            .map(|s| FileSignatureSummaryDto {
                signer_id: s.signer_id,
                signer_label: s.signer_label,
                content_hash: s.content_hash,
                timestamp: s.timestamp,
                has_tsa: s.has_tsa,
                is_expired: s.is_expired,
            })
            .collect(),
        envelope: info.envelope,
    })
}

pub fn seal(
    c: &mut SignatureClient,
    input: &FileInput,
    output: Option<&OutputTarget>,
    ctx: CtxDto,
) -> Result<SealedFileDto> {
    let f = input.load()?;
    let r = c.seal(&f.bytes, f.mime_type.as_deref(), None, &ctx.to_ctx())?;
    Ok(SealedFileDto {
        file: deliver(r.blob, output)?,
        seal_info: r.seal_info,
        handler: r.handler,
        mime_type: r.mime_type,
    })
}
pub fn verify_seal(
    c: &SignatureClient,
    input: &FileInput,
) -> Result<majik_signature::SealVerificationResult> {
    let f = input.load()?;
    c.verify_seal(&f.bytes, f.mime_type.as_deref())
}
pub fn get_seal_info(c: &SignatureClient, input: &FileInput) -> Result<Option<SealInfo>> {
    let f = input.load()?;
    c.get_seal_info(&f.bytes, f.mime_type.as_deref())
}
pub fn is_sealed(c: &SignatureClient, input: &FileInput) -> Result<bool> {
    let f = input.load()?;
    c.is_sealed(&f.bytes, f.mime_type.as_deref())
}

// ─── Notary helpers (the HTTP lives in TypeScript) ───────────────────────────

pub fn can_anchor(input: &FileInput) -> Result<PermitDto> {
    let f = input.load()?;
    let r = MajikSignature::can_anchor(&f.bytes, f.mime_type.as_deref())?;
    Ok(PermitDto {
        permitted: r.permitted,
        reason: r.reason,
    })
}
pub fn register_chain_anchor(
    input: &FileInput,
    anchor: MajikChainAnchor,
    output: Option<&OutputTarget>,
) -> Result<BytesOutput> {
    let f = input.load()?;
    deliver(
        MajikSignature::register_chain_anchor(&f.bytes, anchor, f.mime_type.as_deref())?,
        output,
    )
}

// ─── Signature maps & ordering ───────────────────────────────────────────────

fn batch_files(inputs: &[FileInput]) -> Result<Vec<BatchFileInput>> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let f = input.load()?;
            let path = match input {
                FileInput::Path { path, .. } => path.clone(),
                FileInput::Bytes { name, .. } => {
                    name.clone().unwrap_or_else(|| format!("file-{i}"))
                }
            };
            Ok(BatchFileInput {
                path,
                blob: f.bytes,
                mime_type: f.mime_type,
            })
        })
        .collect()
}

fn verify_inputs(inputs: &[FileInput]) -> Result<Vec<BatchVerifyInput>> {
    Ok(batch_files(inputs)?
        .into_iter()
        .map(|b| BatchVerifyInput {
            path: b.path,
            blob: b.blob,
        })
        .collect())
}

fn failures(list: &[majik_signature::BatchSignFailure]) -> Vec<FailureDto> {
    list.iter()
        .map(|f| FailureDto {
            path: f.path.clone(),
            error: f.error.clone(),
        })
        .collect()
}

pub fn describe_mjks_map(c: &SignatureClient, input: &FileInput) -> Result<Vec<MapFileInfoDto>> {
    let map = MjksMapInput::Bytes(input.load()?.bytes);
    Ok(c.describe_mjks_map(map)?
        .into_iter()
        .map(|i| MapFileInfoDto {
            path: i.path,
            content_hash: i.content_hash,
            size: i.size,
            mime_type: i.mime_type,
            info: i.info,
        })
        .collect())
}

pub fn is_mjks_map(c: &SignatureClient, input: &FileInput) -> Result<bool> {
    Ok(c.is_mjks_map(&input.load()?.bytes))
}

pub fn sign_batch_detached(
    c: &mut SignatureClient,
    a: BatchDetachedArgs,
) -> Result<BatchDetachedDto> {
    let files = batch_files(&a.inputs)?;
    let mode = match a.options.mode.unwrap_or(BatchModeDto::Map) {
        BatchModeDto::Map => BatchSignMode::Map,
        BatchModeDto::Separate => BatchSignMode::Separate,
    };
    let options = BatchSignOptions {
        content_type: a.options.content_type.clone(),
        timestamp: a.options.timestamp.clone(),
        expected_signers: signers(c, &a.options.expected_signers)?,
        valid_until: a.options.valid_until.clone(),
        mode: Some(mode),
        continue_on_error: a.options.continue_on_error,
    };
    let result = c.sign_batch_detached(&files, &options, &a.ctx.to_ctx())?;
    match result {
        BatchSignResult::Map {
            map_blob,
            failures: f,
            ..
        } => Ok(BatchDetachedDto {
            map: Some(deliver(map_blob, a.map_output.as_ref())?),
            signatures: Vec::new(),
            failures: failures(&f),
        }),
        BatchSignResult::Separate {
            signatures,
            failures: f,
        } => {
            let dir = a
                .output_dir
                .as_deref()
                .ok_or_else(|| invalid("outputDir is required when mode is \"separate\""))?;
            let mut out = Vec::new();
            for s in signatures {
                let name = format!(
                    "{}.mjksig",
                    std::path::Path::new(&s.path)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("signature")
                );
                let target = OutputTarget {
                    path: Some(join_output_dir(dir, &name)?),
                    overwrite: a.overwrite,
                };
                out.push(SeparateSignatureDto {
                    path: s.path,
                    output: deliver(s.blob, Some(&target))?,
                });
            }
            Ok(BatchDetachedDto {
                map: None,
                signatures: out,
                failures: failures(&f),
            })
        }
    }
}

pub fn cosign_mjks_map(c: &mut SignatureClient, a: CosignArgs) -> Result<CosignDto> {
    let map = MjksMapInput::Bytes(a.map.load()?.bytes);
    let files = verify_inputs(&a.files)?;
    let options = CosignOptions {
        valid_until: a.valid_until,
        continue_on_error: a.continue_on_error,
    };
    let r = c.cosign_mjks_map(map, &files, &options, &a.ctx.to_ctx())?;
    Ok(CosignDto {
        map: deliver(r.map_blob, a.output.as_ref())?,
        failures: failures(&r.failures),
    })
}

pub fn verify_mjks_map(c: &mut SignatureClient, a: VerifyMapArgs) -> Result<MapVerifyDto> {
    let map = MjksMapInput::Bytes(a.map.load()?.bytes);
    let files = verify_inputs(&a.files)?;
    let resolved = ResolvedTarget::new(c, &a.target)?;
    let r = c.verify_mjks_map(
        map,
        &files,
        &resolved.target(None),
        a.require_all_present,
        a.source.unwrap_or(HistorySource::Gui),
    )?;
    Ok(MapVerifyDto {
        results: r
            .results
            .into_iter()
            .map(|x| FileVerifyDto {
                path: x.path,
                status: x.status,
                results: x.results,
                reason: x.reason,
                relocated_from: x.relocated_from,
            })
            .collect(),
        summary: BatchSummaryDto {
            total: r.summary.total,
            verified: r.summary.verified,
            invalid: r.summary.invalid,
            tampered: r.summary.tampered,
            not_in_map: r.summary.not_in_map,
            all_valid: r.summary.all_valid,
        },
        missing_from_batch: r.missing_from_batch,
    })
}

pub fn verify_file_order(
    c: &mut SignatureClient,
    a: OrderArgs,
) -> Result<majik_signature::SignatureOrderResult> {
    let file = a.input.load()?;
    let expected = resolve_signers(c, &a.expected)?;
    let refs: Vec<SignerRef<'_>> = expected.iter().cloned().map(SignerRef::Expected).collect();
    let opts = OrderCheckOptions {
        mime_type: file.mime_type.clone(),
        strict: a.strict,
    };
    let source = a.source.unwrap_or(HistorySource::Gui);
    match &a.envelope {
        None => c.verify_file_order(&file.bytes, &refs, &opts, source),
        Some(env) => c.verify_file_detached_order(
            &file.bytes,
            EnvelopeInput::Bytes(env.load()?.bytes),
            &refs,
            &opts,
            source,
        ),
    }
}

pub fn verify_mjks_map_order(
    c: &mut SignatureClient,
    map: &FileInput,
    files: &[FileInput],
    expected: &[SignerRefDto],
    strict: bool,
    source: Option<HistorySource>,
) -> Result<Vec<MapOrderDto>> {
    let map = MjksMapInput::Bytes(map.load()?.bytes);
    let batch = verify_inputs(files)?;
    let signers_list = resolve_signers(c, expected)?;
    let for_path = |_: &str| signers_list.clone();
    Ok(c.verify_mjks_map_order(
        map,
        &batch,
        &for_path,
        strict,
        source.unwrap_or(HistorySource::Gui),
    )?
    .into_iter()
    .map(|r| MapOrderDto {
        path: r.path,
        resolve_status: r.resolve_status,
        order: r.order,
        reason: r.reason,
    })
    .collect())
}

// ─── Backups ─────────────────────────────────────────────────────────────────

pub fn backup_contacts(c: &SignatureClient, output: Option<&OutputTarget>) -> Result<BytesOutput> {
    deliver(c.backup_contacts()?, output)
}
pub fn backup_stamps(c: &SignatureClient, output: Option<&OutputTarget>) -> Result<BytesOutput> {
    deliver(c.backup_stamps()?, output)
}
pub fn backup_app_data(
    c: &mut SignatureClient,
    output: Option<&OutputTarget>,
) -> Result<BytesOutput> {
    deliver(c.backup_app_data()?, output)
}
pub fn probe_backup_type(input: &FileInput) -> Result<BackupType> {
    Ok(SignatureClient::probe_backup_type(&input.load()?.bytes))
}
pub fn read_app_data_backup(c: &SignatureClient, input: &FileInput) -> Result<AppDataSummaryDto> {
    let snap = c.read_app_data_backup(&input.load()?.bytes)?;
    Ok(AppDataSummaryDto {
        contacts: snap.contacts.iter().map(|x| x.to_json()).collect(),
        groups: snap.groups.iter().map(|g| g.to_json()).collect(),
        stamps: snap
            .stamps
            .iter()
            .filter_map(|s| crate::stamps::MajikSignatureStamp::from_json(s.clone()).ok())
            .map(|s| s.meta())
            .collect(),
        preferences: snap.preferences,
    })
}
pub fn restore_contacts(
    c: &mut SignatureClient,
    input: &FileInput,
    overwrite_contacts: bool,
    include_groups: bool,
) -> Result<crate::backup::RestoredContacts> {
    c.restore_contacts(
        &input.load()?.bytes,
        RestoreContactsOptions {
            overwrite_contacts,
            include_groups,
        },
    )
}
pub fn restore_stamps(c: &mut SignatureClient, input: &FileInput) -> Result<usize> {
    c.restore_stamps(&input.load()?.bytes)
}
pub fn restore_app_data(
    c: &mut SignatureClient,
    input: &FileInput,
) -> Result<crate::backup::RestoredAppData> {
    c.restore_app_data(&input.load()?.bytes)
}
pub fn restore_app_data_selective(
    c: &mut SignatureClient,
    input: &FileInput,
    options: SelectiveRestoreDto,
) -> Result<crate::backup::RestoredSelective> {
    let snapshot = c.read_app_data_backup(&input.load()?.bytes)?;
    c.restore_app_data_selective(
        snapshot,
        SelectiveRestoreOptions {
            stamps: options.stamps,
            contacts: options.contacts,
            groups: options.groups,
            preferences: options.preferences,
            overwrite_contacts: options.overwrite_contacts,
        },
    )
}

#[allow(dead_code)]
fn _unused(_: VerificationResult, _: Option<&str>) {
    let _ = mime_from_name;
}
