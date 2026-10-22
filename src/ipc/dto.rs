//! Wire types for the signature client IPC (camelCase JSON). File arguments use
//! [`FileInput`]; file results use [`BytesOutput`].

use crate::contacts;
use crate::contacts::majik_contact::{
    MajikContactMeta, PartialMajikContactGroupMeta, SerializedMajikContact,
    SerializedMajikContactGroup,
};
use jiff::Timestamp;
use majik_signature::{
    EnvelopeInfo, ExpectedSigner, FileVerifyStatus, MajikSignatureJSON, MajikSignerPublicKeys,
    MajikTimestamp, SealInfo, VerificationResult,
};
use serde::{Deserialize, Serialize};

use super::input::{BytesOutput, FileInput, OutputTarget};
use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::logs::HistorySource;
use crate::prefs::UserAppPreferences;
use crate::signing::{OpContext, SignerRef, VerifyTarget};
use crate::stamps::{StampAssetKind, StampMeta};

// ─── Shared args ─────────────────────────────────────────────────────────────

/// Which account acts and where the request came from (default source: `gui`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CtxDto {
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

impl CtxDto {
    pub fn source(&self) -> HistorySource {
        self.source.unwrap_or(HistorySource::Gui)
    }
    pub fn to_ctx(&self) -> OpContext {
        OpContext {
            account_id: self.account_id.clone(),
            source: self.source(),
        }
    }
}

/// Where trusted verification keys come from (see `VerifyTarget`). `accountId` = one of your own
/// accounts; `contactId` / `address` = a contact; none = the signature's own embedded keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyTargetDto {
    #[serde(default)]
    pub contact_id: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub expected_signer_id: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    /// ISO timestamp to verify "as of".
    #[serde(default)]
    pub now: Option<String>,
}

/// A [`VerifyTargetDto`] with its keys and timestamp resolved, so it can lend a `VerifyTarget`.
pub struct ResolvedTarget {
    own_keys: Option<MajikSignerPublicKeys>,
    dto: VerifyTargetDto,
    now: Option<Timestamp>,
}

impl ResolvedTarget {
    pub fn new(c: &SignatureClient, dto: &VerifyTargetDto) -> Result<Self> {
        let own_keys = match dto.account_id.as_deref() {
            Some(id) => Some(c.get_signing_public_keys(Some(id))?),
            None => None,
        };
        let now = match dto.now.as_deref() {
            Some(s) => Some(s.parse::<Timestamp>().map_err(|_| {
                SignatureClientError::Invalid(format!("Invalid \"now\" timestamp: {s}"))
            })?),
            None => None,
        };
        Ok(Self {
            own_keys,
            dto: dto.clone(),
            now,
        })
    }

    /// `file_mime` is the loaded file's MIME type, used when the target names none.
    pub fn target<'a>(&'a self, file_mime: Option<&'a str>) -> VerifyTarget<'a> {
        VerifyTarget {
            public_keys: self.own_keys.as_ref(),
            contact_id: self.dto.contact_id.as_deref(),
            address: self.dto.address.as_deref(),
            key: None,
            expected_signer_id: self.dto.expected_signer_id.as_deref(),
            mime_type: self.dto.mime_type.as_deref().or(file_mime),
            now: self.now,
        }
    }
}

/// A signer in an allowlist / expected order.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum SignerRefDto {
    Contact { contact_id: String },
    Account { account_id: String },
    Expected(ExpectedSigner),
}

pub fn resolve_signers(c: &SignatureClient, refs: &[SignerRefDto]) -> Result<Vec<ExpectedSigner>> {
    let mut out = Vec::with_capacity(refs.len());
    for r in refs {
        out.push(match r {
            SignerRefDto::Expected(e) => e.clone(),
            SignerRefDto::Contact { contact_id } => c
                .build_expected_signers(&[SignerRef::Contact(contact_id)])?
                .remove(0),
            SignerRefDto::Account { account_id } => {
                let key = c.keys().key_manager().get(account_id).ok_or_else(|| {
                    SignatureClientError::Invalid(format!("Account not found: \"{account_id}\""))
                })?;
                SignatureClient::expected_signer_from_key(key)?
            }
        });
    }
    Ok(out)
}

// ─── Signing args ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignFileOptionsDto {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub expected_signers: Option<Vec<SignerRefDto>>,
    #[serde(default)]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub prior_signed_file: Option<FileInput>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub save_history: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignDetachedOptionsDto {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub expected_signers: Option<Vec<SignerRefDto>>,
    #[serde(default)]
    pub valid_until: Option<String>,
    /// An existing `.mjksig` to co-sign.
    #[serde(default)]
    pub existing_envelope: Option<FileInput>,
    #[serde(default)]
    pub tsa: Option<MajikTimestamp>,
    #[serde(default)]
    pub save_history: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignFileArgs {
    pub input: FileInput,
    #[serde(default)]
    pub output: Option<OutputTarget>,
    #[serde(default)]
    pub options: SignFileOptionsDto,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignDetachedArgs {
    pub input: FileInput,
    /// The `.mjksig` envelope.
    #[serde(default)]
    pub output: Option<OutputTarget>,
    /// The original with any embedded signatures stripped (rarely needed).
    #[serde(default)]
    pub stripped_output: Option<OutputTarget>,
    #[serde(default)]
    pub options: SignDetachedOptionsDto,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResignArgs {
    pub previous_signed_file: FileInput,
    pub new_file: FileInput,
    #[serde(default)]
    pub output: Option<OutputTarget>,
    #[serde(default)]
    pub options: SignFileOptionsDto,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSignFilesArgs {
    pub inputs: Vec<FileInput>,
    pub output_dir: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub options: SignFileOptionsDto,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTextOptionsDto {
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub valid_until: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyFileArgs {
    pub input: FileInput,
    #[serde(default)]
    pub target: VerifyTargetDto,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyDetachedArgs {
    pub input: FileInput,
    pub envelope: FileInput,
    #[serde(default)]
    pub target: VerifyTargetDto,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyTextArgs {
    pub text: String,
    /// Base64 `serialize()` output or a JSON string.
    pub signature: String,
    #[serde(default)]
    pub target: VerifyTargetDto,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderArgs {
    pub input: FileInput,
    /// For detached order checks.
    #[serde(default)]
    pub envelope: Option<FileInput>,
    pub expected: Vec<SignerRefDto>,
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

// ─── Map / batch args ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BatchModeDto {
    Map,
    Separate,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDetachedOptionsDto {
    #[serde(default)]
    pub mode: Option<BatchModeDto>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub expected_signers: Option<Vec<SignerRefDto>>,
    #[serde(default)]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub continue_on_error: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDetachedArgs {
    pub inputs: Vec<FileInput>,
    /// Map mode: where the `.mjksmap` goes. Separate mode: unused.
    #[serde(default)]
    pub map_output: Option<OutputTarget>,
    /// Separate mode: folder for the `<name>.mjksig` files.
    #[serde(default)]
    pub output_dir: Option<String>,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub options: BatchDetachedOptionsDto,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignArgs {
    pub map: FileInput,
    pub files: Vec<FileInput>,
    #[serde(default)]
    pub output: Option<OutputTarget>,
    #[serde(default)]
    pub valid_until: Option<String>,
    #[serde(default)]
    pub continue_on_error: bool,
    #[serde(default)]
    pub ctx: CtxDto,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyMapArgs {
    pub map: FileInput,
    pub files: Vec<FileInput>,
    #[serde(default)]
    pub target: VerifyTargetDto,
    #[serde(default)]
    pub require_all_present: bool,
    #[serde(default)]
    pub source: Option<HistorySource>,
}

// ─── Stamp args ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateStampArgs {
    pub input: FileInput,
    pub kind: StampAssetKind,
    pub name: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub account_id: Option<String>,
}

// ─── Contact / group args ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGroupArgs {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub meta: Option<PartialMajikContactGroupMeta>,
    #[serde(default)]
    pub initial_member_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupMetaArgs {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub color: Option<String>,
}

// ─── Results ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiResponseDto {
    pub success: bool,
    pub message: String,
}

impl From<contacts::majik_contact::MajikApiResponse> for ApiResponseDto {
    fn from(r: contacts::majik_contact::MajikApiResponse) -> Self {
        Self {
            success: r.success,
            message: r.message,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedFileDto {
    pub file: BytesOutput,
    pub signature: MajikSignatureJSON,
    pub handler: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DetachedSignedDto {
    pub envelope: BytesOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stripped: Option<BytesOutput>,
    pub signature: MajikSignatureJSON,
    pub handler: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignTextDto {
    pub signature: MajikSignatureJSON,
    /// Base64 `serialize()` form, ready to store or send.
    pub serialized: String,
    pub signer_id: String,
    pub content_hash: String,
    pub timestamp: String,
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PermitDto {
    pub permitted: bool,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainDto {
    pub latest: VerificationResult,
    pub history: Vec<majik_signature::RevisionCommitmentResult>,
    pub chain_valid: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionCheckDto {
    pub version: u32,
    pub status: majik_signature::RevisionCheckStatus,
    pub signer_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevisionSetDto {
    pub all_valid: bool,
    pub is_complete_set: bool,
    pub results: Vec<RevisionCheckDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSignatureSummaryDto {
    pub signer_id: String,
    pub signer_label: String,
    pub content_hash: String,
    pub timestamp: String,
    pub has_tsa: bool,
    pub is_expired: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSignatureInfoDto {
    pub is_signed: bool,
    pub signatures: Vec<FileSignatureSummaryDto>,
    pub envelope: Option<EnvelopeInfo>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedFileDto {
    pub file: BytesOutput,
    pub seal_info: SealInfo,
    pub handler: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSignOutcomeDto {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<BytesOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FailureDto {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SeparateSignatureDto {
    pub path: String,
    pub output: BytesOutput,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchDetachedDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub map: Option<BytesOutput>,
    pub signatures: Vec<SeparateSignatureDto>,
    pub failures: Vec<FailureDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CosignDto {
    pub map: BytesOutput,
    pub failures: Vec<FailureDto>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MapFileInfoDto {
    pub path: String,
    pub content_hash: String,
    pub size: Option<u64>,
    pub mime_type: Option<String>,
    pub info: EnvelopeInfo,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileVerifyDto {
    pub path: String,
    pub status: FileVerifyStatus,
    pub results: Option<Vec<VerificationResult>>,
    pub reason: Option<String>,
    pub relocated_from: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchSummaryDto {
    pub total: usize,
    pub verified: usize,
    pub invalid: usize,
    pub tampered: usize,
    pub not_in_map: usize,
    pub all_valid: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MapVerifyDto {
    pub results: Vec<FileVerifyDto>,
    pub summary: BatchSummaryDto,
    pub missing_from_batch: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MapOrderDto {
    pub path: String,
    pub resolve_status: majik_signature::MjksMapResolveStatus,
    pub order: Option<majik_signature::SignatureOrderResult>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TsaBeginDto {
    pub token: String,
    pub tsa_request: majik_signature::MajikTsaRequest,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StampInspectDto {
    pub has_pixel_row: bool,
    pub has_dct: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDataSummaryDto {
    pub contacts: Vec<SerializedMajikContact>,
    pub groups: Vec<SerializedMajikContactGroup>,
    pub stamps: Vec<StampMeta>,
    pub preferences: Option<UserAppPreferences>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectiveRestoreDto {
    #[serde(default = "yes")]
    pub stamps: bool,
    #[serde(default = "yes")]
    pub contacts: bool,
    #[serde(default = "yes")]
    pub groups: bool,
    #[serde(default = "yes")]
    pub preferences: bool,
    #[serde(default = "yes")]
    pub overwrite_contacts: bool,
}

fn yes() -> bool {
    true
}

pub type ContactMeta = MajikContactMeta;
