//! History and user-activity log entries. The serde attributes reproduce the TS JSON exactly,
//! including its inconsistent naming (`reference_id` is snake_case, `historyType` is camelCase).
//!
//! `data` (a base64 encrypted `.mjkb` payload) and `fileJson` (`MajikFileJSON`) are carried through
//! untouched; creating those envelopes arrives with the `majik-file` integration.

use jiff::Timestamp;
use majik_file::MajikFileIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Result, SignatureClientError};

pub const LOG_TYPE_HISTORY: &str = "history";
pub const LOG_TYPE_AUDIT: &str = "audit";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryType {
    Sign,
    Verify,
    Seal,
    Notarize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistoryStatus {
    Success,
    Failed,
    Cancelled,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HistorySource {
    Gui,
    Cli,
    Mcp,
    Api,
    Sdk,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotaryNetwork {
    #[serde(rename = "solana-devnet")]
    SolanaDevnet,
    #[serde(rename = "solana-mainnet")]
    SolanaMainnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    FileViewed,
    FileSigned,
    FileVerified,
    FileSealed,
    FileNotarized,
    StampCreated,
    StampUpdated,
    StampDeleted,
    CreditsTopup,
    CreditsUsed,
    Login,
    Logout,
    SettingsChanged,
    KeyDataReset,
    ContactAdded,
    ContactUpdated,
    ContactDeleted,
    ContactGroupAdded,
    ContactGroupUpdated,
    ContactGroupDeleted,
    AccountCreated,
    AccountUpdated,
    AccountDeleted,
    RestoreAppData,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureOperation {
    pub digest: String,
    pub detached: bool,
    pub sealed: bool,
    pub tsa: bool,
}

/// Behaviour shared by both entry kinds, so the manager and repositories are written once.
/// Plaintext to store encrypted (as a `MajikFile` envelope) on a log entry for `identity`.
#[derive(Debug, Clone)]
pub struct LogEnvelope {
    pub data: Vec<u8>,
    pub identity: MajikFileIdentity,
}

fn apply_envelope(
    envelope: Option<LogEnvelope>,
    reference_id: &str,
) -> Result<(Option<String>, Option<Value>)> {
    match envelope {
        None => Ok((None, None)),
        Some(env) => {
            let sealed = crate::file_identity::encrypt_envelope(
                &env.data,
                &env.identity,
                Some(reference_id),
                None,
            )?;
            Ok((
                Some(sealed.data_base64),
                Some(serde_json::to_value(&sealed.file_json)?),
            ))
        }
    }
}

pub trait LogRecord: Clone + Send + Sync + 'static {
    fn id(&self) -> &str;
    fn fingerprint(&self) -> Option<&str>;
    fn timestamp(&self) -> &str;
    fn validate(&self) -> Result<()>;
}

fn log_err(msg: &str) -> SignatureClientError {
    SignatureClientError::Log(msg.to_string())
}

fn validate_base(
    id: &str,
    reference_id: &str,
    log_type: &str,
    expected_type: &str,
    timestamp: &str,
    version: u32,
) -> Result<()> {
    if id.is_empty() {
        return Err(log_err("Missing ID"));
    }
    if reference_id.is_empty() {
        return Err(log_err("Missing Reference ID"));
    }
    if log_type != expected_type {
        return Err(log_err(&format!(
            "Invalid root type: expected \"{expected_type}\""
        )));
    }
    if timestamp.is_empty() {
        return Err(log_err("Missing Timestamp"));
    }
    if timestamp.parse::<Timestamp>().is_err() {
        return Err(log_err("Invalid Timestamp"));
    }
    if version < 1 {
        return Err(log_err("Invalid Version"));
    }
    Ok(())
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`, the same shape as JS `Date.prototype.toISOString()`.
pub(crate) fn now_iso() -> String {
    let z = Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        z.year(),
        z.month(),
        z.day(),
        z.hour(),
        z.minute(),
        z.second(),
        z.millisecond()
    )
}

pub(crate) fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ─── History ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryLog {
    pub id: String,
    #[serde(rename = "reference_id")]
    pub reference_id: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub timestamp: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    /// Base64 encrypted `.mjkb` payload (opaque here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// `MajikFileJSON` (opaque here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_json: Option<Value>,
    pub history_type: HistoryType,
    pub status: HistoryStatus,
    pub source: HistorySource,
    pub operation: SignatureOperation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NotaryNetwork>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}

/// Input for [`HistoryLog::create`] (TS `CreateHistoryLogOptions`, minus the envelope fields).
#[derive(Debug, Clone)]
pub struct CreateHistoryLog {
    pub reference_id: String,
    pub fingerprint: Option<String>,
    pub history_type: HistoryType,
    pub status: HistoryStatus,
    pub source: HistorySource,
    pub operation: SignatureOperation,
    pub signer_count: Option<u32>,
    pub valid: Option<bool>,
    pub network: Option<NotaryNetwork>,
    pub transaction_id: Option<String>,
    pub id: Option<String>,
    pub version: Option<u32>,
    pub timestamp: Option<String>,
    /// Optional encrypted copy of the operation's output (signed file, envelope bytes, ...).
    pub envelope: Option<LogEnvelope>,
}

impl CreateHistoryLog {
    pub fn new(
        reference_id: impl Into<String>,
        history_type: HistoryType,
        status: HistoryStatus,
        source: HistorySource,
        operation: SignatureOperation,
    ) -> Self {
        Self {
            reference_id: reference_id.into(),
            fingerprint: None,
            history_type,
            status,
            source,
            operation,
            signer_count: None,
            valid: None,
            network: None,
            transaction_id: None,
            id: None,
            version: None,
            timestamp: None,
            envelope: None,
        }
    }
}

impl HistoryLog {
    pub fn create(opts: CreateHistoryLog) -> Result<Self> {
        let (data, file_json) = apply_envelope(opts.envelope, &opts.reference_id)?;
        let log = Self {
            id: opts.id.unwrap_or_else(new_id),
            reference_id: opts.reference_id,
            log_type: LOG_TYPE_HISTORY.to_string(),
            timestamp: opts.timestamp.unwrap_or_else(now_iso),
            version: opts.version.unwrap_or(1),
            fingerprint: opts.fingerprint,
            data,
            file_json,
            history_type: opts.history_type,
            status: opts.status,
            source: opts.source,
            operation: opts.operation,
            signer_count: opts.signer_count,
            valid: opts.valid,
            network: opts.network,
            transaction_id: opts.transaction_id,
        };
        log.validate()?;
        Ok(log)
    }
}

impl LogRecord for HistoryLog {
    fn id(&self) -> &str {
        &self.id
    }
    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
    fn timestamp(&self) -> &str {
        &self.timestamp
    }
    fn validate(&self) -> Result<()> {
        validate_base(
            &self.id,
            &self.reference_id,
            &self.log_type,
            LOG_TYPE_HISTORY,
            &self.timestamp,
            self.version,
        )?;
        if self.operation.digest.is_empty() {
            return Err(log_err("Invalid operation: missing digest"));
        }
        Ok(())
    }
}

// ─── User activity (audit) ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActivityLog {
    pub id: String,
    #[serde(rename = "reference_id")]
    pub reference_id: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub timestamp: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_json: Option<Value>,
    pub action: AuditAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Map<String, Value>>,
}

/// Input for [`UserActivityLog::create`].
#[derive(Debug, Clone)]
pub struct CreateUserActivityLog {
    pub reference_id: String,
    pub fingerprint: Option<String>,
    pub action: AuditAction,
    pub metadata: Option<Map<String, Value>>,
    pub id: Option<String>,
    pub version: Option<u32>,
    pub timestamp: Option<String>,
    pub envelope: Option<LogEnvelope>,
}

impl CreateUserActivityLog {
    pub fn new(reference_id: impl Into<String>, action: AuditAction) -> Self {
        Self {
            reference_id: reference_id.into(),
            fingerprint: None,
            action,
            metadata: None,
            id: None,
            version: None,
            timestamp: None,
            envelope: None,
        }
    }

    /// `metadata` accepts any JSON object (a non-object value is ignored).
    pub fn with_metadata(mut self, metadata: Value) -> Self {
        if let Value::Object(map) = metadata {
            self.metadata = Some(map);
        }
        self
    }
}

impl UserActivityLog {
    pub fn create(opts: CreateUserActivityLog) -> Result<Self> {
        let (data, file_json) = apply_envelope(opts.envelope, &opts.reference_id)?;
        let log = Self {
            id: opts.id.unwrap_or_else(new_id),
            reference_id: opts.reference_id,
            log_type: LOG_TYPE_AUDIT.to_string(),
            timestamp: opts.timestamp.unwrap_or_else(now_iso),
            version: opts.version.unwrap_or(1),
            fingerprint: opts.fingerprint,
            data,
            file_json,
            action: opts.action,
            metadata: opts.metadata,
        };
        log.validate()?;
        Ok(log)
    }
}

impl LogRecord for UserActivityLog {
    fn id(&self) -> &str {
        &self.id
    }
    fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
    fn timestamp(&self) -> &str {
        &self.timestamp
    }
    fn validate(&self) -> Result<()> {
        validate_base(
            &self.id,
            &self.reference_id,
            &self.log_type,
            LOG_TYPE_AUDIT,
            &self.timestamp,
            self.version,
        )
    }
}
