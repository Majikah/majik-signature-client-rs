//! Signature-client events: every key-client event, plus the signature client's own.
//! Wire format is the same for both: `{ "type": "<kebab-name>", "payload": ... }`, so the TS side
//! sees one stream.

use majik_key_client::ClientEvent;
use serde::Serialize;

use crate::logs::{HistoryLog, UserActivityLog};
use crate::contacts::majik_contact::{SerializedMajikContact, SerializedMajikContactGroup};
use crate::signing::{SignEventPayload, VerifyResult};
use crate::stamps::StampMeta;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "kebab-case")]
pub enum SigOnlyEvent {
    Sign(SignEventPayload),
    Verify(VerifyResult),
    NewStamp(StampMeta),
    RemovedStamp(String),
    NewContact(SerializedMajikContact),
    NewContactGroup(SerializedMajikContactGroup),
    RemovedContact(String),
    RemovedContactGroup(SerializedMajikContactGroup),
    ContactGroupChange(SerializedMajikContactGroup),
    HistoryLog(HistoryLog),
    ActivityLog(UserActivityLog),
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum SigEvent {
    Key(ClientEvent),
    Sig(SigOnlyEvent),
}

impl SigOnlyEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sign(_) => "sign",
            Self::Verify(_) => "verify",
            Self::NewStamp(_) => "new-stamp",
            Self::RemovedStamp(_) => "removed-stamp",
            Self::NewContact(_) => "new-contact",
            Self::NewContactGroup(_) => "new-contact-group",
            Self::RemovedContact(_) => "removed-contact",
            Self::RemovedContactGroup(_) => "removed-contact-group",
            Self::ContactGroupChange(_) => "contact-group-change",
            Self::HistoryLog(_) => "history-log",
            Self::ActivityLog(_) => "activity-log",
        }
    }
}

impl SigEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Key(e) => e.name(),
            Self::Sig(e) => e.name(),
        }
    }
}
