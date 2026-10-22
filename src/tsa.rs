//! Two-step trusted-timestamp flow. The network call to the TSA lives in the caller (TypeScript,
//! which holds the session); Rust signs, hands back the request, then finishes with the returned
//! timestamp:
//!
//! 1. `begin_*`: sign, keep the result under a token, return the `MajikTsaRequest`.
//! 2. caller POSTs the request to the TSA and gets a `MajikTimestamp`.
//! 3. `complete_*`: attach the timestamp (and re-embed, or refresh the envelope).

use majik_signature::{MajikSignature, MajikSignatureEnvelope, MajikTimestamp, MajikTsaRequest};

use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::files::{SignDetachedFileOptions, SignFileOptions};
use crate::logs::types::new_id;
use crate::signing::OpContext;

/// Oldest pending results are dropped beyond this many.
const MAX_PENDING: usize = 8;

pub(crate) enum PendingTsa {
    Embedded {
        signature: MajikSignature,
        blob: Vec<u8>,
        mime_type: String,
    },
    Detached {
        signature: MajikSignature,
        envelope: MajikSignatureEnvelope,
        blob: Vec<u8>,
    },
}

pub struct EmbeddedTsaOutcome {
    pub blob: Vec<u8>,
    pub signature: MajikSignature,
}

pub struct DetachedTsaOutcome {
    pub envelope: MajikSignatureEnvelope,
    pub blob: Vec<u8>,
    pub signature: MajikSignature,
}

impl SignatureClient {
    fn store_pending(&mut self, entry: PendingTsa) -> String {
        let token = new_id();
        self.pending_tsa.push((token.clone(), entry));
        while self.pending_tsa.len() > MAX_PENDING {
            self.pending_tsa.remove(0);
        }
        token
    }

    fn take_pending(&mut self, token: &str) -> Result<PendingTsa> {
        let idx = self
            .pending_tsa
            .iter()
            .position(|(t, _)| t == token)
            .ok_or_else(|| {
                SignatureClientError::Invalid(
                    "Unknown or expired timestamp token. Sign the file again.".into(),
                )
            })?;
        Ok(self.pending_tsa.remove(idx).1)
    }

    /// Drop a pending result (e.g. the TSA request failed).
    pub fn cancel_pending_tsa(&mut self, token: &str) {
        self.pending_tsa.retain(|(t, _)| t != token);
    }

    pub fn begin_sign_file_with_tsa(
        &mut self,
        file: &[u8],
        options: &SignFileOptions,
        ctx: &OpContext,
    ) -> Result<(String, MajikTsaRequest)> {
        let result = self.sign_file(file, options, ctx)?;
        let request = result.signature.build_tsa_request_payload();
        let token = self.store_pending(PendingTsa::Embedded {
            signature: result.signature,
            blob: result.blob,
            mime_type: result.mime_type,
        });
        Ok((token, request))
    }

    pub fn complete_sign_file_with_tsa(
        &mut self,
        token: &str,
        timestamp: MajikTimestamp,
    ) -> Result<EmbeddedTsaOutcome> {
        match self.take_pending(token)? {
            PendingTsa::Embedded {
                mut signature,
                blob,
                mime_type,
            } => {
                signature.add_tsa(timestamp)?;
                let blob = signature.embed_in(&blob, Some(&mime_type))?;
                Ok(EmbeddedTsaOutcome { blob, signature })
            }
            PendingTsa::Detached { .. } => Err(SignatureClientError::Invalid(
                "This token belongs to a detached signature; use the detached completion.".into(),
            )),
        }
    }

    pub fn begin_sign_file_detached_with_tsa(
        &mut self,
        file: &[u8],
        options: &SignDetachedFileOptions,
        ctx: &OpContext,
    ) -> Result<(String, MajikTsaRequest)> {
        let result = self.sign_file_detached(file, options, ctx)?;
        let request = result.signature.build_tsa_request_payload();
        let token = self.store_pending(PendingTsa::Detached {
            signature: result.signature,
            envelope: result.envelope,
            blob: result.blob,
        });
        Ok((token, request))
    }

    /// The envelope was built before the timestamp existed, so it is refreshed with the
    /// timestamp-bearing signature (an upsert by signer id, not a duplicate entry).
    pub fn complete_sign_file_detached_with_tsa(
        &mut self,
        token: &str,
        timestamp: MajikTimestamp,
    ) -> Result<DetachedTsaOutcome> {
        match self.take_pending(token)? {
            PendingTsa::Detached {
                mut signature,
                envelope,
                blob,
            } => {
                signature.add_tsa(timestamp)?;
                let envelope = envelope.with_signature(signature.to_json())?;
                Ok(DetachedTsaOutcome {
                    envelope,
                    blob,
                    signature,
                })
            }
            PendingTsa::Embedded { .. } => Err(SignatureClientError::Invalid(
                "This token belongs to an embedded signature; use the embedded completion.".into(),
            )),
        }
    }
}
