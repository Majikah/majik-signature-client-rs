//! User app preferences, stored as one JSON value in the key client's state store under
//! `user_app_preferences` (same key and shape as the TS `ClientStateManager`).
//!
//! Every leaf is an `Option` so the three states the TS code distinguishes survive a round trip:
//! absent, explicitly `false`, explicitly `true`. The getters apply the same fallbacks as the TS
//! `isXEnabled()` methods. A missing *section* is filled from the defaults, matching the TS
//! `{ ...DEFAULTS, ...stored }` shallow merge.

use majik_key_client::state_manager::ClientStateManager;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::Result;

pub const STATE_KEY_USER_APP_PREFERENCES: &str = "user_app_preferences";

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_count: Option<u32>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeneralPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<HistoryPreferences>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutosavePreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_path: Option<String>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutosaveSet {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sign: Option<AutosavePreferences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_seal: Option<AutosavePreferences>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_notary: Option<AutosavePreferences>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_seal: Option<bool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "defaultToTSA"
    )]
    pub default_to_tsa: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_to_detached: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autosave: Option<AutosaveSet>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub share_analytics: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_lock_on_minimize: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_lock_interval: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onetime_unlock: Option<bool>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<KeyPreferences>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

fn d_general() -> GeneralPreferences {
    UserAppPreferences::defaults().general
}
fn d_signing() -> SigningPreferences {
    UserAppPreferences::defaults().signing
}
fn d_privacy() -> PrivacyPreferences {
    UserAppPreferences::defaults().privacy
}
fn d_security() -> SecurityPreferences {
    UserAppPreferences::defaults().security
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAppPreferences {
    #[serde(default = "d_general")]
    pub general: GeneralPreferences,
    #[serde(default = "d_signing")]
    pub signing: SigningPreferences,
    #[serde(default = "d_privacy")]
    pub privacy: PrivacyPreferences,
    #[serde(default = "d_security")]
    pub security: SecurityPreferences,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl Default for UserAppPreferences {
    fn default() -> Self {
        Self::defaults()
    }
}

impl UserAppPreferences {
    /// TS `DEFAULT_USER_APP_PREFERENCES`.
    pub fn defaults() -> Self {
        Self {
            general: GeneralPreferences {
                history: Some(HistoryPreferences {
                    enabled: Some(true),
                    max_count: Some(100),
                    extra: Map::new(),
                }),
                extra: Map::new(),
            },
            signing: SigningPreferences {
                auto_seal: Some(false),
                default_to_tsa: Some(false),
                default_to_detached: Some(false),
                autosave: Some(AutosaveSet {
                    after_sign: Some(AutosavePreferences {
                        enabled: Some(false),
                        ..Default::default()
                    }),
                    after_seal: Some(AutosavePreferences {
                        enabled: Some(false),
                        ..Default::default()
                    }),
                    after_notary: None,
                    extra: Map::new(),
                }),
                extra: Map::new(),
            },
            privacy: PrivacyPreferences {
                share_analytics: Some(true),
                extra: Map::new(),
            },
            security: SecurityPreferences {
                key: Some(KeyPreferences {
                    auto_lock_on_minimize: Some(false),
                    onetime_unlock: Some(true),
                    auto_lock_interval: None,
                    extra: Map::new(),
                }),
                extra: Map::new(),
            },
            extra: Map::new(),
        }
    }

    // ── Getters with the TS fallbacks ────────────────────────────────────────

    pub fn is_analytics_enabled(&self) -> bool {
        self.privacy.share_analytics.unwrap_or(false)
    }
    pub fn is_auto_seal_enabled(&self) -> bool {
        self.signing.auto_seal.unwrap_or(false)
    }
    pub fn is_default_to_tsa_enabled(&self) -> bool {
        self.signing.default_to_tsa.unwrap_or(false)
    }
    pub fn is_default_to_detached_enabled(&self) -> bool {
        self.signing.default_to_detached.unwrap_or(false)
    }
    pub fn is_auto_lock_on_minimize_enabled(&self) -> bool {
        self.key_prefs()
            .and_then(|k| k.auto_lock_on_minimize)
            .unwrap_or(false)
    }
    pub fn auto_lock_interval(&self) -> Option<f64> {
        self.key_prefs().and_then(|k| k.auto_lock_interval)
    }
    /// Defaults to `true`: an unlocked account stays unlocked between operations.
    pub fn is_onetime_unlock_enabled(&self) -> bool {
        self.key_prefs()
            .and_then(|k| k.onetime_unlock)
            .unwrap_or(true)
    }
    pub fn is_auto_save_after_sign_enabled(&self) -> bool {
        self.autosave()
            .and_then(|a| a.after_sign.as_ref())
            .and_then(|p| p.enabled)
            .unwrap_or(false)
    }
    pub fn is_auto_save_after_seal_enabled(&self) -> bool {
        self.autosave()
            .and_then(|a| a.after_seal.as_ref())
            .and_then(|p| p.enabled)
            .unwrap_or(false)
    }
    pub fn is_auto_save_after_notarize_enabled(&self) -> bool {
        self.autosave()
            .and_then(|a| a.after_notary.as_ref())
            .and_then(|p| p.enabled)
            .unwrap_or(false)
    }
    /// History logging is on unless explicitly disabled.
    pub fn is_history_enabled(&self) -> bool {
        self.general.history.as_ref().and_then(|h| h.enabled) != Some(false)
    }
    /// Per-account history cap; `0` means unlimited.
    pub fn history_max_count(&self) -> u32 {
        self.general
            .history
            .as_ref()
            .and_then(|h| h.max_count)
            .unwrap_or(100)
    }

    fn key_prefs(&self) -> Option<&KeyPreferences> {
        self.security.key.as_ref()
    }
    fn autosave(&self) -> Option<&AutosaveSet> {
        self.signing.autosave.as_ref()
    }
}

/// Load from the state store. A missing value writes (and returns) the defaults; unparsable
/// content falls back to the defaults without overwriting it (same as the TS manager).
pub fn load(state: &mut ClientStateManager) -> Result<UserAppPreferences> {
    match state.get(STATE_KEY_USER_APP_PREFERENCES)? {
        None => {
            let defaults = UserAppPreferences::defaults();
            save(state, &defaults)?;
            Ok(defaults)
        }
        Some(raw) => {
            Ok(serde_json::from_str(&raw).unwrap_or_else(|_| UserAppPreferences::defaults()))
        }
    }
}

pub fn save(state: &mut ClientStateManager, prefs: &UserAppPreferences) -> Result<()> {
    state.set(
        STATE_KEY_USER_APP_PREFERENCES,
        &serde_json::to_string(prefs)?,
    )?;
    Ok(())
}

pub fn reset(state: &mut ClientStateManager) -> Result<()> {
    save(state, &UserAppPreferences::defaults())
}

pub fn remove(state: &mut ClientStateManager) -> Result<()> {
    state.remove(STATE_KEY_USER_APP_PREFERENCES)?;
    Ok(())
}
