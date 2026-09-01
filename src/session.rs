use crate::chain::Chain;
use chrono::{DateTime, Utc};
use kvitto_core::{Error, ProfileId, Result, SessionStore, StoredSession};
use serde::{Deserialize, Serialize};

/// Everything needed to resume a logged-in Axfood (Willys/Hemköp) session
/// without BankID.
///
/// Held in memory only — see `MemorySessionStore` in kvitto-core for why.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AxfoodSession {
    pub cookies: Vec<Cookie>,
    pub csrf_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    /// Whether this exists decides how often Uppdatera needs the phone. Look
    /// for it in the HAR before designing the button's copy.
    pub refresh_token: Option<String>,
    /// Willys Plus id, useful for asserting a restored session belongs to the
    /// profile you think it does.
    pub customer_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
}

impl Cookie {
    pub fn header_pair(&self) -> String {
        format!("{}={}", self.name, self.value)
    }
}

impl AxfoodSession {
    pub fn cookie_header(&self) -> String {
        self.cookies.iter().map(Cookie::header_pair).collect::<Vec<_>>().join("; ")
    }

    pub fn is_live(&self) -> bool {
        match self.expires_at {
            Some(t) => t > Utc::now() + chrono::Duration::seconds(60),
            None => !self.cookies.is_empty(),
        }
    }

    pub fn load(store: &dyn SessionStore, profile: &ProfileId, chain: Chain) -> Result<Option<Self>> {
        match store.load(profile, chain.source_id())? {
            Some(s) if s.is_live() => Ok(Some(serde_json::from_value(s.blob)?)),
            _ => Ok(None),
        }
    }

    pub fn save(&self, store: &dyn SessionStore, profile: &ProfileId, chain: Chain) -> Result<()> {
        store.save(&StoredSession {
            profile: profile.clone(),
            source: chain.source_id().to_string(),
            saved_at: Utc::now(),
            expires_at: self.expires_at,
            blob: serde_json::to_value(self).map_err(Error::from)?,
        })
    }
}
