use crate::browser_auth::BrowserLogin;
use crate::client::WillysHttp;
use crate::endpoints as ep;
use crate::session::WillysSession;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use kvitto_core::{
    AuthUi, Media, ProfileId, RawReceipt, Receipt, ReceiptId, ReceiptRef, ReceiptSource, Result,
    SessionStore, SourceId, WILLYS,
};
use std::sync::Arc;

pub struct Willys {
    http: WillysHttp,
    sessions: Arc<dyn SessionStore>,
    /// Where BankID returns the browser after signing.
    pub return_url: Option<String>,
}

impl Willys {
    pub fn new(sessions: Arc<dyn SessionStore>) -> Result<Self> {
        Ok(Self { http: WillysHttp::new()?, sessions, return_url: None })
    }

    /// Escape hatch for exploring the API before `list`/`fetch` target real
    /// receipt endpoints: any authenticated GET, returned as raw JSON. Not
    /// part of `ReceiptSource` — only for manual probing during development.
    pub async fn probe(&self, path: &str) -> Result<serde_json::Value> {
        self.http.get_json(path).await
    }

    /// Raw passthrough for saving a probed response to disk (e.g. a fixture)
    /// instead of embedding it in a JSON debug view.
    pub async fn fetch_raw(&self, path: &str) -> Result<(String, Vec<u8>)> {
        self.http.get_bytes_with_content_type(path).await
    }

    /// Like `probe`, but for an endpoint whose media type isn't known yet
    /// (JSON vs PDF — see WILLYS_BRIEF.md open question 3). JSON bodies are
    /// parsed and returned as-is; anything else comes back as content-type +
    /// size + a base64 snippet, enough to tell a real PDF from an HTML error
    /// page without dumping megabytes into a debug view.
    pub async fn probe_raw(&self, path: &str) -> Result<serde_json::Value> {
        let (content_type, bytes) = self.http.get_bytes_with_content_type(path).await?;
        if content_type.contains("json") {
            return serde_json::from_slice(&bytes)
                .map_err(|e| kvitto_core::Error::Transport(format!("{path} (decoding json): {e}")));
        }
        use base64::Engine;
        let snippet_len = bytes.len().min(256);
        Ok(serde_json::json!({
            "content_type": content_type,
            "size": bytes.len(),
            "base64_prefix": base64::engine::general_purpose::STANDARD.encode(&bytes[..snippet_len]),
        }))
    }
}

#[async_trait]
impl ReceiptSource for Willys {
    fn id(&self) -> SourceId {
        WILLYS
    }

    async fn authenticate(&mut self, profile: &ProfileId, ui: &dyn AuthUi) -> Result<()> {
        if let Some(s) = WillysSession::load(self.sessions.as_ref(), profile)? {
            if s.is_live() {
                self.http.restore(&s);
                self.http.session = Some(s);
                return Ok(());
            }
        }
        let login = BrowserLogin { http: &self.http };
        let s = login.run(ui).await?;
        s.save(self.sessions.as_ref(), profile)?;
        self.http.session = Some(s);
        Ok(())
    }

    async fn list(&self, _since: Option<DateTime<Utc>>) -> Result<Vec<ReceiptRef>> {
        let _ = (ep::RECEIPTS_LIST, &self.http);
        // Page until empty; `handle` is whatever fetch substitutes into
        // RECEIPT_DETAIL. Filter on `since` locally if there is no date param.
        todo!("GET RECEIPTS_LIST, paginate, map to ReceiptRef")
    }

    async fn fetch(&self, r: &ReceiptRef) -> Result<RawReceipt> {
        // Confirmed against a real purchase (2026-08-30): the detail
        // endpoint is a PDF, not JSON — see parse.rs's module doc.
        let path = ep::RECEIPT_DETAIL.replace("{id}", &r.handle);
        let bytes = self.http.get_bytes(&path).await?;
        Ok(RawReceipt::new(r.id.clone(), Media::Pdf, bytes))
    }

    fn parse(&self, raw: &RawReceipt, profile: &ProfileId) -> Result<Receipt> {
        crate::parse::parse(raw, profile)
    }
}

pub fn receipt_id(external: impl Into<String>) -> ReceiptId {
    ReceiptId::new(WILLYS, external)
}
