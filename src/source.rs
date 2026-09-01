use crate::browser_auth::BrowserLogin;
use crate::chain::Chain;
use crate::client::AxfoodHttp;
use crate::endpoints as ep;
use crate::session::AxfoodSession;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use kvitto_core::{
    AuthUi, Media, Money, ProfileId, RawReceipt, Receipt, ReceiptId, ReceiptRef, ReceiptSource,
    Result, SessionStore, SourceId,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A `ReceiptSource` for any Axfood-family chain (Willys, Hemköp, ...).
/// Everything chain-specific — domain, cookie scope, `SourceId`, receipt
/// defaults — is carried by `Chain`; the HTTP/BankID/parse logic is shared.
pub struct AxfoodSource {
    chain: Chain,
    http: AxfoodHttp,
    sessions: Arc<dyn SessionStore>,
    /// Where BankID returns the browser after signing.
    pub return_url: Option<String>,
}

impl AxfoodSource {
    pub fn new(chain: Chain, sessions: Arc<dyn SessionStore>) -> Result<Self> {
        Ok(Self { chain, http: AxfoodHttp::new(chain)?, sessions, return_url: None })
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
impl ReceiptSource for AxfoodSource {
    fn id(&self) -> SourceId {
        self.chain.source_id()
    }

    async fn authenticate(&mut self, profile: &ProfileId, ui: &dyn AuthUi) -> Result<()> {
        if let Some(s) = AxfoodSession::load(self.sessions.as_ref(), profile, self.chain)? {
            if s.is_live() {
                self.http.restore(&s);
                self.http.session = Some(s);
                return Ok(());
            }
        }
        let login = BrowserLogin { http: &self.http };
        let s = login.run(ui).await?;
        s.save(self.sessions.as_ref(), profile, self.chain)?;
        self.http.session = Some(s);
        Ok(())
    }

    /// `RECEIPTS_LIST` (`pagedOrderBonusCombined`) doubles as the loyalty
    /// view and the receipt list — paged, so keep pulling pages until
    /// `numberOfPages` says stop. Everything `fetch` needs later
    /// (`date`/`storeId`/`source`/`memberCardNumber`) only exists on *this*
    /// listing entry, not on the detail endpoint, so it rides along inside
    /// `handle` as a small JSON blob — opaque to core, meaningful only here.
    /// Confirmed identical shape on both willys.se and hemkop.se.
    async fn list(&self, since: Option<DateTime<Utc>>) -> Result<Vec<ReceiptRef>> {
        let today = Utc::now().date_naive();
        let from = since
            .map(|d| d.date_naive())
            .unwrap_or_else(|| today - chrono::Duration::days(730));

        let mut out = Vec::new();
        let mut page = 0u32;
        loop {
            let path = format!(
                "{}?fromDate={from}&toDate={today}&currentPage={page}&pageSize=50",
                ep::RECEIPTS_LIST
            );
            let resp: PagedOrderBonusCombined = self.http.get_json(&path).await?;

            for t in resp.loyalty_transactions_in_page {
                if !t.digital_receipt_available {
                    continue; // no receipt to fetch for this transaction
                }
                let Some(reference) = t.digital_receipt_reference else { continue };
                let Some(purchased_at) = t
                    .booking_date
                    .and_then(DateTime::<Utc>::from_timestamp_millis)
                else {
                    continue;
                };
                if since.is_some_and(|s| purchased_at < s) {
                    continue;
                }

                let handle = ReceiptHandle {
                    reference: reference.clone(),
                    date: purchased_at.format("%Y-%m-%d").to_string(),
                    store_id: t.store_customer_id.unwrap_or_default(),
                    source: t.receipt_source.unwrap_or_default(),
                    member_card_number: t.member_card_number.unwrap_or_default(),
                };
                let handle = serde_json::to_string(&handle).map_err(kvitto_core::Error::from)?;

                out.push(ReceiptRef {
                    id: ReceiptId::new(self.chain.source_id(), reference),
                    purchased_at,
                    handle,
                    store_hint: t.store_name,
                    total_hint: t.amount.map(Money::from_kr),
                });
            }

            page += 1;
            if page >= resp.pagination_data.number_of_pages {
                break;
            }
        }
        Ok(out)
    }

    async fn fetch(&self, r: &ReceiptRef) -> Result<RawReceipt> {
        let h: ReceiptHandle = serde_json::from_str(&r.handle).map_err(kvitto_core::Error::from)?;
        // Confirmed against a real purchase (2026-08-30) on both Willys and
        // Hemköp: the detail endpoint is a PDF, not JSON — see parse.rs's
        // module doc. The reference contains `:`/`+`/`.` — percent-encode it
        // as its own path segment, don't just paste it in.
        let path = format!(
            "{}/{}?date={}&storeId={}&source={}&memberCardNumber={}",
            ep::RECEIPT_DETAIL,
            encode_path_segment(&h.reference),
            h.date,
            h.store_id,
            h.source,
            h.member_card_number,
        );
        let bytes = self.http.get_bytes(&path).await?;
        Ok(RawReceipt::new(r.id.clone(), Media::Pdf, bytes))
    }

    fn parse(&self, raw: &RawReceipt, profile: &ProfileId) -> Result<Receipt> {
        crate::parse::parse(raw, profile, self.chain)
    }
}

pub fn receipt_id(chain: Chain, external: impl Into<String>) -> ReceiptId {
    ReceiptId::new(chain.source_id(), external)
}

/// Everything `fetch` needs that only exists on the `pagedOrderBonusCombined`
/// listing entry, carried opaquely inside `ReceiptRef::handle`.
#[derive(Serialize, Deserialize)]
struct ReceiptHandle {
    reference: String,
    date: String,
    store_id: String,
    source: String,
    member_card_number: String,
}

#[derive(Deserialize)]
struct PagedOrderBonusCombined {
    #[serde(rename = "loyaltyTransactionsInPage")]
    loyalty_transactions_in_page: Vec<Transaction>,
    #[serde(rename = "paginationData")]
    pagination_data: PaginationData,
}

#[derive(Deserialize)]
struct PaginationData {
    #[serde(rename = "numberOfPages")]
    number_of_pages: u32,
}

#[derive(Deserialize)]
struct Transaction {
    amount: Option<f64>,
    #[serde(rename = "bookingDate")]
    booking_date: Option<i64>,
    #[serde(rename = "digitalReceiptAvailable", default)]
    digital_receipt_available: bool,
    #[serde(rename = "digitalReceiptReference")]
    digital_receipt_reference: Option<String>,
    #[serde(rename = "memberCardNumber")]
    member_card_number: Option<String>,
    #[serde(rename = "receiptSource")]
    receipt_source: Option<String>,
    #[serde(rename = "storeCustomerId")]
    store_customer_id: Option<String>,
    #[serde(rename = "storeName")]
    store_name: Option<String>,
}

/// RFC 3986 path-segment percent-encoding — only unreserved characters pass
/// through unescaped. Over-encoding a path segment is always safe; this
/// exists so `:`/`+`/`.` in `digitalReceiptReference` don't get interpreted
/// as URL syntax.
fn encode_path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
