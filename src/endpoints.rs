//! Every URL and field name Axfood can change under us, in one file.
//! Filled in from a HAR capture of a real Willys BankID login (2026-08-29)
//! and confirmed identical against hemkop.se (2026-08-31) — same Hybris
//! instance behind both domains. The domain itself lives in `Chain::base`,
//! not here; everything below is path-only and shared across chains.

// --- CSRF ---------------------------------------------------------------
// Fetched proactively before the first mutating call, not reactively on 401:
// the real login flow does GET csrf-token, then POST bankid/auth with the
// token already attached. Skipping it gives back `{"error":"csrf.badormissing"}`.

/// GET — response body is the token itself, a bare JSON string (not an
/// object): `"71ee115b-9bf1-44b2-ab73-c6234768a105"`.
pub const CSRF_TOKEN: &str = "/axfood/rest/v1/csrf-token";

// --- BankID ---------------------------------------------------------------
// A bespoke Axfood/Hybris endpoint, not standard OIDC — no PKCE flow to
// reuse from kvitto-ica here.

/// POST, body `{"mobile":true,"generateQrData":true}`, requires the
/// `x-csrf-token` header. Response: `{"autoStartToken": "...", "orderRef": "..."}`.
/// No `qrStartToken`/`qrStartSecret` — unlike Kivra, Willys does not hand the
/// client a secret to compute the animated QR itself.
pub const BANKID_AUTH: &str = "/axfood/rest/v1/checkout/bankid/auth";

/// POST, empty body, `x-csrf-token` header. Not optional: confirmed live
/// that skipping it makes the resulting `autostarttoken` fail in the real
/// BankID app ("något gick fel, försök igen") — this call is what actually
/// registers the order with BankID's own backend, not just UI rendering. The
/// real page polls it repeatedly while a QR is on screen; one call right
/// after `BANKID_AUTH` is enough for the autostart-only flow
/// (`browser_auth.rs`) since no QR is ever shown. Response shape still
/// unconfirmed — we only need the side effect, not the body.
pub const BANKID_QR: &str = "/axfood/rest/v1/checkout/bankid/qr";

/// POST, body `{"orderRef": "...", "rememberMe": "false"}`, `x-csrf-token` header.
/// Response while waiting: `{"status":"PENDING","hintCode":"userSign"}`.
/// Response on success: `{"status":"COMPLETE","ssn":"..."}`. Note `status` is
/// upper-case — unlike BankID's own API, which uses lower-case.
pub const BANKID_COLLECT: &str = "/axfood/rest/v1/checkout/bankid/collect-login";

// --- Receipts ---------------------------------------------------------

/// GET — confirmed against a real purchase (2026-08-30). Not the list
/// endpoint itself: this is `account/pagedOrderBonusCombined` from the "Mina
/// köp" page, which doubles as both the loyalty/bonus view and the receipt
/// list — each entry's `digitalReceiptReference`, `bookingDate`,
/// `storeCustomerId`, `receiptSource` and `memberCardNumber` are exactly the
/// fields `RECEIPT_DETAIL` below needs. `list()` still needs to page this
/// (`currentPage`/`pageSize` seen in the query) and map entries to
/// `ReceiptRef` — `handle` is the natural place to carry the four detail
/// params, since the core never interprets it.
pub const RECEIPTS_LIST: &str = "/axfood/rest/v1/account/pagedOrderBonusCombined";

/// GET — confirmed: a PDF (see `parse.rs`), not JSON. Base path only;
/// `source.rs::fetch` builds the full URL (reference path segment +
/// `date`/`storeId`/`source`/`memberCardNumber` query params, all from the
/// same `pagedOrderBonusCombined` entry) so it can URL-encode the reference
/// properly — it contains slashes and colons.
pub const RECEIPT_DETAIL: &str = "/axfood/rest/order/orders/digitalreceipt";

// --- Headers ----------------------------------------------------------

pub const CSRF_HEADER: &str = "x-csrf-token";
pub const REQUESTED_WITH: &str = "X-Requested-With";

/// Match a current desktop browser. A stale UA string is the cheapest way to
/// get blocked by a WAF.
pub const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

/// One request at a time, with a gap between them.
pub const REQUEST_DELAY_MS: u64 = 400;
