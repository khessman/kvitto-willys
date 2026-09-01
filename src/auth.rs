#![allow(dead_code)]
//! BankID login — bare HTTP client, currently unused.
//!
//! Every call here works against the real backend except the last:
//! `collect-login` 503s instantly on every attempt, and the response is
//! missing the `x-cf-stack` header real backend responses carry — CloudFront
//! generates that error itself, before ever reaching Willys. Read as a WAF
//! rule guarding the account-takeover-risk endpoint specifically, likely on
//! a TLS/JS fingerprint this client can't reproduce. `source.rs` now uses
//! `browser_auth::BrowserLogin` (a real, visible Chromium instance) instead.
//! Kept as reference in case Willys ever loosens this.
//!
//! Confirmed against a real HAR capture (2026-08-29) of a full login on
//! willys.se. The shape:
//!
//!   1. GET  CSRF_TOKEN                 -> bare token string, cache it
//!   2. POST BANKID_AUTH  {mobile,generateQrData}, x-csrf-token
//!                                      -> { autoStartToken, orderRef }
//!   3. hand autostart_url to the AuthUi; poll BANKID_QR alongside collect
//!      for a fresh QR payload each tick (response shape unconfirmed)
//!   4. poll BANKID_COLLECT {orderRef, rememberMe} every ~2s
//!      -> {status: "PENDING", hintCode} | {status: "COMPLETE", ssn}
//!   5. on COMPLETE, harvest cookies + csrf token into a AxfoodSession
//!
//! Willys does not hand out `qrStartToken`/`qrStartSecret` the way Kivra
//! does, so the animated-QR HMAC helper from kvitto-ica does not apply here
//! — BANKID_QR is Willys' own server-computed equivalent. `status` and
//! `hintCode` are upper/camel-case, unlike BankID's own collect API.

use crate::client::AxfoodHttp;
use crate::endpoints as ep;
use crate::session::AxfoodSession;
use kvitto_core::{AuthPrompt, AuthUi, Error, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// BankID orders expire after ~3 minutes; give up a little after that.
const POLL_TIMEOUT: Duration = Duration::from_secs(200);

#[derive(Debug, Serialize)]
struct AuthRequest {
    mobile: bool,
    #[serde(rename = "generateQrData")]
    generate_qr_data: bool,
}

#[derive(Debug, Deserialize)]
struct AuthOrder {
    #[serde(rename = "autoStartToken")]
    auto_start_token: String,
    #[serde(rename = "orderRef")]
    order_ref: String,
}

#[derive(Debug, Serialize)]
struct CollectRequest<'a> {
    #[serde(rename = "orderRef")]
    order_ref: &'a str,
    #[serde(rename = "rememberMe")]
    remember_me: &'a str,
}

#[derive(Debug, Deserialize)]
struct CollectResponse {
    /// `PENDING` | `COMPLETE` | (presumably) `FAILED` — never observed the
    /// last one, treat anything but the first two as failure.
    status: String,
    #[serde(rename = "hintCode")]
    hint_code: Option<String>,
    /// Only present on `COMPLETE`.
    ssn: Option<String>,
}

/// Response shape for BANKID_QR is unconfirmed — no receipt existed yet to
/// finish a HAR capture past this point without a body. Guessed field name;
/// `qr_frame` below falls back to no QR (autostart-only) if this doesn't
/// deserialize, so a wrong guess degrades instead of breaking login.
#[derive(Debug, Deserialize)]
struct QrResponse {
    #[serde(rename = "qrData")]
    qr_data: Option<String>,
}

/// Swedish text for the hint codes BankID emits during login. Worth keeping in
/// sync with whatever kvitto-ica already shows, so the dashboard reads the same
/// regardless of which chain is authenticating.
pub fn hint_text(code: &str) -> &'static str {
    match code {
        "outstandingTransaction" | "noClient" => "Starta BankID-appen",
        "userSign" => "Skriv in din säkerhetskod i BankID-appen",
        "started" => "Söker efter BankID...",
        "userCancel" => "Du avbröt inloggningen",
        "expiredTransaction" => "BankID-ordern hann gå ut",
        "startFailed" => "Kunde inte starta BankID",
        _ => "Väntar på BankID...",
    }
}

pub struct BankIdLogin<'a> {
    pub http: &'a AxfoodHttp,
    /// Where BankID sends the browser after signing. Point it at the dashboard
    /// so a phone lands back on the progress view instead of a blank tab.
    pub return_url: Option<String>,
}

impl<'a> BankIdLogin<'a> {
    pub async fn run(&self, ui: &dyn AuthUi) -> Result<AxfoodSession> {
        self.http.warm_up().await?;
        // The real login page fetches these right before `bankid/auth` — in
        // particular `cart` attaches an anonymous cart to the session.
        // `collect-login` lives under `/checkout/...`; a missing cart is a
        // plausible reason it 503s with a generic OUTOFSERVICE_ERROR while
        // auth/csrf/qr (which don't need one) succeed fine. Best-effort: a
        // fresh account might 404/401 here without a cart existing yet, and
        // that must not block login.
        let _: Result<serde_json::Value> =
            self.http.get_json_unauthenticated("/axfood/rest/v1/customer").await;
        let _: Result<serde_json::Value> =
            self.http.get_json_unauthenticated("/axfood/rest/v1/cart").await;

        let csrf = self.fetch_csrf().await?;
        let order = self.start(&csrf).await?;
        ui.prompt(self.build_prompt(&order, &csrf).await)?;
        // The real page calls BANKID_QR twice before its first collect-login
        // — collect-login has 503'd instantly on every attempt so far, which
        // this rules out or confirms: matching that spacing rather than
        // hitting collect the instant the order exists.
        tokio::time::sleep(POLL_INTERVAL).await;
        ui.prompt(self.build_prompt(&order, &csrf).await)?;

        let started = std::time::Instant::now();
        loop {
            if started.elapsed() > POLL_TIMEOUT {
                return Err(Error::Auth("BankID timeout".into()));
            }
            let c = self.collect(&csrf, &order.order_ref).await?;
            match c.status.as_str() {
                "COMPLETE" => return self.finish(csrf, c).await,
                "PENDING" => {
                    ui.status(hint_text(c.hint_code.as_deref().unwrap_or("")));
                    ui.prompt(self.build_prompt(&order, &csrf).await)?;
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                _ => {
                    return Err(Error::Auth(
                        hint_text(c.hint_code.as_deref().unwrap_or("")).to_string(),
                    ))
                }
            }
        }
    }

    async fn fetch_csrf(&self) -> Result<String> {
        // Response body is the bare token string, not `{"csrfToken": ...}`.
        self.http.get_json_unauthenticated(ep::CSRF_TOKEN).await
    }

    async fn start(&self, csrf: &str) -> Result<AuthOrder> {
        let body = AuthRequest { mobile: true, generate_qr_data: true };
        self.http.post_json(ep::BANKID_AUTH, csrf, &body).await
    }

    async fn collect(&self, csrf: &str, order_ref: &str) -> Result<CollectResponse> {
        let body = CollectRequest { order_ref, remember_me: "false" };
        self.http.post_json(ep::BANKID_COLLECT, csrf, &body).await
    }

    /// Emit the autostart link always; layer in a QR payload when BANKID_QR
    /// answers with one. Both may be shown — the *front end* picks, since the
    /// device pressing Uppdatera may or may not have BankID installed.
    async fn build_prompt(&self, o: &AuthOrder, csrf: &str) -> AuthPrompt {
        let redirect = self.return_url.as_deref().unwrap_or("null");
        let autostart_url =
            Some(format!("bankid:///?autostarttoken={}&redirect={redirect}", o.auto_start_token));
        let qr_payload = self
            .http
            .post_json::<_, QrResponse>(ep::BANKID_QR, csrf, &())
            .await
            .ok()
            .and_then(|r| r.qr_data);
        AuthPrompt::BankId { autostart_url, qr_payload }
    }

    /// Harvest cookies and the CSRF token from the completed session.
    async fn finish(&self, csrf: String, c: CollectResponse) -> Result<AxfoodSession> {
        let cookies = self.http.session_cookies();
        Ok(AxfoodSession {
            cookies,
            csrf_token: Some(csrf),
            // Unknown whether Willys offers a longer-lived session; treat it
            // as browser-session-only until a HAR shows an expiry. See
            // WILLYS_BRIEF.md open question 1.
            expires_at: None,
            refresh_token: None,
            customer_id: c.ssn,
        })
    }
}
