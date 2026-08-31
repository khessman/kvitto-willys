//! BankID login: order creation over plain HTTP, completion polled from
//! inside a real (background) browser.
//!
//! `auth.rs` reproduces willys.se's login API call-for-call, and almost all
//! of it works fine over a bare `reqwest` client: `csrf-token`, `bankid/auth`
//! (which is enough to get an `autoStartToken` and build the `bankid://`
//! link) and `bankid/qr` all succeed. Only `collect-login` — the call that
//! finds out whether the order was signed, and what turns the order into a
//! logged-in session — 503s instantly, every time, with a CloudFront-
//! generated error missing the `x-cf-stack` header real backend responses
//! carry. That means CloudFront never reaches Willys' own backend for that
//! one call: almost certainly a WAF rule guarding the account-takeover-risk
//! endpoint specifically, on a TLS/JS fingerprint a bare HTTP client can't
//! reproduce.
//!
//! So the split: create the order and hand the phone its `bankid://` link
//! immediately, over plain HTTP (fast — no browser needed for this part at
//! all). Then launch a background browser purely to re-run the
//! *already-known-correct* `collect-login` call as a `fetch()` from inside
//! real page JS — same endpoint, same body, same session cookies (copied
//! into the browser), just executed somewhere CloudFront doesn't distrust.
//! No UI clicking, no DOM scraping: earlier attempts drove the site's own
//! login form, which turned out to be unnecessary (the API sequence was
//! already reverse-engineered) and fragile (React ignores JS-dispatched
//! clicks; real `Input.dispatchMouseEvent` clicks hung outright on the
//! cookie-consent button in this environment).

use crate::client::WillysHttp;
use crate::endpoints as ep;
use crate::session::{Cookie, WillysSession};
use chromiumoxide::cdp::browser_protocol::network::CookieParam;
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use kvitto_core::{AuthPrompt, AuthUi, Error, Result};
use serde::Deserialize;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Human BankID interaction takes a while — the phone has to come out.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Deserialize)]
struct AuthOrder {
    #[serde(rename = "autoStartToken")]
    auto_start_token: String,
    #[serde(rename = "orderRef")]
    order_ref: String,
}

#[derive(Debug, Deserialize)]
struct CollectResponse {
    /// `PENDING` | `COMPLETE` | (presumably) `FAILED`.
    status: String,
    ssn: Option<String>,
}

pub struct BrowserLogin<'a> {
    pub http: &'a WillysHttp,
}

impl<'a> BrowserLogin<'a> {
    pub async fn run(&self, ui: &dyn AuthUi) -> Result<WillysSession> {
        ui.status("Startar BankID-order...");
        let (order, csrf) = self.create_order().await?;

        ui.prompt(AuthPrompt::BankId {
            autostart_url: Some(format!(
                "bankid:///?autostarttoken={}&redirect=null",
                order.auto_start_token
            )),
            qr_payload: None,
        })?;
        ui.status("Tryck på länken för att öppna BankID-appen...");

        self.wait_for_completion(&order.order_ref, &csrf, ui).await
    }

    /// The part that already worked over plain HTTP (see `auth.rs`): warm
    /// up a session, bootstrap a cart, and open a BankID order.
    async fn create_order(&self) -> Result<(AuthOrder, String)> {
        self.http.warm_up().await?;
        let _: Result<serde_json::Value> =
            self.http.get_json_unauthenticated("/axfood/rest/v1/customer").await;
        let _: Result<serde_json::Value> =
            self.http.get_json_unauthenticated("/axfood/rest/v1/cart").await;

        let csrf: String = self.http.get_json_unauthenticated(ep::CSRF_TOKEN).await?;
        let order: AuthOrder = self
            .http
            .post_json(ep::BANKID_AUTH, &csrf, &serde_json::json!({"mobile": true, "generateQrData": true}))
            .await?;

        // The real page always polls BANKID_QR at least once right after
        // auth, before ever touching collect-login. Untested whether that's
        // load-bearing (maybe it's what actually registers the order with
        // BankID's own backend) or just UI — cheap to match either way.
        let _: Result<serde_json::Value> = self.http.post_json(ep::BANKID_QR, &csrf, &()).await;
        Ok((order, csrf))
    }

    /// The part that needs a real browser: poll `collect-login` — same
    /// endpoint, body and session `create_order` used — but run as a
    /// `fetch()` from inside actual page JS instead of from `reqwest`.
    async fn wait_for_completion(
        &self,
        order_ref: &str,
        csrf: &str,
        ui: &dyn AuthUi,
    ) -> Result<WillysSession> {
        let profile_dir = std::env::temp_dir().join(format!(
            "kvittokartan-browser-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
        ));
        // Headless: nothing left to click since the whole flow moved to
        // plain fetch() calls (see module docs) — no UI a human ever needs
        // to see, so no window needs to open.
        let mut builder = BrowserConfig::builder().user_data_dir(profile_dir);
        if let Some(bin) = find_browser_binary() {
            builder = builder.chrome_executable(bin);
        }
        let config = builder.build().map_err(|e| Error::Auth(format!("browser config: {e}")))?;
        let (mut browser, mut handler) = Browser::launch(config)
            .await
            .map_err(|e| Error::Auth(format!("could not launch browser: {e}")))?;
        let drain = tokio::spawn(async move { while handler.next().await.is_some() {} });

        let result = self.poll_in_browser(&browser, order_ref, csrf, ui).await;

        browser.close().await.ok();
        drain.abort();
        result
    }

    async fn poll_in_browser(
        &self,
        browser: &Browser,
        order_ref: &str,
        csrf: &str,
        ui: &dyn AuthUi,
    ) -> Result<WillysSession> {
        let page = browser
            .new_page(ep::BASE)
            .await
            .map_err(|e| Error::Auth(format!("could not open a page: {e}")))?;

        // Carry the order's session into the browser — collect-login is
        // scoped to whichever session created the order, and this page just
        // did its own independent (anonymous) page load a moment ago.
        let cookie_params: Vec<CookieParam> = self
            .http
            .session_cookies()
            .into_iter()
            .map(|c| {
                let mut p = CookieParam::new(c.name, c.value);
                p.domain = Some(c.domain);
                p.path = Some(c.path);
                p
            })
            .collect();
        page.set_cookies(cookie_params)
            .await
            .map_err(|e| Error::Auth(format!("could not set cookies in browser: {e}")))?;

        let collect_js = format!(
            "(async () => {{ \
               const r = await fetch('{base}{path}', {{ \
                 method: 'POST', \
                 headers: {{'content-type':'application/json','x-csrf-token':'{csrf}'}}, \
                 credentials: 'include', \
                 body: JSON.stringify({{orderRef:'{order_ref}', rememberMe:'false'}}) \
               }}); \
               const body = await r.json(); \
               return {{status: r.status, body}}; \
             }})()",
            base = ep::BASE,
            path = ep::BANKID_COLLECT,
        );

        let started = std::time::Instant::now();
        loop {
            if started.elapsed() > LOGIN_TIMEOUT {
                return Err(Error::Auth("inloggningen tog för lång tid".into()));
            }
            tokio::time::sleep(POLL_INTERVAL).await;

            #[derive(Deserialize)]
            struct Wrapped {
                status: u16,
                body: serde_json::Value,
            }
            let wrapped: Wrapped = match page
                .evaluate(collect_js.as_str())
                .await
                .ok()
                .and_then(|r| r.into_value::<Wrapped>().ok())
            {
                Some(w) => w,
                None => continue, // transient — page not ready, network blip, etc.
            };
            if wrapped.status != 200 {
                continue;
            }
            let Ok(collect) = serde_json::from_value::<CollectResponse>(wrapped.body) else {
                continue;
            };

            match collect.status.as_str() {
                "COMPLETE" => {
                    ui.status("Inloggad, avslutar...");
                    let raw_cookies = page
                        .get_cookies()
                        .await
                        .map_err(|e| Error::Auth(format!("could not read cookies: {e}")))?;
                    let cookies: Vec<Cookie> = raw_cookies
                        .into_iter()
                        .filter(|c| c.domain.contains("willys.se"))
                        .map(|c| Cookie {
                            name: c.name,
                            value: c.value,
                            domain: c.domain,
                            path: c.path,
                        })
                        .collect();
                    return Ok(WillysSession {
                        cookies,
                        csrf_token: Some(csrf.to_string()),
                        expires_at: None,
                        refresh_token: None,
                        customer_id: collect.ssn,
                    });
                }
                "PENDING" => continue,
                other => return Err(Error::Auth(format!("BankID: {other}"))),
            }
        }
    }
}

/// Prefer a real, already-installed browser over whatever chromiumoxide
/// would download — the user has one, no need to fetch another.
fn find_browser_binary() -> Option<String> {
    if let Ok(p) = std::env::var("KVITTOKARTAN_BROWSER_PATH") {
        return Some(p);
    }
    ["brave-browser", "google-chrome", "chromium", "chromium-browser"]
        .into_iter()
        .find_map(|name| which(name))
}

fn which(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths).find_map(|dir| {
            let candidate = dir.join(name);
            candidate.is_file().then(|| candidate.to_string_lossy().into_owned())
        })
    })
}
