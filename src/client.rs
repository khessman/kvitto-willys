use crate::chain::Chain;
use crate::endpoints as ep;
use crate::session::{Cookie, AxfoodSession};
use kvitto_core::{Error, Result};
use reqwest::cookie::CookieStore;
use std::sync::Arc;
use std::time::Duration;

/// Cookies, CSRF, throttling, and the single place a 401/403 becomes
/// `SessionExpired` — so the dashboard knows to prompt for BankID again rather
/// than reporting a confusing parse failure.
///
/// Cookies are held in an explicit `reqwest::cookie::Jar` rather than the
/// client builder's opaque built-in store, because `auth::finish` needs to
/// read them back out afterwards to build a `AxfoodSession` — the whole
/// point of `MemorySessionStore` is that a session survives without ever
/// touching disk, so it has to come from somewhere introspectable.
pub struct AxfoodHttp {
    pub chain: Chain,
    pub http: reqwest::Client,
    jar: Arc<reqwest::cookie::Jar>,
    pub session: Option<AxfoodSession>,
    last_call: std::sync::Mutex<Option<std::time::Instant>>,
}

impl AxfoodHttp {
    pub fn new(chain: Chain) -> Result<Self> {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let http = reqwest::Client::builder()
            .cookie_provider(jar.clone())
            .user_agent(ep::USER_AGENT)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| Error::Transport(e.to_string()))?;
        Ok(Self { chain, http, jar, session: None, last_call: std::sync::Mutex::new(None) })
    }

    /// Restore cookies from a previously saved session, e.g. after loading
    /// one from `SessionStore` instead of running BankID again.
    pub fn restore(&self, session: &AxfoodSession) {
        let url: reqwest::Url = self.chain.base().parse().expect("chain base is a valid URL");
        for c in &session.cookies {
            let set_cookie = format!("{}={}; Domain={}; Path={}", c.name, c.value, c.domain, c.path);
            self.jar.add_cookie_str(&set_cookie, &url);
        }
    }

    /// Everything the jar currently holds for the chain's base URL,
    /// flattened into the name/value pairs `AxfoodSession` stores.
    /// Domain/path are not recoverable from `Jar::cookies` (it only
    /// serialises a `Cookie:` header value), so they're filled in as the
    /// base URL's own host — harmless, since `AxfoodSession::cookie_header`
    /// only ever re-joins name=value pairs.
    pub fn session_cookies(&self) -> Vec<Cookie> {
        let url: reqwest::Url = self.chain.base().parse().expect("chain base is a valid URL");
        let domain = url.host_str().unwrap_or_default().to_string();
        match self.jar.cookies(&url) {
            Some(header) => header
                .to_str()
                .unwrap_or_default()
                .split("; ")
                .filter_map(|pair| pair.split_once('='))
                .map(|(name, value)| Cookie {
                    name: name.to_string(),
                    value: value.to_string(),
                    domain: domain.clone(),
                    path: "/".to_string(),
                })
                .collect(),
            None => Vec::new(),
        }
    }

    fn throttle(&self) {
        let mut guard = self.last_call.lock().unwrap();
        if let Some(prev) = *guard {
            let min = Duration::from_millis(ep::REQUEST_DELAY_MS);
            if prev.elapsed() < min {
                std::thread::sleep(min - prev.elapsed());
            }
        }
        *guard = Some(std::time::Instant::now());
    }

    /// Consumes the response so the body can be quoted in the error — a bare
    /// status code is useless when the failure is a WAF/CDN block rather
    /// than the application (CloudFront fronts willys.se; see the `server`/
    /// `x-cf-stack` headers in the HAR capture).
    async fn check_status(path: &str, resp: reqwest::Response) -> Result<reqwest::Response> {
        let status = resp.status().as_u16();
        match status {
            200..=299 => Ok(resp),
            401 | 403 => Err(Error::SessionExpired),
            _ => {
                let headers: String = resp
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap_or("<binary>")))
                    .collect::<Vec<_>>()
                    .join(" | ");
                let body = resp.text().await.unwrap_or_default();
                let snippet: String = body.chars().take(500).collect();
                Err(Error::Transport(format!("{path} -> HTTP {status}\nHEADERS: {headers}\nBODY: {snippet}")))
            }
        }
    }

    /// Headers a bare `reqwest` client doesn't send by default but a real
    /// browser always does. Missing these is a plausible reason a CDN-level
    /// bot filter would 503 a request the app itself would have accepted —
    /// TLS fingerprinting could still block it regardless, but this is the
    /// cheap thing to rule out first.
    fn browser_headers(rb: reqwest::RequestBuilder, base: &str) -> reqwest::RequestBuilder {
        rb.header("accept", "*/*")
            .header("accept-language", "en-US,en;q=0.9")
            .header("origin", base)
            .header("referer", format!("{base}/"))
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-origin")
            // Every captured browser request carried a W3C traceparent (New
            // Relic browser-agent instrumentation). Speculative: some gateway
            // rule on the higher-value endpoints (collect-login) may use its
            // absence as a bot signal. Standard header, nothing sneaky — just
            // completing the shape a real browser already sends.
            .header("traceparent", random_traceparent())
    }

    /// Load the homepage once, purely for its `Set-Cookie`s. The real
    /// browser always has a Hybris session cookie (and presumably an
    /// anonymous cart) in place before the first `checkout/bankid/*` call —
    /// our client starts from an empty jar, which is a plausible reason
    /// `collect-login` answers `OUTOFSERVICE_ERROR` where a browser wouldn't.
    pub async fn warm_up(&self) -> Result<()> {
        self.throttle();
        let rb = self
            .http
            .get(self.chain.base())
            .header("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("accept-language", "en-US,en;q=0.9")
            .header("sec-fetch-dest", "document")
            .header("sec-fetch-mode", "navigate")
            .header("sec-fetch-site", "none");
        let resp = rb.send().await.map_err(|e| Error::Transport(format!("warm_up: {e}")))?;
        Self::check_status("warm_up", resp).await?;
        Ok(())
    }

    /// GET with no auth requirement — cookies still ride along via the jar,
    /// but no session or CSRF header is required. Used for `CSRF_TOKEN`
    /// itself, before there is anything to authenticate with.
    pub async fn get_json_unauthenticated<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T> {
        self.throttle();
        let rb = Self::browser_headers(
            self.http.get(format!("{}{}", self.chain.base(), path)),
            self.chain.base(),
        )
        .header(ep::REQUESTED_WITH, "XMLHttpRequest");
        let resp = rb.send().await.map_err(|e| Error::Transport(format!("{path}: {e}")))?;
        Self::check_status(path, resp)
            .await?
            .json()
            .await
            .map_err(|e| Error::Transport(format!("{path} (decoding): {e}")))
    }

    /// POST with an explicit CSRF token, for the BankID handshake before a
    /// session exists to pull the token from.
    pub async fn post_json<B: serde::Serialize + ?Sized, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        csrf: &str,
        body: &B,
    ) -> Result<T> {
        self.throttle();
        let rb = Self::browser_headers(
            self.http.post(format!("{}{}", self.chain.base(), path)),
            self.chain.base(),
        )
        .header(ep::REQUESTED_WITH, "XMLHttpRequest")
        .header(ep::CSRF_HEADER, csrf)
        .json(body);
        let resp = rb.send().await.map_err(|e| Error::Transport(format!("{path}: {e}")))?;
        Self::check_status(path, resp)
            .await?
            .json()
            .await
            .map_err(|e| Error::Transport(format!("{path} (decoding): {e}")))
    }

    /// GET for post-login calls (receipt list/detail): requires a live
    /// session and attaches its CSRF token.
    pub fn request(&self, method: reqwest::Method, path: &str) -> Result<reqwest::RequestBuilder> {
        self.throttle();
        let s = self.session.as_ref().ok_or(Error::NotAuthenticated("willys"))?;
        let mut rb = Self::browser_headers(
            self.http.request(method, format!("{}{}", self.chain.base(), path)),
            self.chain.base(),
        )
        .header(ep::REQUESTED_WITH, "XMLHttpRequest");
        if let Some(t) = &s.csrf_token {
            rb = rb.header(ep::CSRF_HEADER, t);
        }
        Ok(rb)
    }

    pub async fn send(&self, path: &str, rb: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let resp = rb.send().await.map_err(|e| Error::Transport(format!("{path}: {e}")))?;
        Self::check_status(path, resp).await
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        let rb = self.request(reqwest::Method::GET, path)?;
        self.send(path, rb)
            .await?
            .json()
            .await
            .map_err(|e| Error::Transport(format!("{path} (decoding): {e}")))
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let rb = self.request(reqwest::Method::GET, path)?;
        let resp = self.send(path, rb).await?;
        Ok(resp.bytes().await.map_err(|e| Error::Transport(format!("{path}: {e}")))?.to_vec())
    }

    /// Like `get_bytes`, but also hands back the `content-type` — for
    /// probing an endpoint whose media type (JSON? PDF?) isn't known yet.
    pub async fn get_bytes_with_content_type(&self, path: &str) -> Result<(String, Vec<u8>)> {
        let rb = self.request(reqwest::Method::GET, path)?;
        let resp = self.send(path, rb).await?;
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();
        let bytes = resp.bytes().await.map_err(|e| Error::Transport(format!("{path}: {e}")))?.to_vec();
        Ok((content_type, bytes))
    }
}

/// A syntactically valid W3C traceparent (`00-<32 hex trace id>-<16 hex span
/// id>-01`). Random, not tied to any real trace — good enough if the check
/// on the other end is "does this header exist and look real", not "does it
/// correlate with a New Relic session".
fn random_traceparent() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        ^ COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed).wrapping_mul(0x9E3779B97F4A7C15);
    let mut hex = |n: usize| -> String {
        (0..n)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                std::char::from_digit(((seed >> 60) & 0xf) as u32, 16).unwrap()
            })
            .collect()
    };
    format!("00-{}-{}-01", hex(32), hex(16))
}
