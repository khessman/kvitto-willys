//! Throwaway: dump the willys.se login page's HTML + a screenshot so we can
//! find the right selectors for the BankID button / QR / autostart link.
//! Not part of the app. Run with: cargo run -p kvitto-willys --example inspect_login

use chromiumoxide::handler::viewport::Viewport;
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;

const MOBILE_UA: &str = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let profile_dir = std::env::temp_dir().join(format!(
        "kvittokartan-inspect-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()
    ));
    let (mut browser, mut handler) = Browser::launch(
        BrowserConfig::builder()
            .with_head()
            .user_data_dir(profile_dir)
            .arg(format!("--user-agent={MOBILE_UA}"))
            .viewport(Viewport {
                width: 390,
                height: 844,
                device_scale_factor: Some(3.0),
                emulating_mobile: true,
                is_landscape: false,
                has_touch: true,
            })
            .build()?,
    )
    .await?;
    let drain = tokio::spawn(async move { while handler.next().await.is_some() {} });

    let page = browser.new_page("https://www.willys.se/anvandare/inloggning").await?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Cookie banner overlays the modal and swallows the tab click otherwise.
    for text_hint in ["#onetrust-reject-all-handler", "button#onetrust-accept-btn-handler"] {
        if let Ok(btn) = page.find_element(text_hint).await {
            btn.click().await.ok();
            println!("clicked cookie button {text_hint}");
            break;
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    if let Ok(tab) = page.find_element("button[data-tabkey=\"bankId\"]").await {
        tab.click().await?;
        println!("clicked bankId tab");
    } else {
        println!("no bankId tab found");
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    use chromiumoxide::cdp::browser_protocol::page::EventFrameRequestedNavigation;
    let mut nav_events = page.event_listener::<EventFrameRequestedNavigation>().await?;

    for btn in page.find_elements("button").await.unwrap_or_default() {
        if btn.inner_text().await.ok().flatten().as_deref() == Some("Starta BankID-appen") {
            btn.click().await?;
            println!("clicked Starta BankID-appen");
            break;
        }
    }

    match tokio::time::timeout(std::time::Duration::from_secs(5), nav_events.next()).await {
        Ok(Some(ev)) => println!("NAV EVENT url = {}", ev.url),
        Ok(None) => println!("nav event stream ended"),
        Err(_) => println!("no nav event within 5s"),
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let html = page.content().await?;
    std::fs::write("/tmp/willys-login.html", &html)?;
    println!("wrote {} bytes to /tmp/willys-login.html", html.len());

    let shot = page.screenshot(chromiumoxide::page::ScreenshotParams::builder().build()).await?;
    std::fs::write("/tmp/willys-login.png", &shot)?;
    println!("wrote {} bytes to /tmp/willys-login.png", shot.len());

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    browser.close().await.ok();
    drain.abort();
    Ok(())
}
