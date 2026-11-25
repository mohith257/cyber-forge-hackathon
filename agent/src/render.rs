// Headless rendering for JavaScript-only docs pages. Chrome runs in its OWN
// container (CB_DOC_RENDERER); the agent drives it over DevTools and pauses
// every request the page makes: each must pass the same egress rules as a
// plain fetch (https, port 443, every resolved IP public), or it is failed.
// Chrome resolves DNS again after this check, so the renderer container must
// also sit on a network without internal services: interception is the
// second line, not the only one. Each render gets a fresh browser context
// (no cookies or storage shared between renders) and invalid TLS is refused.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, EventRequestPaused, FailRequestParams,
};
use chromiumoxide::cdp::browser_protocol::network::{ErrorReason, ResourceType};
use chromiumoxide::cdp::browser_protocol::target::{
    CreateBrowserContextParams, CreateTargetParams,
};
use chromiumoxide::handler::HandlerConfig;
use chromiumoxide::{Browser, Page};
use futures_util::StreamExt;
use serde::Serialize;
use url::Url;

use crate::egress::{self, Policy};

const RENDER_TIMEOUT: Duration = Duration::from_secs(30);
const SETTLE: Duration = Duration::from_secs(2); // let the docs app fetch and draw
pub const MAX_HTML: usize = 16 << 20;

#[derive(Serialize, Debug, Default)]
pub struct Rendered {
    pub final_url: String,
    pub html: String,
    pub text: String,
    pub specs: Vec<String>, // OpenAPI-looking files the page downloaded
}

pub struct Renderer {
    devtools: Url,
    policy: Policy,
    slots: tokio::sync::Semaphore, // Chrome is heavy: two pages at a time
}

/// spec_file: a .json/.yaml/.yml path (query ignored).
pub fn spec_file(raw: &str) -> bool {
    Url::parse(raw).is_ok_and(|u| {
        let p = u.path().to_ascii_lowercase();
        p.ends_with(".json") || p.ends_with(".yaml") || p.ends_with(".yml")
    })
}

/// The production egress rules for one browser request.
pub async fn allowed(raw: &str, kind: &ResourceType, policy: Policy) -> bool {
    if matches!(
        kind,
        ResourceType::Image | ResourceType::Media | ResourceType::Font
    ) {
        return false; // not needed for API text; less traffic
    }
    let Ok(u) = egress::check_url(raw, policy) else {
        return false;
    };
    let Some(host) = u.host_str() else {
        return false;
    };
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return true; // literal IPs were already checked by check_url
    }
    match tokio::net::lookup_host((host, 443)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            !addrs.is_empty() && addrs.iter().all(|a| egress::check_ip(a.ip()).is_ok())
        }
        Err(_) => false,
    }
}

impl Renderer {
    /// devtools: CB_DOC_RENDERER, e.g. http://renderer:9222.
    pub fn new(devtools: &str, policy: Policy) -> Result<Self, String> {
        let u = Url::parse(devtools).map_err(|_| {
            "CB_DOC_RENDERER must be the renderer's http:// DevTools address".to_string()
        })?;
        if u.scheme() != "http" || u.host_str().is_none() {
            return Err("CB_DOC_RENDERER must be the renderer's http:// DevTools address".into());
        }
        Ok(Renderer {
            devtools: u,
            policy,
            slots: tokio::sync::Semaphore::new(2),
        })
    }

    // Chrome refuses DevTools requests whose Host header is a name, not an IP.
    async fn endpoint(&self) -> Result<String, String> {
        let host = self.devtools.host_str().unwrap_or_default();
        let port = self.devtools.port().unwrap_or(9222);
        let ip = tokio::net::lookup_host((host, port))
            .await
            .ok()
            .and_then(|mut a| a.next())
            .ok_or("renderer unreachable")?;
        Ok(format!("http://{ip}"))
    }

    pub async fn render(&self, raw: &str) -> Result<Rendered, String> {
        egress::check_url(raw, self.policy)?;
        let _slot = tokio::time::timeout(RENDER_TIMEOUT, self.slots.acquire())
            .await
            .map_err(|_| "renderer busy".to_string())?
            .map_err(|_| "renderer closed".to_string())?;
        match tokio::time::timeout(RENDER_TIMEOUT, self.render_inner(raw)).await {
            Ok(r) => r,
            Err(_) => Err("the documentation page could not be rendered in time".into()),
        }
    }

    async fn render_inner(&self, raw: &str) -> Result<Rendered, String> {
        let config = HandlerConfig {
            request_intercept: true,
            ignore_https_errors: false,
            ..Default::default()
        };
        let (browser, mut handler) = Browser::connect_with_config(self.endpoint().await?, config)
            .await
            .map_err(|_| "renderer unreachable".to_string())?;
        let driver = tokio::spawn(async move { while handler.next().await.is_some() {} });
        let result = self.load(&browser, raw).await;
        // Never Browser.close: that shuts down the shared Chrome. load() already
        // disposed this render's context; dropping the socket ends the session.
        driver.abort();
        drop(browser);
        result
    }

    async fn load(&self, browser: &Browser, raw: &str) -> Result<Rendered, String> {
        let fail = |_| "the documentation page could not be rendered".to_string();
        let ctx = browser
            .create_browser_context(CreateBrowserContextParams::default())
            .await
            .map_err(fail)?;
        let target = CreateTargetParams::builder()
            .url("about:blank")
            .browser_context_id(ctx.clone())
            .build()
            .map_err(|_| "bad target".to_string())?;
        let page = browser.new_page(target).await.map_err(fail)?;
        let specs = Arc::new(Mutex::new(Vec::<String>::new()));
        let guard = self.intercept(&page, specs.clone()).await?;
        let loaded = async {
            page.goto(raw).await.map_err(fail)?;
            tokio::time::sleep(SETTLE).await;
            let mut html = page.content().await.map_err(fail)?;
            let text: String = page
                .evaluate("document.body ? document.body.innerText : ''")
                .await
                .map_err(fail)?
                .into_value()
                .unwrap_or_default();
            let final_url = page
                .url()
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| raw.to_string());
            if html.len() > MAX_HTML {
                html = crate::extract::cut(&html, MAX_HTML).to_string();
            }
            Ok::<_, String>(Rendered {
                final_url,
                html,
                text,
                specs: vec![],
            })
        }
        .await;
        guard.abort();
        let _ = page.close().await;
        let _ = browser.dispose_browser_context(ctx).await;
        let mut out = loaded?;
        out.specs = specs.lock().map(|s| s.clone()).unwrap_or_default();
        Ok(out)
    }

    /// Pauses every page request and continues only those the egress rules allow.
    async fn intercept(
        &self,
        page: &Page,
        specs: Arc<Mutex<Vec<String>>>,
    ) -> Result<tokio::task::JoinHandle<()>, String> {
        let mut paused = page
            .event_listener::<EventRequestPaused>()
            .await
            .map_err(|_| "renderer interception failed".to_string())?;
        let page = page.clone();
        let policy = self.policy;
        Ok(tokio::spawn(async move {
            while let Some(ev) = paused.next().await {
                let url = ev.request.url.clone();
                if allowed(&url, &ev.resource_type, policy).await {
                    if spec_file(&url)
                        && let Ok(mut s) = specs.lock()
                        && s.len() < 5
                    {
                        s.push(url.split('?').next().unwrap_or(&url).to_string());
                    }
                    let _ = page
                        .execute(ContinueRequestParams::new(ev.request_id.clone()))
                        .await;
                } else {
                    tracing::info!(url = %crate::extract::cut(&url, 200), "render request blocked");
                    let _ = page
                        .execute(FailRequestParams::new(
                            ev.request_id.clone(),
                            ErrorReason::BlockedByClient,
                        ))
                        .await;
                }
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn browser_requests_follow_egress_rules() {
        let p = Policy::production();
        assert!(!allowed("https://169.254.169.254/latest", &ResourceType::Xhr, p).await);
        assert!(!allowed("http://example.com/x.js", &ResourceType::Script, p).await);
        assert!(!allowed("https://example.com:8443/x.js", &ResourceType::Script, p).await);
        assert!(
            !allowed("https://localhost/x", &ResourceType::Xhr, p).await,
            "name resolving to loopback"
        );
        assert!(
            !allowed("https://example.com/logo.png", &ResourceType::Image, p).await,
            "images skipped"
        );
    }

    #[test]
    fn spec_files() {
        assert!(spec_file("https://x.io/openapi.yaml?v=2"));
        assert!(!spec_file("https://x.io/docs/api"));
    }

    #[test]
    fn devtools_address_validated() {
        assert!(Renderer::new("http://renderer:9222", Policy::production()).is_ok());
        assert!(Renderer::new("renderer:9222", Policy::production()).is_err());
        assert!(Renderer::new("https://renderer:9222", Policy::production()).is_err());
    }
}
