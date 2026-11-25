// fetch: download one public reference page (egress guarded, bounded in
// size, time and concurrency) and return its structured text.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::egress::{self, Policy};
use crate::extract::{self, Link, Section};
use crate::render::Renderer;

pub const MAX_BYTES: usize = 8 << 20;
const MAX_TEXT: usize = 2 << 20;

#[derive(Deserialize)]
pub struct FetchRequest {
    pub url: String,
    // Extra words to favour when the page must be cut (a dataset heading).
    #[serde(default)]
    pub focus: Option<Vec<String>>,
    pub max_chars: usize,
}

#[derive(Serialize, Debug)]
pub struct FetchResponse {
    pub url: String,
    pub final_url: String,
    pub content_type: String,
    pub title: String,
    pub text: String,
    pub truncated: bool,
    pub total_chars: usize,
    pub sections: Vec<Section>,
    pub links: Vec<Link>,
    pub rendered: bool,
    // OpenAPI-looking files the rendered page downloaded
    pub downloaded_specs: Vec<String>,
}

#[derive(Debug)]
pub enum FetchError {
    Refused(String),  // the URL itself is not allowed
    Upstream(String), // the page could not be read
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FetchError::Refused(m) => write!(f, "refused: {m}"),
            FetchError::Upstream(m) => write!(f, "{m}"),
        }
    }
}

#[derive(Clone)]
pub struct Fetcher {
    pub http: reqwest::Client,
    pub policy: Policy,
    pub slots: Arc<Semaphore>,
    // None when CB_DOC_RENDERER=off: JavaScript-only pages stay unreadable.
    pub renderer: Option<Arc<Renderer>>,
}

// A JavaScript-built page has (almost) no text until rendered.
const THIN_PAGE: usize = 1500;

fn chars(p: &extract::Page) -> usize {
    p.sections.iter().map(|s| s.chars).sum()
}

impl Fetcher {
    pub fn clone_handle(&self) -> Fetcher {
        self.clone()
    }

    /// Raw bytes, content type and final URL of one public reference. With
    /// prefix, a larger body is cut at limit instead of refused.
    pub async fn get(
        &self,
        raw: &str,
        accept: &str,
        limit: usize,
        prefix: bool,
    ) -> Result<(Vec<u8>, String, String), FetchError> {
        let mut u = egress::check_url(raw, self.policy).map_err(FetchError::Refused)?;
        u.set_fragment(None);
        let _slot = self
            .slots
            .acquire()
            .await
            .map_err(|_| FetchError::Upstream("reader closed".into()))?;
        let mut res = self
            .http
            .get(u.clone())
            .header("Accept", accept)
            .send()
            .await
            .map_err(|e| {
                FetchError::Upstream(if e.is_redirect() {
                    "redirect not followed".into()
                } else {
                    "page could not be reached".into()
                })
            })?;
        if res.status() != 200 {
            return Err(FetchError::Upstream(format!(
                "page returned HTTP {}; provide its final public URL",
                res.status().as_u16()
            )));
        }
        let ct = res
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !(ct.contains("text/") || ct.contains("json") || ct.contains("yaml")) {
            return Err(FetchError::Upstream(
                "use a text, HTML, JSON or YAML reference".into(),
            ));
        }
        let final_url = res.url().to_string();
        let mut body = Vec::new();
        while let Some(chunk) = res
            .chunk()
            .await
            .map_err(|_| FetchError::Upstream("download interrupted".into()))?
        {
            if body.len() + chunk.len() > limit {
                if prefix {
                    body.extend_from_slice(&chunk[..limit - body.len()]);
                    break;
                }
                return Err(FetchError::Upstream(format!(
                    "document larger than {} MiB",
                    limit >> 20
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok((body, ct, final_url))
    }

    pub async fn fetch(&self, req: FetchRequest) -> Result<FetchResponse, FetchError> {
        let max_chars = req.max_chars.clamp(1000, MAX_TEXT);
        let fragment = url::Url::parse(&req.url)
            .ok()
            .and_then(|u| u.fragment().map(str::to_owned));
        let mut failed = None;
        let mut parsed = None;
        match self
            .get(
                &req.url,
                "text/html, text/plain, application/json",
                MAX_BYTES,
                false,
            )
            .await
        {
            Ok((body, ct, final_url)) => {
                let body = String::from_utf8_lossy(&body);
                let base = url::Url::parse(&final_url)
                    .map_err(|_| FetchError::Upstream("bad final URL".into()))?;
                let page = if ct.contains("html") {
                    extract::html(&body, &base)
                } else {
                    extract::text(&body)
                };
                parsed = Some((page, ct, final_url));
            }
            Err(FetchError::Refused(m)) => return Err(FetchError::Refused(m)),
            Err(e) => failed = Some(e),
        }
        let mut rendered = false;
        let mut downloaded_specs = vec![];
        let thin = parsed
            .as_ref()
            .is_none_or(|(p, ct, _)| ct.contains("html") && chars(p) < THIN_PAGE);
        if thin && let Some(r) = &self.renderer {
            match r.render(&req.url).await {
                Ok(out) => {
                    downloaded_specs = out.specs;
                    if let Ok(base) = url::Url::parse(&out.final_url) {
                        let page = extract::html(&out.html, &base);
                        if parsed
                            .as_ref()
                            .is_none_or(|(p, _, _)| chars(&page) > chars(p))
                        {
                            parsed = Some((page, "text/html; rendered".into(), out.final_url));
                            rendered = true;
                        }
                    }
                }
                Err(e) => tracing::info!(url = %req.url, reason = %e, "render failed"),
            }
        }
        let Some((mut page, ct, final_url)) = parsed else {
            return Err(failed.unwrap_or(FetchError::Upstream("page could not be read".into())));
        };
        if let Some(f) = fragment.filter(|f| !f.is_empty()) {
            page.sections = extract::focus_fragment(page.sections, &f);
        }
        let total_chars = page.sections.iter().map(|s| s.chars).sum();
        let (text, truncated) = extract::select(
            &page.sections,
            req.focus.as_deref().unwrap_or_default(),
            max_chars,
        );
        if text.trim().len() < 20 {
            return Err(FetchError::Upstream(
                "page has no usable public API text".into(),
            ));
        }
        Ok(FetchResponse {
            url: req.url,
            final_url,
            content_type: ct,
            title: page.title,
            text,
            truncated,
            total_chars,
            sections: page.sections,
            links: page.links,
            rendered,
            downloaded_specs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn serve(response: &'static str) -> String {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(response.as_bytes()).await;
            }
        });
        format!("http://{addr}/docs/users#list-users")
    }

    fn fetcher(policy: Policy) -> Fetcher {
        Fetcher {
            http: egress::client(policy, Duration::from_secs(5)),
            policy,
            slots: Arc::new(Semaphore::new(2)),
            renderer: None,
        }
    }

    #[tokio::test]
    async fn reads_and_focuses_a_page() {
        let url = serve("HTTP/1.1 200 OK\r\ncontent-type: text/html\r\nconnection: close\r\n\r\n<h1>API</h1><p>intro text here</p><h2 id=\"list-users\">List users</h2><p>GET /api/v1/users with Authorization: Bearer token</p><h2>Other</h2><p>x</p>").await;
        let r = fetcher(Policy::loopback_for_tests())
            .fetch(FetchRequest {
                url,
                focus: None,
                max_chars: 40_000,
            })
            .await
            .unwrap();
        assert!(r.text.starts_with("List users"), "{}", r.text);
        assert!(!r.text.contains("Other"));
    }

    #[tokio::test]
    async fn production_policy_refuses_loopback() {
        let url = serve("HTTP/1.1 200 OK\r\n\r\n").await;
        let https = url.replace("http://", "https://");
        let e = fetcher(Policy::production())
            .fetch(FetchRequest {
                url: https,
                focus: None,
                max_chars: 40_000,
            })
            .await;
        assert!(matches!(e, Err(FetchError::Refused(_))), "{e:?}");
    }

    #[tokio::test]
    async fn refuses_non_200_and_binary() {
        let url =
            serve("HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
        assert!(matches!(
            fetcher(Policy::loopback_for_tests())
                .fetch(FetchRequest {
                    url,
                    focus: None,
                    max_chars: 40_000
                })
                .await,
            Err(FetchError::Upstream(_))
        ));
        let url = serve("HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\nconnection: close\r\n\r\nxx").await;
        assert!(matches!(
            fetcher(Policy::loopback_for_tests())
                .fetch(FetchRequest {
                    url,
                    focus: None,
                    max_chars: 40_000
                })
                .await,
            Err(FetchError::Upstream(_))
        ));
    }
}
