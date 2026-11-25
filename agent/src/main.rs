// cb-agent: ConfigBridge's retrieval agent. It is the only component that
// reads the open web for AI drafting: search, page fetch, link crawl, spec
// probing. The Go API calls it on an internal network with a shared token;
// the Go side keeps the deterministic evidence verifier.

mod discover;
mod egress;
mod extract;
mod fetch;
mod gemini;
mod render;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

use fetch::{FetchError, FetchRequest, Fetcher};

struct App {
    token: Vec<u8>,
    fetcher: Fetcher,
    // None when CB_AGENT_SEARCH=off: /v1/discover and /v1/search answer 503.
    tools: Option<discover::Tools>,
    // None when CB_DOC_RENDERER=off: /v1/render answers 503.
    renderer: Option<Arc<render::Renderer>>,
}

#[derive(serde::Deserialize)]
struct RawRequest {
    url: String,
    max_bytes: usize,
}

/// One public file, unparsed (OpenAPI specs: the Go side parses them).
async fn raw_file(State(app): State<Arc<App>>, Json(req): Json<RawRequest>) -> Response {
    let limit = req.max_bytes.clamp(1 << 10, 16 << 20);
    match app
        .fetcher
        .get(
            &req.url,
            "application/json, application/yaml, text/yaml, text/plain",
            limit,
            false,
        )
        .await
    {
        Ok((body, ct, final_url)) => {
            let mut res = body.into_response();
            if let (Ok(ct), Ok(fu)) = (ct.parse(), final_url.parse()) {
                res.headers_mut().insert("content-type", ct);
                res.headers_mut().insert("x-final-url", fu);
            }
            res
        }
        Err(FetchError::Refused(m)) => fail(StatusCode::UNPROCESSABLE_ENTITY, "refused", &m),
        Err(FetchError::Upstream(m)) => fail(StatusCode::BAD_GATEWAY, "upstream", &m),
    }
}

#[derive(serde::Deserialize)]
struct UrlRequest {
    url: String,
}

async fn render_page(State(app): State<Arc<App>>, Json(req): Json<UrlRequest>) -> Response {
    let Some(r) = &app.renderer else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "render_off",
            "rendering is off (CB_DOC_RENDERER=off)",
        );
    };
    if let Err(m) = egress::check_url(&req.url, egress::Policy::production()) {
        return fail(StatusCode::UNPROCESSABLE_ENTITY, "refused", &m);
    }
    match r.render(&req.url).await {
        Ok(out) => Json(out).into_response(),
        Err(m) => fail(StatusCode::BAD_GATEWAY, "upstream", &m),
    }
}

#[derive(serde::Deserialize)]
struct SearchRequest {
    prompt: String,
}

/// One Google-Search-grounded answer, with the queries run and the pages
/// search actually visited (grounding redirects resolved).
async fn search_web(State(app): State<Arc<App>>, Json(req): Json<SearchRequest>) -> Response {
    let Some(tools) = &app.tools else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "search_off",
            "web search is off (CB_AGENT_SEARCH=off)",
        );
    };
    if req.prompt.trim().is_empty() || req.prompt.len() > 20_000 {
        return fail(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "prompt must be 1-20000 characters",
        );
    }
    match tools.gemini.grounded(&req.prompt).await {
        Ok(a) => {
            let mut sources = vec![];
            for (uri, _) in a.sources {
                if let Some(u) = tools.resolve(uri).await
                    && !sources.contains(&u)
                {
                    sources.push(u);
                }
            }
            tracing::info!(queries = ?a.queries, sources = sources.len(), tokens = a.usage.total_tokens, "search");
            Json(
                json!({"text": a.text, "queries": a.queries, "sources": sources, "usage": a.usage}),
            )
            .into_response()
        }
        Err(gemini::GemError::RateLimited) => fail(
            StatusCode::TOO_MANY_REQUESTS,
            "provider",
            "provider rate limit, try again in a minute",
        ),
        Err(e) => fail(StatusCode::BAD_GATEWAY, "provider", &e.to_string()),
    }
}

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!("{name} is required");
            std::process::exit(2);
        }
    }
}

fn fail(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"error": code, "message": message}))).into_response()
}

async fn auth(State(app): State<Arc<App>>, req: Request, next: Next) -> Response {
    let given = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !bool::from(given.as_bytes().ct_eq(&app.token)) {
        return fail(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "agent token required",
        );
    }
    next.run(req).await
}

async fn fetch_page(State(app): State<Arc<App>>, Json(req): Json<FetchRequest>) -> Response {
    let url = req.url.clone();
    match app.fetcher.fetch(req).await {
        Ok(page) => {
            tracing::info!(url = %page.final_url, chars = page.text.len(), total = page.total_chars, truncated = page.truncated, "fetch");
            Json(page).into_response()
        }
        Err(FetchError::Refused(m)) => {
            tracing::warn!(%url, reason = %m, "fetch refused");
            fail(StatusCode::UNPROCESSABLE_ENTITY, "refused", &m)
        }
        Err(FetchError::Upstream(m)) => {
            tracing::info!(%url, reason = %m, "fetch failed");
            fail(StatusCode::BAD_GATEWAY, "upstream", &m)
        }
    }
}

async fn discover_product(
    State(app): State<Arc<App>>,
    Json(req): Json<discover::DiscoverRequest>,
) -> Response {
    let Some(tools) = &app.tools else {
        return fail(
            StatusCode::SERVICE_UNAVAILABLE,
            "search_off",
            "web search is off (CB_AGENT_SEARCH=off)",
        );
    };
    if req.product.trim().is_empty() || req.want.trim().is_empty() {
        return fail(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "product and want are required",
        );
    }
    match discover::run(tools, req).await {
        Ok(out) => {
            tracing::info!(found = out.found, steps = out.trace.len(), tokens = out.usage.total_tokens, reason = %out.reason, "discover");
            Json(out).into_response()
        }
        Err(gemini::GemError::RateLimited) => fail(
            StatusCode::TOO_MANY_REQUESTS,
            "provider",
            "provider rate limit, try again in a minute",
        ),
        Err(e) => fail(StatusCode::BAD_GATEWAY, "provider", &e.to_string()),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
        .init();
    let listen = required("CB_AGENT_LISTEN");
    let token = required("CB_AGENT_TOKEN");
    if token.len() < 32 {
        eprintln!("CB_AGENT_TOKEN must be at least 32 characters");
        std::process::exit(2);
    }
    let policy = egress::Policy::production();
    // Headless Chrome for JavaScript-only docs pages: its own container, or
    // "off". Required explicitly so the choice is visible in .env.
    let renderer = match required("CB_DOC_RENDERER").as_str() {
        "off" => None,
        addr => Some(Arc::new(
            render::Renderer::new(addr, policy).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            }),
        )),
    };
    let fetcher = Fetcher {
        http: egress::client(policy, Duration::from_secs(15)),
        policy,
        slots: Arc::new(Semaphore::new(4)),
        renderer: renderer.clone(),
    };
    // Explicit, like CB_DOC_RENDERER: the choice is visible in .env.
    let tools = match required("CB_AGENT_SEARCH").as_str() {
        "gemini" => {
            let g =
                gemini::Gemini::new(required("GEMINI_API_KEY"), required("CB_AI_MODEL"), policy);
            Some(discover::Tools::new(fetcher.clone(), g, policy))
        }
        "off" => None,
        _ => {
            eprintln!("CB_AGENT_SEARCH must be gemini or off");
            std::process::exit(2);
        }
    };
    let app = Arc::new(App {
        token: token.into_bytes(),
        fetcher,
        tools,
        renderer,
    });
    let api = Router::new()
        .route("/v1/fetch", post(fetch_page))
        .route("/v1/discover", post(discover_product))
        .route("/v1/raw", post(raw_file))
        .route("/v1/render", post(render_page))
        .route("/v1/search", post(search_web))
        .route_layer(middleware::from_fn_with_state(app.clone(), auth))
        .route("/healthz", get(|| async { "ok" }))
        .layer(DefaultBodyLimit::max(64 << 10))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("cannot listen on {listen}: {e}");
            std::process::exit(2);
        });
    tracing::info!(%listen, "cb-agent ready");
    axum::serve(listener, api)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .expect("server");
}
