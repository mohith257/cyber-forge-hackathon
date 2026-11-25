// Gemini calls for the discovery loop: a grounded web search (returns the
// pages Google Search actually visited and the queries it ran) and a strict
// JSON planning call. Search + strict JSON in one call silently skips the
// search, so they stay separate.

use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::egress::{self, Policy};

#[derive(Serialize, Clone, Copy, Default, Debug)]
pub struct Usage {
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub total_tokens: i64,
}

impl Usage {
    pub fn add(&mut self, u: Usage) {
        self.input_tokens += u.input_tokens;
        self.output_tokens += u.output_tokens;
        self.total_tokens += u.total_tokens;
    }
}

#[derive(Debug)]
pub enum GemError {
    RateLimited,
    Busy,
    KeyRejected,
    Bad(String),
}

impl std::fmt::Display for GemError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            GemError::RateLimited => write!(f, "provider rate limit, try again in a minute"),
            GemError::Busy => write!(f, "provider busy"),
            GemError::KeyRejected => write!(f, "Gemini key rejected"),
            GemError::Bad(m) => write!(f, "{m}"),
        }
    }
}

pub struct Answer {
    pub text: String,
    pub sources: Vec<(String, String)>, // grounding URI (often a redirect), title
    pub queries: Vec<String>,
    pub usage: Usage,
}

pub struct Gemini {
    http: reqwest::Client,
    key: String,
    model: String,
    base: String,
}

const MAX_RESPONSE: usize = 4 << 20;

impl Gemini {
    pub fn new(key: String, model: String, policy: Policy) -> Self {
        Gemini {
            http: egress::client(policy, Duration::from_secs(120)),
            key,
            model,
            base: "https://generativelanguage.googleapis.com/v1beta/models/".into(),
        }
    }
    #[cfg(test)]
    pub fn with_base(mut self, base: String) -> Self {
        self.base = base;
        self
    }

    async fn once(&self, body: &Value) -> Result<Answer, (GemError, Duration)> {
        let url = format!("{}{}:generateContent", self.base, self.model);
        let res = self
            .http
            .post(url)
            .header("x-goog-api-key", &self.key) // header, never the URL: URLs get logged
            .json(body)
            .send()
            .await
            .map_err(|_| (GemError::Bad("provider unreachable".into()), Duration::ZERO))?;
        match res.status().as_u16() {
            200 => {}
            429 => return Err((GemError::RateLimited, Duration::from_secs(10))),
            500 | 503 => return Err((GemError::Busy, Duration::from_secs(5))),
            401 | 403 => return Err((GemError::KeyRejected, Duration::ZERO)),
            s => return Err((GemError::Bad(format!("provider HTTP {s}")), Duration::ZERO)), // body not echoed
        }
        let b = res
            .bytes()
            .await
            .map_err(|_| (GemError::Bad("no answer".into()), Duration::ZERO))?;
        if b.len() > MAX_RESPONSE {
            return Err((GemError::Bad("answer too large".into()), Duration::ZERO));
        }
        let v: Value = serde_json::from_slice(&b)
            .map_err(|_| (GemError::Bad("no answer".into()), Duration::ZERO))?;
        let mut usage = Usage::default();
        if let (Some(p), Some(t)) = (
            v["usageMetadata"]["promptTokenCount"].as_i64(),
            v["usageMetadata"]["totalTokenCount"].as_i64(),
        ) && t >= p
        {
            usage = Usage {
                input_tokens: p,
                output_tokens: t - p,
                total_tokens: t,
            };
        }
        let c = &v["candidates"][0];
        if c.is_null() {
            return Err((GemError::Bad("no answer".into()), Duration::ZERO));
        }
        if c["finishReason"] == "MAX_TOKENS" {
            return Err((
                GemError::Bad("model output too long".into()),
                Duration::ZERO,
            ));
        }
        let text: String = c["content"]["parts"]
            .as_array()
            .map(|parts| {
                parts
                    .iter()
                    .filter(|p| p["thought"] != true)
                    .filter_map(|p| p["text"].as_str())
                    .collect()
            })
            .unwrap_or_default();
        if text.is_empty() {
            return Err((GemError::Bad("empty answer".into()), Duration::from_secs(1)));
        }
        let gm = &c["groundingMetadata"];
        let sources = gm["groundingChunks"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|ch| {
                        Some((
                            ch["web"]["uri"].as_str()?.to_string(),
                            ch["web"]["title"].as_str().unwrap_or("").to_string(),
                        ))
                    })
                    .take(10)
                    .collect()
            })
            .unwrap_or_default();
        let queries = gm["webSearchQueries"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|q| q.as_str().map(str::to_owned))
                    .take(10)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Answer {
            text,
            sources,
            queries,
            usage,
        })
    }

    // Up to 3 attempts; waits only what the provider asks, capped.
    async fn call(&self, body: Value) -> Result<Answer, GemError> {
        let mut last = GemError::Bad("no answer".into());
        for _ in 0..3 {
            match self.once(&body).await {
                Ok(a) => return Ok(a),
                Err((e, wait)) if wait > Duration::ZERO => {
                    last = e;
                    tokio::time::sleep(wait).await;
                }
                Err((e, _)) => return Err(e),
            }
        }
        Err(last)
    }

    /// One Google-Search-grounded answer.
    pub async fn grounded(&self, prompt: &str) -> Result<Answer, GemError> {
        self.call(json!({
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "tools": [{"google_search": {}}],
            "generationConfig": {"thinkingConfig": {"thinkingLevel": "low"}}
        }))
        .await
    }

    /// One strict-JSON answer (no tools).
    pub async fn json(
        &self,
        system: &str,
        user: &str,
        schema: &Value,
    ) -> Result<(Value, Usage), GemError> {
        let a = self
            .call(json!({
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"responseMimeType": "application/json", "responseJsonSchema": schema,
                    "temperature": 0.2, "maxOutputTokens": 4096, "thinkingConfig": {"thinkingLevel": "low"}}
            }))
            .await?;
        let v = serde_json::from_str(&a.text)
            .map_err(|_| GemError::Bad("planner returned invalid JSON".into()))?;
        Ok((v, a.usage))
    }
}
