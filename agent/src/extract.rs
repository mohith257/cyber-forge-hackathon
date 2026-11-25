// Turns a docs page into readable sections instead of regex-stripped soup:
// headings split the page, code blocks and tables keep their shape, and when
// the page is larger than the budget the sections that carry API facts
// (route, auth, pagination, JSON examples) are kept rather than the first N
// characters.

use scraper::{ElementRef, Html, Node};
use serde::Serialize;
use url::Url;

#[derive(Serialize, Clone, Debug)]
pub struct Section {
    pub heading: String,
    pub level: u8,
    #[serde(skip)]
    pub id: String,
    #[serde(skip)]
    pub text: String,
    pub chars: usize,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Link {
    pub url: String,
    pub text: String,
}

pub struct Page {
    pub title: String,
    pub sections: Vec<Section>,
    pub links: Vec<Link>,
}

const SKIP: &[&str] = &[
    "script", "style", "noscript", "svg", "template", "iframe", "nav", "footer", "head",
];
const BLOCK: &[&str] = &[
    "p",
    "div",
    "li",
    "ul",
    "ol",
    "dt",
    "dd",
    "dl",
    "section",
    "article",
    "main",
    "br",
    "hr",
    "tr",
    "blockquote",
    "header",
    "aside",
    "details",
    "summary",
    "figure",
    "caption",
];
const MAX_LINKS: usize = 300;

struct Walker {
    sections: Vec<Section>,
    cur: Section,
    links: Vec<Link>,
    base: Url,
}

fn new_section(heading: String, level: u8, id: String) -> Section {
    Section {
        heading,
        level,
        id,
        text: String::new(),
        chars: 0,
    }
}

fn push_text(buf: &mut String, t: &str) {
    for word in t.split_whitespace() {
        if !buf.is_empty() && !buf.ends_with([' ', '\n']) {
            buf.push(' ');
        }
        buf.push_str(word);
    }
}

fn newline(buf: &mut String) {
    let trimmed = buf.trim_end_matches(' ').len();
    buf.truncate(trimmed);
    if !buf.is_empty() && !buf.ends_with('\n') {
        buf.push('\n');
    }
}

fn plain(el: ElementRef) -> String {
    el.text()
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

impl Walker {
    fn walk(&mut self, el: ElementRef) {
        for child in el.children() {
            match child.value() {
                Node::Text(t) => push_text(&mut self.cur.text, t),
                Node::Element(e) => {
                    let Some(c) = ElementRef::wrap(child) else {
                        continue;
                    };
                    let name = e.name();
                    if SKIP.contains(&name) {
                        if name == "nav" || name == "footer" {
                            self.collect_links(c); // sidebars still lead to other reference pages
                        }
                        continue;
                    }
                    if let Some(level) = name
                        .strip_prefix('h')
                        .and_then(|n| n.parse::<u8>().ok())
                        .filter(|l| (1..=6).contains(l))
                    {
                        let heading = plain(c);
                        let id = e.attr("id").unwrap_or_default().to_string();
                        let done = std::mem::replace(
                            &mut self.cur,
                            new_section(heading.clone(), level, id),
                        );
                        if !done.text.trim().is_empty() || !done.heading.is_empty() {
                            self.sections.push(done);
                        }
                        push_text(&mut self.cur.text, &heading);
                        newline(&mut self.cur.text);
                        continue;
                    }
                    match name {
                        "pre" => {
                            // keep code exactly: JSON examples must stay parseable
                            let code: String = c.text().collect();
                            newline(&mut self.cur.text);
                            self.cur.text.push_str(code.trim_matches('\n'));
                            self.cur.text.push('\n');
                        }
                        "td" | "th" => {
                            self.walk(c);
                            self.cur.text.push_str(" | ");
                        }
                        "a" => {
                            self.add_link(e.attr("href"), &plain(c));
                            self.walk(c);
                        }
                        _ => {
                            let block = BLOCK.contains(&name) || name == "table";
                            if block {
                                newline(&mut self.cur.text);
                            }
                            self.walk(c);
                            if block {
                                newline(&mut self.cur.text);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn collect_links(&mut self, el: ElementRef) {
        for a in el
            .descendants()
            .filter_map(ElementRef::wrap)
            .filter(|a| a.value().name() == "a")
        {
            self.add_link(a.value().attr("href"), &plain(a));
        }
    }

    fn add_link(&mut self, href: Option<&str>, text: &str) {
        let Some(href) = href else { return };
        if self.links.len() >= MAX_LINKS {
            return;
        }
        let Ok(mut u) = self.base.join(href) else {
            return;
        };
        if u.scheme() != "https" {
            return;
        }
        u.set_fragment(None);
        let url = u.to_string();
        if url != self.base.as_str() && !self.links.iter().any(|l| l.url == url) {
            self.links.push(Link {
                url,
                text: text.chars().take(120).collect(),
            });
        }
    }
}

pub fn html(body: &str, base: &Url) -> Page {
    let doc = Html::parse_document(body);
    let title = doc
        .root_element()
        .descendants()
        .filter_map(ElementRef::wrap)
        .find(|e| e.value().name() == "title")
        .map(plain)
        .unwrap_or_default();
    let mut base = base.clone();
    base.set_fragment(None);
    let mut w = Walker {
        sections: vec![],
        cur: new_section(String::new(), 0, String::new()),
        links: vec![],
        base,
    };
    w.walk(doc.root_element());
    let last = std::mem::replace(&mut w.cur, new_section(String::new(), 0, String::new()));
    w.sections.push(last);
    let mut sections: Vec<Section> = w
        .sections
        .into_iter()
        .filter(|s| !s.text.trim().is_empty())
        .collect();
    for s in &mut sections {
        s.text = s.text.trim().to_string();
        s.chars = s.text.len();
    }
    Page {
        title,
        sections,
        links: w.links,
    }
}

/// Plain text, JSON or YAML: one section.
pub fn text(body: &str) -> Page {
    let t = body.trim().to_string();
    Page {
        title: String::new(),
        sections: vec![Section {
            heading: String::new(),
            level: 0,
            id: String::new(),
            chars: t.len(),
            text: t,
        }],
        links: vec![],
    }
}

/// A URL fragment names one operation on a long reference page: keep that
/// heading and everything under it (until the next heading of its level).
/// The chosen operation's block: the section whose heading is the dataset,
/// plus its subsections (until the next heading of its level or higher).
pub fn block_of(sections: &[Section], heading: &str) -> Vec<usize> {
    let norm = |s: &str| {
        s.split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    let want = norm(heading);
    if want.len() < 2 {
        return vec![];
    }
    let Some(start) = sections
        .iter()
        .position(|s| norm(&s.heading) == want)
        .or_else(|| {
            sections
                .iter()
                .position(|s| norm(&s.heading).contains(&want))
        })
    else {
        return vec![];
    };
    let level = sections[start].level;
    let end = sections[start + 1..]
        .iter()
        .position(|s| s.level > 0 && s.level <= level)
        .map_or(sections.len(), |i| start + 1 + i);
    (start..end).collect()
}

pub fn focus_fragment(sections: Vec<Section>, fragment: &str) -> Vec<Section> {
    let Some(start) = sections
        .iter()
        .position(|s| !s.id.is_empty() && s.id == fragment)
    else {
        return sections;
    };
    let level = sections[start].level;
    let end = sections[start + 1..]
        .iter()
        .position(|s| s.level > 0 && s.level <= level)
        .map_or(sections.len(), |i| start + 1 + i);
    sections[start..end].to_vec()
}

// What an API reference section must show for a connector to be built.
const API_TERMS: &[(&str, u32)] = &[
    ("authorization", 4),
    ("bearer", 4),
    ("api key", 3),
    ("api token", 3),
    ("oauth", 3),
    ("access token", 3),
    ("token url", 3),
    ("client credentials", 3),
    ("scope", 1),
    ("pagination", 4),
    ("paginat", 2),
    ("cursor", 3),
    ("next page", 3),
    ("next_page", 3),
    ("\"next", 2),
    ("link header", 3),
    ("per_page", 3),
    ("page_size", 3),
    ("pagesize", 3),
    ("limit", 1),
    ("offset", 1),
    ("response", 2),
    ("example", 1),
    ("request", 1),
    ("rate limit", 1),
    ("base url", 3),
    ("endpoint", 2),
];
const VERBS: &[&str] = &[
    "GET /",
    "GET https://",
    "POST /",
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
];

fn score(s: &Section, focus: &[String]) -> u32 {
    let low = s.text.to_lowercase();
    let mut n = 0;
    for (term, w) in API_TERMS {
        if low.contains(term) {
            n += w;
        }
    }
    for v in VERBS {
        if s.text.contains(v) {
            n += 4;
        }
    }
    if s.text.contains("{\"") || s.text.contains("{\n") {
        n += 4; // a JSON example: response fields and the records path live here
    }
    for f in focus {
        if !f.is_empty()
            && (low.contains(f.as_str()) || s.heading.to_lowercase().contains(f.as_str()))
        {
            n += 6;
        }
    }
    n
}

const SECTION_CAP: usize = 12_000;

/// Keeps the page whole when it fits; otherwise the intro plus the
/// highest-scoring sections, in page order, within max_chars.
pub fn select(sections: &[Section], focus: &[String], max_chars: usize) -> (String, bool) {
    select_pinned(sections, &[], focus, max_chars)
}

/// Like select, but the pinned sections (the chosen operation's block) go in
/// first, before any scored section.
pub fn select_pinned(
    sections: &[Section],
    pinned: &[usize],
    focus: &[String],
    max_chars: usize,
) -> (String, bool) {
    let join = |picked: &[usize]| {
        picked
            .iter()
            .map(|&i| sections[i].text.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    let all: Vec<usize> = (0..sections.len()).collect();
    let whole = join(&all);
    if whole.len() <= max_chars {
        return (whole, false);
    }
    let focus: Vec<String> = focus.iter().map(|f| f.to_lowercase()).collect();
    let mut ranked: Vec<(u32, usize)> = sections
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(i, _)| !pinned.contains(i))
        .map(|(i, s)| (score(s, &focus), i))
        .filter(|(sc, _)| *sc > 0)
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut picked = vec![];
    let mut used = 0;
    if let Some(first) = sections.first() {
        picked.push(0);
        used += first.text.len().min(SECTION_CAP);
    }
    for &i in pinned.iter().filter(|&&i| i > 0 && i < sections.len()) {
        let len = sections[i].text.len().min(SECTION_CAP) + 2;
        if used + len <= max_chars {
            picked.push(i);
            used += len;
        }
    }
    for (_, i) in ranked {
        let len = sections[i].text.len().min(SECTION_CAP) + 2;
        if used + len <= max_chars {
            picked.push(i);
            used += len;
        }
    }
    picked.sort_unstable();
    let mut out = String::new();
    for i in picked {
        let t = &sections[i].text;
        let t = if t.len() > SECTION_CAP {
            cut(t, SECTION_CAP)
        } else {
            t.as_str()
        };
        if !out.is_empty() {
            out.push_str("\n\n");
        }
        out.push_str(t);
    }
    let cut_len = out.len().min(max_chars);
    (cut(&out, cut_len).to_string(), true)
}

/// Truncates at a char boundary.
pub fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: &str = r#"<html><head><title>List users | Acme API</title><script>var x="secret";</script></head>
<body><nav><a href="/docs/auth">Authentication</a><a href="https://other.example/x">x</a></nav>
<main><h1 id="intro">Acme API</h1><p>Welcome to   the Acme   API.</p>
<h2 id="list-users">List users</h2><p>GET /api/v1/users returns every user in the organization.</p>
<pre><code>{
  "data": [{"id": "u1", "email": "a@b.c"}],
  "next_cursor": "abc"
}</code></pre>
<table><tr><th>Parameter</th><th>Type</th></tr><tr><td>limit</td><td>integer</td></tr></table>
<h2 id="changelog">Changelog</h2><p>We shipped dark mode.</p></main>
<footer><a href="/docs/pagination#top">Pagination</a></footer></body></html>"#;

    fn page() -> Page {
        html(
            PAGE,
            &Url::parse("https://docs.acme.example/docs/users").unwrap(),
        )
    }

    #[test]
    fn sections_keep_structure() {
        let p = page();
        assert_eq!(p.title, "List users | Acme API");
        let heads: Vec<_> = p.sections.iter().map(|s| s.heading.as_str()).collect();
        assert_eq!(heads, ["Acme API", "List users", "Changelog"]);
        let users = &p.sections[1].text;
        assert!(
            users.contains("\"next_cursor\": \"abc\""),
            "code block kept verbatim: {users}"
        );
        assert!(
            users.contains("limit | integer"),
            "table rows kept: {users}"
        );
        assert!(
            !p.sections.iter().any(|s| s.text.contains("secret")),
            "script dropped"
        );
        assert!(p.sections[0].text.contains("Welcome to the Acme API."));
    }

    #[test]
    fn links_resolved_and_deduped() {
        let urls: Vec<_> = page().links.into_iter().map(|l| l.url).collect();
        assert!(urls.contains(&"https://docs.acme.example/docs/auth".to_string()));
        assert!(
            urls.contains(&"https://docs.acme.example/docs/pagination".to_string()),
            "fragment dropped"
        );
        assert!(urls.contains(&"https://other.example/x".to_string()));
    }

    #[test]
    fn fragment_focuses_operation() {
        let s = focus_fragment(page().sections, "list-users");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].heading, "List users");
        assert_eq!(focus_fragment(page().sections, "missing").len(), 3);
    }

    #[test]
    fn selection_prefers_api_sections_over_page_head() {
        let mut sections = vec![new_section("Intro".into(), 1, String::new())];
        sections[0].text = "Intro".into();
        for i in 0..20 {
            let mut s = new_section(format!("News {i}"), 2, String::new());
            s.text = format!("News {i} ") + &"marketing words ".repeat(300);
            sections.push(s);
        }
        let mut api = new_section("List users".into(), 2, String::new());
        api.text =
            "List users GET /api/v1/users Authorization: Bearer <token> {\"data\":[]} next_cursor"
                .into();
        sections.push(api);
        let (text, truncated) = select(&sections, &[], 10_000);
        assert!(truncated);
        assert!(
            text.contains("GET /api/v1/users"),
            "API section survives although it is last"
        );
        assert!(text.len() <= 10_000);
        assert!(!text.contains("News 0"), "unscored filler dropped");
    }

    #[test]
    fn chosen_operation_block_is_pinned() {
        let mut sections = vec![new_section("Hosts".into(), 1, String::new())];
        sections[0].text = "Hosts".into();
        for i in 0..30 {
            let mut s = new_section(format!("Op{i}"), 2, String::new());
            s.text = format!("Op{i} GET /devices/v{i} Authorization: Bearer {{\"resources\":[]}} ")
                + &"param ".repeat(250);
            sections.push(s);
        }
        let mut op = new_section("CombinedDevicesByFilter".into(), 2, String::new());
        op.text = "CombinedDevicesByFilter GET /devices/combined/devices/v1".into();
        let mut resp = new_section("Response".into(), 3, String::new());
        resp.text = "Response {\"resources\":[{\"device_id\":\"x\"}],\"meta\":{\"pagination\":{\"after\":\"a\"}}}".into();
        sections.push(op);
        sections.push(resp);
        let pinned = block_of(&sections, "CombinedDevicesByFilter");
        assert_eq!(pinned, vec![31, 32]);
        let (text, _) = select_pinned(&sections, &pinned, &[], 8_000);
        assert!(
            text.contains("device_id") && text.contains("/devices/combined/devices/v1"),
            "operation and its response kept"
        );
        assert!(block_of(&sections, "missing").is_empty());
    }

    #[test]
    fn small_page_returned_whole() {
        let (text, truncated) = select(&page().sections, &[], 40_000);
        assert!(!truncated);
        assert!(text.contains("Changelog"));
    }
}
