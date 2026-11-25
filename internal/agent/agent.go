// Package agent calls cb-agent, the Rust retrieval service in agent/. It is
// the only component that reads the open web for AI drafting (egress guarded
// there); this side only talks to it over the internal network with a token.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	base  string
	token string
	http  *http.Client
}

// New validates CB_AGENT_URL and CB_AGENT_TOKEN (read by cmd/api).
func New(base, token string) (*Client, error) {
	u, e := url.Parse(base)
	if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, errors.New("CB_AGENT_URL must be the agent's base URL, e.g. http://agent:8090")
	}
	if len(token) < 32 {
		return nil, errors.New("CB_AGENT_TOKEN must be at least 32 characters")
	}
	return &Client{base: u.Scheme + "://" + u.Host, token: token, http: &http.Client{
		Timeout:       5 * time.Minute, // a discovery loop makes up to ~12 model calls
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

type Section struct {
	Heading string `json:"heading"`
	Level   int    `json:"level"`
	Chars   int    `json:"chars"`
}

type Link struct {
	URL  string `json:"url"`
	Text string `json:"text"`
}

// Page is one public reference as the agent read it.
type Page struct {
	URL         string    `json:"url"`
	FinalURL    string    `json:"final_url"`
	ContentType string    `json:"content_type"`
	Title       string    `json:"title"`
	Text        string    `json:"text"` // whole page, or its API-relevant sections when larger than max_chars
	Truncated   bool      `json:"truncated"`
	TotalChars  int       `json:"total_chars"`
	Sections    []Section `json:"sections"`
	Links       []Link    `json:"links"`
}

// Error is the agent's own refusal ("refused": the URL is not allowed) or
// failure ("upstream": the page could not be read), with its safe message.
type Error struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// ErrUnavailable: the agent itself could not be reached or answered garbage.
var ErrUnavailable = errors.New("documentation agent unavailable")

// a rendered page (16 MiB of HTML, JSON-escaped) is the largest answer
const maxResponse = 40 << 20

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	b, e := c.do(ctx, path, in)
	if e != nil {
		return e
	}
	if json.Unmarshal(b, out) != nil {
		return ErrUnavailable
	}
	return nil
}

// do sends one request and returns the 200 body; anything else is an error.
func (c *Client) do(ctx context.Context, path string, in any) ([]byte, error) {
	body, _ := json.Marshal(in)
	req, e := http.NewRequestWithContext(ctx, "POST", c.base+path, bytes.NewReader(body))
	if e != nil {
		return nil, ErrUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, e := c.http.Do(req)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if e != nil || len(b) > maxResponse {
		return nil, ErrUnavailable
	}
	if res.StatusCode != 200 {
		ae := &Error{Status: res.StatusCode}
		if json.Unmarshal(b, ae) != nil || ae.Message == "" {
			return nil, fmt.Errorf("%w: HTTP %d", ErrUnavailable, res.StatusCode)
		}
		return nil, ae
	}
	return b, nil
}

// Fetch reads one public page. focus favours sections mentioning those words
// when the page must be cut to maxChars.
func (c *Client) Fetch(ctx context.Context, pageURL string, focus []string, maxChars int) (*Page, error) {
	if focus == nil {
		focus = []string{}
	}
	var p Page
	if e := c.post(ctx, "/v1/fetch", map[string]any{"url": pageURL, "focus": focus, "max_chars": maxChars}, &p); e != nil {
		return nil, e
	}
	return &p, nil
}

type Doc struct {
	URL   string `json:"url"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

type Step struct {
	Action string `json:"action"`
	Input  string `json:"input"`
	Result string `json:"result"`
}

type Usage struct {
	Input  int64 `json:"input_tokens"`
	Output int64 `json:"output_tokens"`
	Total  int64 `json:"total_tokens"`
}

// Discovery is the agent loop's verified answer: pages it fetched, specs it
// confirmed, and a dataset heading that appears verbatim on a cited page.
type Discovery struct {
	Found    bool     `json:"found"`
	SpecURLs []string `json:"spec_urls"`
	Docs     []Doc    `json:"docs"`
	Dataset  string   `json:"dataset"`
	Scope    string   `json:"scope"`
	Reason   string   `json:"reason"`
	Queries  []string `json:"queries"`
	Trace    []Step   `json:"trace"`
	Usage    Usage    `json:"usage"`
}

// Rejected is the previous pass's citation and why the verifier refused it.
// The agent refuses the same dataset on the same pages again.
type Rejected struct {
	Feedback string
	Dataset  string
	Docs     []string
}

// Discover runs the bounded search/read/probe loop for a product name.
// prev is nil on the first pass.
func (c *Client) Discover(ctx context.Context, product, want string, prev *Rejected, maxChars int) (*Discovery, error) {
	in := map[string]any{"product": product, "want": want, "max_chars": maxChars}
	if prev != nil {
		in["feedback"], in["rejected_dataset"], in["rejected_docs"] = prev.Feedback, prev.Dataset, prev.Docs
	}
	var d Discovery
	if e := c.post(ctx, "/v1/discover", in, &d); e != nil {
		return nil, e
	}
	return &d, nil
}

// Raw downloads one public file unparsed (an OpenAPI spec), up to maxBytes.
func (c *Client) Raw(ctx context.Context, fileURL string, maxBytes int) (string, error) {
	b, e := c.do(ctx, "/v1/raw", map[string]any{"url": fileURL, "max_bytes": maxBytes})
	return string(b), e
}

// Rendered is a JavaScript-built page after its scripts ran.
type Rendered struct {
	FinalURL string   `json:"final_url"`
	HTML     string   `json:"html"`
	Text     string   `json:"text"`
	Specs    []string `json:"specs"` // OpenAPI-looking files the page downloaded
}

// Render opens a page in the agent's isolated headless browser.
func (c *Client) Render(ctx context.Context, pageURL string) (*Rendered, error) {
	var r Rendered
	if e := c.post(ctx, "/v1/render", map[string]any{"url": pageURL}, &r); e != nil {
		return nil, e
	}
	return &r, nil
}

// SearchResult is one Google-Search-grounded answer.
type SearchResult struct {
	Text    string   `json:"text"`
	Queries []string `json:"queries"`
	Sources []string `json:"sources"` // pages search actually visited
	Usage   Usage    `json:"usage"`
}

// Search runs one grounded web search with the given prompt.
func (c *Client) Search(ctx context.Context, prompt string) (*SearchResult, error) {
	var r SearchResult
	if e := c.post(ctx, "/v1/search", map[string]any{"prompt": prompt}, &r); e != nil {
		return nil, e
	}
	return &r, nil
}
