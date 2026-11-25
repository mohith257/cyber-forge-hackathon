package ai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"configbridge/internal/agent"
)

func TestSameSite(t *testing.T) {
	for _, tc := range []struct {
		api  string
		refs []string
		ok   bool
	}{
		{"https://api.github.com/orgs/x/members", []string{"https://docs.github.com/en/rest"}, true},
		{"https://services.nvd.nist.gov/rest/json/cves/2.0", []string{"https://nvd.nist.gov/developers"}, true},
		{"https://api.example.co.uk/v1", []string{"https://docs.example.co.uk/"}, true},
		{"https://api.example.co.uk/v1", []string{"https://docs.other.co.uk/"}, false},
		{"https://api.github.com/x", []string{"https://github-docs.attacker.example/rest"}, false},
		{"https://your-tenant.okta.com/api/v1/users", []string{"https://anything.example"}, true},
	} {
		if sameSite(tc.api, tc.refs) != tc.ok {
			t.Fatal(tc)
		}
	}
}

func TestNameOnlyNeedsSearchProviderBeforeBudget(t *testing.T) {
	r := Request{Product: "SomeVendor", Data: "auto"}
	if e := r.Check(); e != nil {
		t.Fatal("bare product name must be accepted", e)
	}
	if _, e := New("k", "m").Prepare(context.Background(), r); !errors.Is(e, ErrSearchRequired) {
		t.Fatal("groq cannot search; must refuse before reserving budget", e)
	}
	if _, e := NewGemini("k", "m").Prepare(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	// partial requests still fail closed
	if e := (Request{Product: "SomeVendor", Data: "auto", Dataset: "users"}).Check(); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
}

// noDocs is an agent that does nothing; fakes embed it and override.
type noDocs struct{}

func (noDocs) Fetch(context.Context, string, []string, int) (*agent.Page, error) {
	return nil, errors.New("tests read pages through FetchDocumentation")
}
func (noDocs) Raw(context.Context, string, int) (string, error) {
	return "", errors.New("tests read specs through FetchSpec")
}
func (noDocs) Render(context.Context, string) (*agent.Rendered, error) {
	return nil, errors.New("no renderer in tests")
}
func (noDocs) Search(context.Context, string) (*agent.SearchResult, error) {
	return nil, errors.New("no search in this test")
}
func (noDocs) Discover(context.Context, string, string, *agent.Rejected, int) (*agent.Discovery, error) {
	return nil, errors.New("no discovery in this test")
}

// searchAgent answers grounded searches with text; calls counts them.
type searchAgent struct {
	noDocs
	text  string
	calls *int
}

func (a searchAgent) Search(context.Context, string) (*agent.SearchResult, error) {
	*a.calls++
	return &agent.SearchResult{Text: a.text, Usage: agent.Usage{Input: 5, Output: 4, Total: 9}}, nil
}

// fakeAgent stands in for the Rust agent's /v1/discover. next, when set,
// answers the second pass; feedback records what each pass was told.
type fakeAgent struct {
	noDocs
	found    *agent.Discovery
	err      error
	calls    *[]string
	next     *agent.Discovery
	feedback *[]string
}

func (f fakeAgent) Discover(_ context.Context, _, _ string, prev *agent.Rejected, _ int) (*agent.Discovery, error) {
	*f.calls = append(*f.calls, "discover")
	feedback := ""
	if prev != nil {
		feedback = prev.Feedback + " dataset=" + prev.Dataset + " docs=" + strings.Join(prev.Docs, ",")
	}
	if f.feedback != nil {
		*f.feedback = append(*f.feedback, feedback)
	}
	if f.next != nil && feedback != "" {
		return f.next, nil
	}
	return f.found, f.err
}

var agentUsage = agent.Usage{Input: 10, Output: 20, Total: 30}

// fakeGemini answers the draft call with out; a web search from the API is a
// bug (search runs in the agent).
func fakeGemini(t *testing.T, found *agent.Discovery, out *modelOutput) (*Client, *[]string) {
	calls := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "google_search") {
			t.Error("the API searched itself; search belongs to the agent")
		}
		calls = append(calls, "draft")
		json.NewEncoder(w).Encode(map[string]any{"usageMetadata": map[string]int{"promptTokenCount": 10, "totalTokenCount": 30},
			"candidates": []any{map[string]any{"finishReason": "STOP", "content": map[string]any{"parts": []any{map[string]any{"text": mustJSON(out)}}}}}})
	}))
	t.Cleanup(srv.Close)
	c := NewGemini("k", "m")
	c.URL, c.HTTP = srv.URL+"/", srv.Client()
	c.FetchSpec = func(context.Context, string) (string, error) { return "", ErrDocumentation } // no network
	c.Agent = fakeAgent{found: found, calls: &calls}
	return c, &calls
}

func docsFound(ref string) *agent.Discovery {
	return &agent.Discovery{Found: true, Docs: []agent.Doc{{URL: ref, Text: fixtureDoc}}, Dataset: "organization members", Scope: "organization",
		Queries: []string{"examplevendor list members api"}, Usage: agentUsage}
}

func TestNameOnlyDraftsFromAgentPagesAndMetersEverything(t *testing.T) {
	const ref = "https://docs.github.com/en/rest/orgs/members"
	out, _ := groundedFixture()
	for i := range out.Evidence {
		out.Evidence[i].URL = ref
	}
	c, calls := fakeGemini(t, docsFound(ref), out)
	d, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(*calls, ",") != "discover,draft" || d.Contract.Status != "documented_candidate" || len(d.Evidence) == 0 || d.Usage.Total != 60 {
		t.Fatal(*calls, d.Contract, d.Usage)
	}
	if len(d.Sources) != 1 || d.Sources[0] != ref || !strings.Contains(d.Notes[0], "examplevendor list members api") {
		t.Fatal("sources or search queries not reported", d.Sources, d.Notes)
	}
}

func TestNameOnlyRejectionGoesBackToTheAgentOnce(t *testing.T) {
	const wrong, right = "https://docs.github.com/en/rest/orgs/reports", "https://docs.github.com/en/rest/orgs/members"
	out, _ := groundedFixture()
	for i := range out.Evidence {
		out.Evidence[i].URL = right
	}
	first := docsFound(wrong)
	first.Docs[0].Text = "List reports GET /orgs/{org}/reports" // nothing to cite: the verifier must reject
	c, calls := fakeGemini(t, first, out)
	fb := []string{}
	c.Agent = fakeAgent{found: first, next: docsFound(right), calls: calls, feedback: &fb}
	d, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if len(fb) != 2 || fb[0] != "" || !strings.Contains(fb[1], "docs="+wrong) || !strings.Contains(fb[1], "dataset=organization members") || !strings.Contains(fb[1], "issues:") || d.Sources[0] != right {
		t.Fatal("second pass not told why the first was rejected", fb, d.Sources)
	}
	// both discovery passes and every drafting call are metered
	if d.Usage.Total != int64(30*2+30*strings.Count(strings.Join(*calls, ","), "draft")) {
		t.Fatal(*calls, d.Usage)
	}
	// a second rejection ends it: never a third pass
	c, calls = fakeGemini(t, first, out)
	c.Agent = fakeAgent{found: first, calls: calls}
	var bad *InvalidDraft
	if _, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil); !errors.As(e, &bad) || strings.Count(strings.Join(*calls, ","), "discover") != 2 {
		t.Fatal(e, *calls)
	}
}

func TestNameOnlyFailsClosedAndMetersWhenAgentFindsNothing(t *testing.T) {
	out, _ := groundedFixture()
	c, calls := fakeGemini(t, &agent.Discovery{Found: false, Reason: "only blog posts found", Usage: agentUsage}, out)
	_, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	var bad *InvalidDraft
	if !errors.As(e, &bad) || bad.Last != nil || !strings.Contains(bad.Issues[0].Message, "only blog posts found") || bad.Usage.Total != 30 || strings.Join(*calls, ",") != "discover" {
		t.Fatal("drafted without a verified reference, or search tokens not metered", e, *calls)
	}
}

func TestNameOnlyAgentProviderErrorIsUpstream(t *testing.T) {
	out, _ := groundedFixture()
	c, _ := fakeGemini(t, nil, out)
	c.Agent = fakeAgent{err: &agent.Error{Status: 429, Code: "provider", Message: "provider rate limit"}, calls: &[]string{}}
	if _, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil); !errors.Is(e, ErrUpstream) {
		t.Fatal(e)
	}
	c.Agent = fakeAgent{err: agent.ErrUnavailable, calls: &[]string{}}
	if _, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil); !errors.Is(e, ErrDocumentation) {
		t.Fatal(e)
	}
}

func TestNameOnlyRejectsAPIOnAnotherSiteThanTheDocs(t *testing.T) {
	out, _ := groundedFixture() // config calls api.github.com, docs live on vendor.example
	c, _ := fakeGemini(t, docsFound(fixtureReference), out)
	_, e := c.Draft(context.Background(), Request{Product: "ExampleVendor", Data: "user_inventory"}, nil)
	var bad *InvalidDraft
	if !errors.As(e, &bad) || bad.Issues[0].Field != "request.url" || bad.Last != nil {
		t.Fatal("lookalike documentation accepted", e)
	}
}

// Live: CB_LIVE_DISCOVERY=1 GEMINI_API_KEY=... CB_AI_MODEL=gemini-3.5-flash CB_AGENT_URL=... CB_AGENT_TOKEN=...
// LIVE_PRODUCTS="Okta;FIRST EPSS" go test -v -run TestLiveNameOnly ./internal/ai
func TestLiveNameOnly(t *testing.T) {
	if os.Getenv("CB_LIVE_DISCOVERY") != "1" || os.Getenv("GEMINI_API_KEY") == "" {
		t.Skip("set CB_LIVE_DISCOVERY=1, GEMINI_API_KEY, CB_AGENT_URL and CB_AGENT_TOKEN (a running agent)")
	}
	c := NewGemini(os.Getenv("GEMINI_API_KEY"), os.Getenv("CB_AI_MODEL"))
	c.Resolve = LookupDNS
	docs, err := agent.New(os.Getenv("CB_AGENT_URL"), os.Getenv("CB_AGENT_TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	c.Agent = docs
	for _, p := range strings.Split(os.Getenv("LIVE_PRODUCTS"), ";") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		t.Run(p, func(t *testing.T) {
			c.debugDiscovery = func(s string) { t.Logf("%s", s) }
			data := os.Getenv("LIVE_DATA")
			if data == "" {
				data = "auto"
			}
			d, e := c.Draft(context.Background(), Request{Product: p, Data: data}, nil)
			var bad *InvalidDraft
			switch {
			case errors.As(e, &bad):
				t.Logf("REJECTED tokens=%d issues=%v", bad.Usage.Total, bad.Issues)
			case e != nil:
				t.Logf("FAILED %v", e)
			default:
				t.Logf("DRAFTED class=%s endpoint=%s auth=%s paging=%s sources=%v credential=%v tokens=%d evidence=%d",
					d.Data, d.Contract.Endpoint, d.Contract.Auth, d.Contract.Pagination, d.Sources, d.Credential, d.Usage.Total, len(d.Evidence))
			}
		})
	}
}

func TestSecretNamedOnlyFillsAMissingLocalLabel(t *testing.T) {
	got := string(secretNamed([]byte(`{"request":{"url":"https://api.snyk.io/rest/orgs/your-org/issues"},"auth":{"type":"bearer"},"page_size":100}`)))
	if !strings.Contains(got, `"secret":"snyk_io_token"`) || !strings.Contains(got, `"page_size":100`) {
		t.Fatal(got)
	}
	for _, keep := range []string{
		`{"request":{"url":"https://api.snyk.io/x"},"auth":{"type":"bearer","secret":"mine"}}`,
		`{"request":{"url":"https://api.snyk.io/x"},"auth":{"type":"none"}}`,
		`not json`,
	} {
		if string(secretNamed([]byte(keep))) != keep {
			t.Fatal("changed", keep)
		}
	}
}
