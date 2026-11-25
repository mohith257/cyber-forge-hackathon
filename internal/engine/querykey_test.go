package engine

import (
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// Shodan-style APIs accept the key only as ?key=. It must ride on every page,
// never in a header, and never appear in errors or logs.
func TestAPIKeyInQueryParam(t *testing.T) {
	var pages atomic.Int32
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("key") != secretValue || r.Header.Get("Authorization") != "" || len(q["key"]) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if q.Get("query") != "net:203.0.113.0/24" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		n := pages.Add(1)
		if q.Get("page") != fmt.Sprint(n) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if n == 1 {
			fmt.Fprintf(w, `{"matches":%s}`, itemsJSON(1, 10))
			return
		}
		fmt.Fprintf(w, `{"matches":%s}`, itemsJSON(11, 3))
	})
	c := h.conn("/shodan/host/search")
	c.Auth = Auth{Type: "api_key", Param: "key", Secret: "tok"}
	c.Request.Params = map[string]string{"query": "net:203.0.113.0/24"}
	c.ItemsPath = "matches"
	c.Pagination = Pagination{Type: "page", PageParam: "page", PageSize: 10}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid query-key config rejected: %v", err)
	}
	if _, items, err := h.fetch(c); err != nil || len(items) != 13 || pages.Load() != 2 {
		t.Fatalf("items=%d pages=%d err=%v", len(items), pages.Load(), err)
	}

	// wrong key -> 401: the error and the logs must not carry the key
	h.eng.Secrets = fakeSecrets{"t1/tok": NewSecret("wrong-"+secretValue, h.host)}
	_, _, err := h.fetch(c)
	if err == nil {
		t.Fatal("bad key must fail")
	}
	if strings.Contains(err.Error(), secretValue) || strings.Contains(h.logs.String(), secretValue) || strings.Contains(h.logs.String(), "key=") {
		t.Fatalf("key leaked: err=%v logs=%s", err, h.logs.String())
	}
}

func TestAPIKeyParamValidation(t *testing.T) {
	base := func() Connector {
		return Connector{TenantID: "t1", ID: "x", Request: Request{Method: "GET", URL: "https://api.shodan.io/shodan/host/search"},
			Auth: Auth{Type: "api_key", Param: "key", Secret: "shodan"}}
	}
	for name, mut := range map[string]func(*Connector){
		"header and param":  func(c *Connector) { c.Auth.Header = "X-Key" },
		"neither":           func(c *Connector) { c.Auth.Param = "" },
		"bad name":          func(c *Connector) { c.Auth.Param = "k e y" },
		"also in params":    func(c *Connector) { c.Request.Params = map[string]string{"key": "x"} },
		"is the page param": func(c *Connector) { c.Pagination = Pagination{Type: "page", PageParam: "key", PageSize: 10} },
		"not api_key":       func(c *Connector) { c.Auth.Type = "bearer" },
	} {
		c := base()
		mut(&c)
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "auth.") {
			t.Errorf("%s: want auth error, got %v", name, err)
		}
	}
	if c := base(); c.Validate() != nil {
		t.Fatalf("base config should validate: %v", c.Validate())
	}
}
