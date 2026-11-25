package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const token = "0123456789abcdef0123456789abcdef"

func TestNewValidatesSettings(t *testing.T) {
	for _, base := range []string{"", "agent:8090", "ftp://agent", "http://u:p@agent:8090", "http://agent:8090/x", "http://agent:8090/?a=1"} {
		if _, e := New(base, token); e == nil {
			t.Fatal("bad base accepted", base)
		}
	}
	if _, e := New("http://agent:8090", "short"); e == nil {
		t.Fatal("short token accepted")
	}
}

func TestFetchSendsTokenAndDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/fetch" || r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		if in["url"] != "https://docs.example.com/users" || in["max_chars"] != float64(40000) {
			w.WriteHeader(400)
			return
		}
		w.Write([]byte(`{"url":"https://docs.example.com/users","final_url":"https://docs.example.com/users","text":"List users GET /v1/users","links":[{"url":"https://docs.example.com/auth","text":"Auth"}]}`))
	}))
	defer srv.Close()
	c, e := New(srv.URL, token)
	if e != nil {
		t.Fatal(e)
	}
	p, e := c.Fetch(context.Background(), "https://docs.example.com/users", nil, 40000)
	if e != nil || !strings.Contains(p.Text, "GET /v1/users") || len(p.Links) != 1 {
		t.Fatal(p, e)
	}
}

func TestFetchSurfacesAgentRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"error":"refused","message":"address 169.254.169.254 is not public"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, token)
	_, e := c.Fetch(context.Background(), "https://169.254.169.254/", nil, 40000)
	var ae *Error
	if !errors.As(e, &ae) || ae.Code != "refused" || !strings.Contains(ae.Message, "not public") {
		t.Fatal(e)
	}
	srv.Close()
	if _, e := c.Fetch(context.Background(), "https://docs.example.com/", nil, 40000); !errors.Is(e, ErrUnavailable) {
		t.Fatal("down agent must be ErrUnavailable", e)
	}
}

func TestRawReturnsBodyUnparsedAndSearchDecodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/raw":
			w.Header().Set("content-type", "application/yaml")
			w.Write([]byte("openapi: 3.0.0\npaths: {}\n"))
		case "/v1/search":
			w.Write([]byte(`{"text":"facts","queries":["q1"],"sources":["https://docs.example.com/a"],"usage":{"input_tokens":5,"output_tokens":4,"total_tokens":9}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, token)
	if s, e := c.Raw(context.Background(), "https://docs.example.com/openapi.yaml", 1<<20); e != nil || !strings.HasPrefix(s, "openapi: 3.0.0") {
		t.Fatal(s, e)
	}
	r, e := c.Search(context.Background(), "find docs")
	if e != nil || r.Text != "facts" || r.Queries[0] != "q1" || r.Usage.Total != 9 {
		t.Fatal(r, e)
	}
}
