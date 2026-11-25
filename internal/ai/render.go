package ai

import (
	"context"
	"fmt"
)

// RenderedPage is what a JavaScript-built docs page looked like after its
// scripts ran, in the agent's isolated headless browser (agent/src/render.rs:
// every browser request passes the egress rules there).
type RenderedPage struct {
	HTML  string
	Text  string
	Specs []string // OpenAPI-looking files the page downloaded (.json/.yaml)
}

// render: the Render test seam, else the agent's renderer.
func (c *Client) render(ctx context.Context, raw string) (*RenderedPage, error) {
	if c.Render != nil {
		return c.Render(ctx, raw)
	}
	if !publicDocURL(raw) || c.Agent == nil {
		return nil, ErrDocumentation
	}
	p, e := c.Agent.Render(ctx, raw)
	if e != nil {
		return nil, fmt.Errorf("%w: %s", ErrDocumentation, trunc(e.Error(), 200))
	}
	return &RenderedPage{HTML: p.HTML, Text: compact(p.Text), Specs: p.Specs}, nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
