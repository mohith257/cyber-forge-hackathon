package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"configbridge/internal/store"
	"configbridge/internal/testutil"
	"configbridge/pkg/config"
	"configbridge/pkg/model"
)

// Proves the real extraction SQL: records from two different sources that share
// an OCSF entity (same host, same CVE) must correlate — with no vendor/tool
// knowledge anywhere. Skips without TEST_DATABASE_URL.
func TestObservablesCorrelateAcrossSources(t *testing.T) {
	db := testutil.Setup(t)
	ctx := context.Background()
	scope := db.Store.ForTenant("tenant-a")

	// A live config + running run only to satisfy the ocsf_records FK; its own
	// vendor is irrelevant to correlation.
	b, _ := os.ReadFile("../../configs/fixture_events.json")
	c, issues := config.Decode(b)
	if len(issues) > 0 {
		t.Fatal(issues)
	}
	saved, e := scope.SaveConfig(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	if e = scope.Activate(ctx, c.ID, saved.Revision); e != nil {
		t.Fatal(e)
	}
	run := model.Run{TenantID: "tenant-a", ID: "run1", Connector: c.ID, ConfigVersion: 1, ConfigHash: saved.Hash, Mode: "live", StartedAt: time.Now().UTC()}
	if e = scope.StartRun(ctx, run); e != nil {
		t.Fatal(e)
	}

	seed := func(source, id string, class int, payload string) {
		rec := model.Record{TenantID: "tenant-a", Source: source, ID: id, ClassUID: class, FetchedAt: time.Now().UTC(), Payload: []byte(payload)}
		if e := scope.SavePage(ctx, run.ID, source, []model.Record{rec}, nil); e != nil {
			t.Fatal(e)
		}
	}
	// Same host from two different tools.
	seed("edr", "d1", 5001, `{"device":{"hostname":"WEB01","ip":"10.0.0.5"}}`)
	seed("siem", "e1", 3002, `{"device":{"hostname":"web01"},"severity":"High"}`)
	// Same CVE from two different tools.
	seed("tenable", "v1", 2002, `{"vulnerabilities":[{"cve":{"uid":"CVE-2024-1234"}}]}`)
	seed("qualys", "v2", 2002, `{"vulnerabilities":[{"cve":{"uid":"CVE-2024-1234"}}]}`)
	// Single-source host: must NOT correlate.
	seed("edr", "d2", 5001, `{"device":{"hostname":"lonely-box"}}`)

	post, e := scope.Posture(ctx)
	if e != nil {
		t.Fatal(e)
	}
	byVal := map[string]store.Cluster{}
	for _, cl := range post.Clusters {
		byVal[cl.Type+":"+cl.Value] = cl
	}

	host := byVal["host:web01"]
	if len(host.Sources) != 2 {
		t.Fatalf("host web01: want 2 sources (edr,siem), got %v", host.Sources)
	}
	if !host.HighSev {
		t.Fatalf("host web01: expected high-severity flag from the siem record")
	}
	cve := byVal["cve:cve-2024-1234"]
	if len(cve.Sources) != 2 {
		t.Fatalf("cve: want 2 sources (tenable,qualys), got %v", cve.Sources)
	}
	if _, ok := byVal["host:lonely-box"]; ok {
		t.Fatalf("single-source host must not correlate")
	}
}
