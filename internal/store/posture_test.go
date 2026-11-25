package store

import "testing"

// correlate groups observables by shared entity across sources. These cases pin
// the tier rules and the "cross-tool or KEV only" filter without a database.
func TestCorrelateEntities(t *testing.T) {
	obs := []Observable{
		// Same KEV CVE from two different tools -> corroborated -> critical.
		{Type: "cve", Value: "cve-2024-0001", Source: "tenable", ClassUID: 2002, RecordID: "r1", IsKEV: true},
		{Type: "cve", Value: "cve-2024-0001", Source: "qualys", ClassUID: 2002, RecordID: "r2", IsKEV: true},
		// KEV CVE from one tool -> high.
		{Type: "cve", Value: "cve-2024-0002", Source: "tenable", ClassUID: 2002, RecordID: "r3", IsKEV: true},
		// Host seen by three tools, no KEV -> high.
		{Type: "host", Value: "web01", Source: "edr", ClassUID: 5001, RecordID: "h1"},
		{Type: "host", Value: "web01", Source: "siem", ClassUID: 3002, RecordID: "h2"},
		{Type: "host", Value: "web01", Source: "cmdb", ClassUID: 5001, RecordID: "h3"},
		// User seen by two tools, no KEV -> medium.
		{Type: "user", Value: "alice", Source: "idp", ClassUID: 5003, RecordID: "u1"},
		{Type: "user", Value: "alice", Source: "siem", ClassUID: 3002, RecordID: "u2"},
		// IP seen by one tool, no KEV -> dropped (not a correlation).
		{Type: "ip", Value: "10.0.0.9", Source: "edr", ClassUID: 5001, RecordID: "i1"},
	}

	got := map[string]Cluster{}
	for _, c := range correlate(obs) {
		got[c.Type+":"+c.Value] = c
	}

	if got["cve:cve-2024-0001"].Tier != "critical" {
		t.Fatalf("corroborated KEV CVE: want critical, got %q", got["cve:cve-2024-0001"].Tier)
	}
	if n := len(got["cve:cve-2024-0001"].Sources); n != 2 {
		t.Fatalf("want 2 sources, got %d", n)
	}
	if got["cve:cve-2024-0002"].Tier != "high" {
		t.Fatalf("single KEV CVE: want high, got %q", got["cve:cve-2024-0002"].Tier)
	}
	if got["host:web01"].Tier != "high" {
		t.Fatalf("3-source host: want high, got %q", got["host:web01"].Tier)
	}
	if got["user:alice"].Tier != "medium" {
		t.Fatalf("2-source user: want medium, got %q", got["user:alice"].Tier)
	}
	if _, ok := got["ip:10.0.0.9"]; ok {
		t.Fatalf("single-source non-KEV ip should be dropped")
	}

	all := correlate(obs)
	if all[0].Tier != "critical" {
		t.Fatalf("ranking: want critical first, got %q", all[0].Tier)
	}
}

func TestCorrelateEmpty(t *testing.T) {
	if c := correlate(nil); len(c) != 0 {
		t.Fatalf("want no clusters, got %d", len(c))
	}
}
