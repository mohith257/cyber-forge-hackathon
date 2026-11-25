package store

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Posture is the tool-agnostic correlation engine. It does NOT know about any
// specific vendor or connector. Because every source is normalised to OCSF, it
// extracts shared entities (observables) from fixed OCSF paths — CVE, IP,
// hostname, user, device — and joins records by entity. Any two tools that
// mention the same entity become a correlation edge, so adding a new source
// needs zero correlation code: as long as its mapping fills the standard OCSF
// fields (the product's whole premise), its entities auto-join to everything
// else. KEV membership is the one deterministic severity signal folded in.
//
// Tiers (prioritisation, never proof of compromise):
//
//	critical  an actively-exploited (KEV) CVE seen by 2+ sources
//	high      a KEV CVE (any source), or any entity seen by 3+ sources
//	medium    an entity seen by exactly 2 sources (cross-tool, no KEV)
//
// Single-source, non-KEV entities are dropped: one tool seeing a host is not a
// correlation.
type Observable struct {
	Type     string
	Value    string
	Source   string
	ClassUID int
	RecordID string
	Severity string
	IsKEV    bool
}

type Cluster struct {
	Type      string   `json:"type"`
	Value     string   `json:"value"`
	Tier      string   `json:"tier"`
	IsKEV     bool     `json:"is_kev"`
	Sources   []string `json:"sources"`
	Classes   []int    `json:"classes"`
	Records   []string `json:"records"`
	HighSev   bool     `json:"high_severity"`
	Rationale string   `json:"rationale"`
}

type Posture struct {
	Generated time.Time `json:"generated"`
	Clusters  []Cluster `json:"clusters"`
	Notes     []string  `json:"notes"`
}

// scalarPaths: the fixed OCSF locations every class may populate. Entities are
// read from here regardless of which tool produced the record.
var scalarPaths = []struct{ typ, path string }{
	{"ip", "{device,ip}"},
	{"ip", "{src_endpoint,ip}"},
	{"ip", "{dst_endpoint,ip}"},
	{"host", "{device,hostname}"},
	{"host", "{src_endpoint,hostname}"},
	{"host", "{dst_endpoint,hostname}"},
	{"user", "{user,uid}"},
	{"user", "{user,name}"},
	{"user", "{actor,user,name}"},
	{"device", "{device,uid}"},
}

// Observables extracts every entity from the tenant's OCSF records in one query.
// It reuses the KEV CTE (kevSource) to flag actively-exploited CVEs. RLS plus
// the explicit tenant filter keep it to the caller's own records.
func (s Scope) Observables(ctx context.Context) ([]Observable, error) {
	out := []Observable{}
	parts := []string{
		`SELECT 'cve' AS typ, lower(v->'cve'->>'uid') AS val, source, class_uid, external_id, coalesce(payload->>'severity','') AS sev
		 FROM ocsf_records, jsonb_array_elements(CASE WHEN jsonb_typeof(payload->'vulnerabilities')='array' THEN payload->'vulnerabilities' ELSE '[]'::jsonb END) v
		 WHERE tenant_id=$1 AND coalesce(v->'cve'->>'uid','') ~ '^CVE-[0-9]{4}-[0-9]{4,}$'`,
	}
	for _, p := range scalarPaths {
		parts = append(parts, fmt.Sprintf(
			`SELECT '%s', lower(payload#>>'%s'), source, class_uid, external_id, coalesce(payload->>'severity','')
			 FROM ocsf_records WHERE tenant_id=$1 AND coalesce(payload#>>'%s','')<>''`, p.typ, p.path, p.path))
	}
	q := kevSource + `, obs AS (` + strings.Join(parts, " UNION ALL ") + `)
	 SELECT typ, val, source, class_uid, external_id, sev,
	  (typ='cve' AND val IN (SELECT lower(cve) FROM kev)) AS is_kev
	 FROM obs WHERE val IS NOT NULL AND val<>'' AND length(val)<=255 LIMIT 20000`

	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	err := s.WithTx(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, q, s.Tenant)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var o Observable
			if e = rows.Scan(&o.Type, &o.Value, &o.Source, &o.ClassUID, &o.RecordID, &o.Severity, &o.IsKEV); e != nil {
				return e
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// Posture runs the extraction, then the pure correlation.
func (s Scope) Posture(ctx context.Context) (Posture, error) {
	out := Posture{Generated: time.Now().UTC(), Clusters: []Cluster{}, Notes: []string{}}
	obs, err := s.Observables(ctx)
	if err != nil {
		return out, err
	}
	out.Clusters = correlate(obs)
	out.Notes = append(out.Notes,
		"Correlation is by shared OCSF entity across sources; any new tool that maps to standard OCSF fields joins automatically.",
		"Prioritisation only, not proof of compromise. Verify asset versions, source freshness and deployment before acting.")
	return out, nil
}

// correlate is the pure, DB-free engine: group observables by entity, keep the
// cross-tool or KEV ones, tier and rank them.
func correlate(obs []Observable) []Cluster {
	type agg struct {
		typ, value                string
		isKEV, highSev            bool
		sources, classes, records map[string]bool
		classIDs                  map[int]bool
	}
	groups := map[string]*agg{}
	for _, o := range obs {
		key := o.Type + "\x00" + o.Value
		g := groups[key]
		if g == nil {
			g = &agg{typ: o.Type, value: o.Value, sources: map[string]bool{}, classes: map[string]bool{}, records: map[string]bool{}, classIDs: map[int]bool{}}
			groups[key] = g
		}
		g.sources[o.Source] = true
		g.classIDs[o.ClassUID] = true
		if len(g.records) < 10 {
			g.records[o.Source+"/"+o.RecordID] = true
		}
		g.isKEV = g.isKEV || o.IsKEV
		g.highSev = g.highSev || isHighSeverity(o.Severity)
	}

	clusters := []Cluster{}
	for _, g := range groups {
		n := len(g.sources)
		if n < 2 && !g.isKEV {
			continue // one tool seeing an entity is not a correlation
		}
		tier := "medium"
		switch {
		case g.isKEV && n >= 2:
			tier = "critical"
		case g.isKEV || n >= 3:
			tier = "high"
		}
		clusters = append(clusters, Cluster{
			Type:      g.typ,
			Value:     g.value,
			Tier:      tier,
			IsKEV:     g.isKEV,
			Sources:   sortedKeys(g.sources),
			Classes:   sortedInts(g.classIDs),
			Records:   sortedKeys(g.records),
			HighSev:   g.highSev,
			Rationale: entityRationale(g.typ, g.value, n, g.isKEV, g.highSev),
		})
	}

	rank := map[string]int{"critical": 0, "high": 1, "medium": 2}
	sort.Slice(clusters, func(i, j int) bool {
		a, b := clusters[i], clusters[j]
		if rank[a.Tier] != rank[b.Tier] {
			return rank[a.Tier] < rank[b.Tier]
		}
		if len(a.Sources) != len(b.Sources) {
			return len(a.Sources) > len(b.Sources)
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Value < b.Value
	})
	return clusters
}

func entityRationale(typ, value string, sources int, kev, high bool) string {
	s := strconv.Itoa(sources) + " source(s)"
	label := map[string]string{"cve": "CVE", "ip": "IP", "host": "host", "user": "user", "device": "device"}[typ]
	if label == "" {
		label = typ
	}
	switch {
	case kev && sources >= 2:
		return "Actively-exploited (KEV) " + label + " " + value + " is corroborated by " + s + ". This is a prioritised attack path — verify affected asset versions first."
	case kev:
		return "Actively-exploited (KEV) " + label + " " + value + " appears in your findings. Confirm the affected asset is deployed and unpatched."
	case high:
		return label + " " + value + " links " + s + " including a high-severity signal. Review what the correlated records describe."
	default:
		return label + " " + value + " links " + s + ". Cross-tool overlap worth reviewing together."
	}
}

func isHighSeverity(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "critical", "fatal", "4", "5", "6":
		return true
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedInts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}
