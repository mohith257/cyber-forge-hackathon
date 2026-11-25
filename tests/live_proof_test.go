package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

// An AI draft whose docs printed no response example is marked server-side:
// that config id activates only after a preview of the exact revision returns
// records containing every mapped path. Other configs activate as before.
func TestLiveProofGatesOnlyMarkedDraftsAndIsTenantScoped(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	if err := e.db.Store.ForTenant("tenant-a").RequireLiveProof(ctx, "proof_users"); err != nil {
		t.Fatal(err)
	}
	// /clean has id, profile.name and last_login but no email: unproven path
	c := userConfig("proof_users", e.vendor.URL+"/clean")
	rev := e.save(t, "tenant-a", c, false)
	body := []byte(fmt.Sprintf(`{"revision":%d}`, rev))
	var refused struct {
		Error, Detail string
	}
	json.Unmarshal(e.request(t, "tenant-a", "POST", "/configs/proof_users/activate", body, 422), &refused)
	if refused.Error != "activation_needs_live_proof" || refused.Detail == "" {
		t.Fatal(refused)
	}
	// the same id in another tenant is not marked
	e.save(t, "tenant-b", c, false)
	e.request(t, "tenant-b", "POST", "/configs/proof_users/activate", body, 200)

	delete(c.Destination.Mapping, "user.email_addr") // remove the unproven path
	rev = e.save(t, "tenant-a", c, false)
	body = []byte(fmt.Sprintf(`{"revision":%d}`, rev))
	e.request(t, "tenant-a", "POST", "/configs/proof_users/activate", body, 200)
	if open, err := e.db.Store.ForTenant("tenant-a").NeedsLiveProof(ctx, "proof_users"); err != nil || open {
		t.Fatal("proof not cleared", open, err)
	}
}
