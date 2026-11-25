package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// RequireLiveProof marks a config id whose response shape the docs did not
// prove: activating it needs a preview with real records first.
func (s Scope) RequireLiveProof(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "INSERT INTO live_proof(tenant_id,config_id)VALUES($1,$2) ON CONFLICT DO NOTHING", s.Tenant, id)
		return e
	})
}

// NeedsLiveProof reports whether RequireLiveProof is still open for id.
func (s Scope) NeedsLiveProof(ctx context.Context, id string) (open bool, err error) {
	err = s.WithTx(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM live_proof WHERE tenant_id=$1 AND config_id=$2)", s.Tenant, id).Scan(&open)
	})
	return open, err
}

// LiveProven closes the requirement once a preview proved the config.
func (s Scope) LiveProven(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, "DELETE FROM live_proof WHERE tenant_id=$1 AND config_id=$2", s.Tenant, id)
		return e
	})
}
