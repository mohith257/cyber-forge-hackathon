-- AI drafts whose public docs show no JSON response example: the record path
-- and field paths are unproven, so activation of that config id must first
-- preview real records with the customer's key (see api.activate).
CREATE TABLE live_proof(
 tenant_id text NOT NULL REFERENCES tenants,
 config_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,config_id));
__RLS_POLICIES__
