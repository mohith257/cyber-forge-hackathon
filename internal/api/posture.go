package api

import "net/http"

// GET /posture — deterministic correlation across the tenant's connected
// sources: vendor KEV exposure joined with exact KEV matches in the tenant's
// own retained findings, ranked into attack-path tiers. No model, no secrets.
func (a *API) posture(w http.ResponseWriter, r *http.Request) {
	out, err := a.scope(r).Posture(r.Context())
	if err != nil {
		dbFail(w, err)
		return
	}
	write(w, 200, out)
}
