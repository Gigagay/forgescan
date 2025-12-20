package api

import (
	"encoding/json"
	"net/http"

	"forgescan/scanner-runner/internal/model"

	"github.com/go-chi/render"
)

func IngestHandler(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		JobID    string           `json:"job_id"`
		TenantID string           `json:"tenant_id"`
		Findings []model.Finding  `json:"findings"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		render.Status(r, 400)
		return
	}

	// No trust boundary crossing without validation
	for _, f := range payload.Findings {
		if f.Fingerprint == "" {
			render.Status(r, 400)
			return
		}
	}

	render.Status(r, 202)
}
