package api

import (
	"encoding/json"
	"net/http"

	"forgescan/scanner-runner/internal/docker"
	"forgescan/scanner-runner/internal/model"
	"forgescan/scanner-runner/internal/scanners"
	"forgescan/scanner-runner/internal/security"
	"github.com/go-chi/render"
)

func RunScanHandler(w http.ResponseWriter, r *http.Request) {
	var job model.ScanJob

	if err := json.NewDecoder(r.Body).Decode(&job); err != nil {
		render.Status(r, 400)
		render.JSON(w, r, map[string]string{"error": "invalid json"})
		return
	}

	if err := security.ValidateJob(job); err != nil {
		render.Status(r, 400)
		render.JSON(w, r, map[string]string{"error": err.Error()})
		return
	}

	cli, err := docker.New()
	if err != nil {
		render.Status(r, 500)
		return
	}

	var scannerList []scanners.Scanner
	if job.ScanType == model.ScanTypeSAST {
		scannerList = scanners.DefaultSAST
	} else {
		scannerList = scanners.DefaultWeb
	}

	results := []map[string]string{}
	for _, scanner := range scannerList {
		logs, err := docker.RunContainer(
			docker.Ctx(),
			cli,
			scanner.Image,
			[]string{job.Target},
			int64(job.Timeout),
		)
		if err != nil {
			results = append(results, map[string]string{
				"scanner": scanner.Name,
				"status":  "failed",
			})
			continue
		}

		defer logs.Close()
		results = append(results, map[string]string{
			"scanner": scanner.Name,
			"status":  "completed",
		})
	}

	render.JSON(w, r, map[string]any{
		"job_id":  job.JobID,
		"status":  "done",
		"results": results,
	})
}
