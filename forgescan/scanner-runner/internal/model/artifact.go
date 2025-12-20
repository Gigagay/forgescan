package model

type Artifact struct {
	JobID    string `json:"job_id"`
	Scanner  string `json:"scanner"`
	Checksum string `json:"checksum"`
	Output   string `json:"output"`
}
