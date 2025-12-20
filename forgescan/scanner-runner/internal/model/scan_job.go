package model

import "time"

type ScanType string

const (
	ScanTypeWeb  ScanType = "web"
	ScanTypeSAST ScanType = "sast"
)

type ScanJob struct {
	JobID    string        `json:"job_id"`
	TenantID string        `json:"tenant_id"`
	ScanType ScanType      `json:"scan_type"`
	Target   string        `json:"target"`
	Timeout  time.Duration `json:"timeout_seconds"`
}
