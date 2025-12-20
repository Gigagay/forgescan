package security

import (
	"errors"
	"net/url"
	"regexp"

	"forgescan/scanner-runner/internal/model"
)

var uuidRegex = regexp.MustCompile(
	`^[a-fA-F0-9-]{36}$`,
)

func ValidateJob(job model.ScanJob) error {
	if !uuidRegex.MatchString(job.JobID) {
		return errors.New("invalid job_id")
	}
	if !uuidRegex.MatchString(job.TenantID) {
		return errors.New("invalid tenant_id")
	}
	if job.Timeout <= 0 || job.Timeout > 600 {
		return errors.New("invalid timeout")
	}

	switch job.ScanType {
	case model.ScanTypeWeb:
		_, err := url.ParseRequestURI(job.Target)
		return err
	case model.ScanTypeSAST:
		if job.Target == "" {
			return errors.New("empty target")
		}
	default:
		return errors.New("invalid scan_type")
	}

	return nil
}
