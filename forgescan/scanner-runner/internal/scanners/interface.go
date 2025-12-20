package scanners

import "forgescan/scanner-runner/internal/model"

type Parser interface {
	Parse(raw string) ([]model.Finding, error)
}
