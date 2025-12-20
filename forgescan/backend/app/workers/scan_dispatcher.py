import requests

RUNNER_URL = "http://127.0.0.1:9001/run-scan"


def dispatch_scan(scan):
	payload = {
		"job_id": str(scan.id),
		"tenant_id": str(scan.tenant_id),
		"scan_type": scan.type,
		"target": scan.target,
		"timeout_seconds": 600,
	}
	resp = requests.post(RUNNER_URL, json=payload, timeout=700)
	resp.raise_for_status()
	return resp.json()
