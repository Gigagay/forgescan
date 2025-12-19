# backend/app/api/v1/findings.py
from fastapi import APIRouter

router = APIRouter()

# Findings are accessed via /scans/{scan_id}/findings
# This router is a placeholder for future direct finding operations