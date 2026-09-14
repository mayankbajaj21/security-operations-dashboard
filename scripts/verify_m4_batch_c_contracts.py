import sys
print('Running verification script')
import os
import traceback
from fastapi.testclient import TestClient
# Ensure project root is in PYTHONPATH for relative imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.app.main import app

client = TestClient(app)

def verify_posture_api():
    """Task 15 – Verify /api/v1/posture returns full M4 posture data."""
    resp = client.get('/api/v1/posture')
    if resp.status_code != 200:
        raise AssertionError(f"Posture endpoint returned {resp.status_code}")
    data = resp.json()
    for key in ['posture_score', 'status', 'conditions']:
        if key not in data:
            raise AssertionError(f"Posture response missing required key: {key}")
    expected_conditions = {
        'critical_vulnerabilities',
        'active_incidents',
        'high_risk_assets',
        'unresolved_threats',
        'threat_volume'
    }
    missing = expected_conditions - set(data['conditions'].keys())
    if missing:
        raise AssertionError(f"Posture conditions missing: {missing}")
    score = data['posture_score']
    if not (0 <= score <= 100):
        raise AssertionError(f"Posture score out of bounds: {score}")
    print(f"Task 15 posture API verification passed (score={score})")

def verify_executive_summary_api():
    """Task 16 – Verify executive summary endpoint supplies required M4 fields."""
    resp = client.get('/api/reports/executive/data')
    if resp.status_code != 200:
        raise AssertionError(f"Executive summary endpoint returned {resp.status_code}")
    data = resp.json()
    for key in ['posture', 'metrics', 'critical_cves', 'affected_assets', 'recent_critical_incidents']:
        if key not in data:
            raise AssertionError(f"Executive summary missing top‑level key: {key}")
    required_metric_keys = {
        'critical_threats',
        'active_incidents',
        'critical_vulnerabilities',
        'affected_assets_count'
    }
    missing_metrics = required_metric_keys - set(data['metrics'].keys())
    if missing_metrics:
        raise AssertionError(f"Executive metrics missing required fields: {missing_metrics}")
    for sub in ['posture_score', 'status', 'conditions']:
        if sub not in data['posture']:
            raise AssertionError(f"Executive posture missing sub‑key: {sub}")
    expected_conditions = {
        'critical_vulnerabilities',
        'active_incidents',
        'high_risk_assets',
        'unresolved_threats',
        'threat_volume'
    }
    missing_cond = expected_conditions - set(data['posture']['conditions'].keys())
    if missing_cond:
        raise AssertionError(f"Executive posture conditions missing: {missing_cond}")
    print("Task 16 executive summary API verification passed")

def verify_report_downloads():
    """Task 17 – Verify downloadable PDF and CSV reports meet M4 specification."""
    pdf_resp = client.get('/api/reports/executive?format=pdf')
    if pdf_resp.status_code != 200:
        raise AssertionError(f"PDF report endpoint returned {pdf_resp.status_code}")
    if not pdf_resp.headers.get('content-type', '').split(';')[0] == 'application/pdf':
        raise AssertionError('PDF report content-type is not application/pdf')
    cd = pdf_resp.headers.get('content-disposition', '').lower()
    if 'attachment' not in cd or '.pdf' not in cd:
        raise AssertionError('PDF report missing proper Content‑Disposition filename')
    if len(pdf_resp.content) == 0:
        raise AssertionError('PDF report body is empty')
    if not pdf_resp.content.startswith(b'%PDF'):
        raise AssertionError('PDF content does not start with %PDF signature')
    csv_resp = client.get('/api/reports/executive?format=csv')
    if csv_resp.status_code != 200:
        raise AssertionError(f"CSV report endpoint returned {csv_resp.status_code}")
    if not csv_resp.headers.get('content-type', '').startswith('text/csv'):
        raise AssertionError('CSV report content-type is not text/csv')
    cd_csv = csv_resp.headers.get('content-disposition', '').lower()
    if 'attachment' not in cd_csv or '.csv' not in cd_csv:
        raise AssertionError('CSV report missing proper Content‑Disposition filename')
    csv_text = csv_resp.text
    if not csv_text.strip():
        raise AssertionError('CSV report body is empty')
    lines = [ln for ln in csv_text.splitlines() if ln.strip()]
    header_found = any('Metric' in line and 'Value' in line for line in lines)
    if not header_found:
        raise AssertionError('CSV report does not contain expected Metric/Value header')
    required_fields = ['Security Posture Score', 'Critical Threats', 'Active Incidents', 'Critical Vulnerabilities', 'Affected Assets', 'Generation Timestamp']
    missing_fields = [f for f in required_fields if f not in csv_text]
    if missing_fields:
        raise AssertionError(f"CSV report missing required fields: {missing_fields}")
    print("Task 17 report download verification passed")

def main():
    try:
        verify_posture_api()
        verify_executive_summary_api()
        verify_report_downloads()
        print('\nAll M4 Batch C contract verifications PASSED')
    except Exception:
        print('\nVerification FAILED')
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
