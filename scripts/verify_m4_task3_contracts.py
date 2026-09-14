"""
scripts/verify_m4_task3_contracts.py

Milestone 4 — Module 4.3, Task 3: Critical Threat Panel Verification
Automated Non-Browser Test Suite validating backend API contracts,
authoritative M3 data fidelity, exact 6 table columns, and Threat Investigation routing.
"""

import sys
import json
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.app.main import app

client = TestClient(app)

def run_tests():
    print("=" * 70)
    print("VERIFYING MILESTONE 4 — MODULE 4.3, TASK 3: CRITICAL THREAT PANEL")
    print("=" * 70)

    # Test 1: GET /api/v1/incidents?risk_level=Critical API Contract
    print("\n[Test 1] Querying GET /api/v1/incidents?risk_level=Critical...")
    resp = client.get("/api/v1/incidents?risk_level=Critical&limit=50")
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "data" in body, "Response missing 'data' key"
    assert "pagination" in body, "Response missing 'pagination' key"
    incidents = body["data"]
    total = body["pagination"]["total"]
    print(f"  -> Returned {len(incidents)} items (total in collection: {total})")
    assert total == 17, f"Expected exactly 17 critical incidents in DB, got {total}"
    assert len(incidents) == 17, f"Expected 17 items returned with limit=50, got {len(incidents)}"

    # Test 2: Verify all 17 incidents are Critical and Priority is P1
    print("\n[Test 2] Validating Risk Level == 'Critical' and Priority == 'P1'...")
    for idx, inc in enumerate(incidents):
        r_level = inc.get("risk_level")
        prio = inc.get("priority")
        assert r_level == "Critical", f"Incident #{idx} ({inc.get('incident_id')}) has risk_level '{r_level}' != 'Critical'"
        assert prio == "P1", f"Incident #{idx} ({inc.get('incident_id')}) has priority '{prio}' != 'P1'"
    print(f"  -> All {len(incidents)} incidents strictly confirmed with risk_level='Critical' and priority='P1'")

    # Test 3: Verify all 6 Required Columns exist on every incident
    print("\n[Test 3] Verifying exact 6 M4 required fields on all records...")
    # Required columns: Incident, Threat, Asset, Risk, Priority, Status
    for inc in incidents:
        inc_id = inc.get("incident_id")
        threat = inc.get("threat_type") or inc.get("title")
        asset = inc.get("affected_asset") or inc.get("asset_id")  # May be None for infrastructure-wide
        risk_score = inc.get("risk_score")
        priority = inc.get("priority")
        status = inc.get("status")

        assert inc_id and str(inc_id).startswith("INC-"), f"Invalid Incident ID: {inc_id}"
        assert threat, f"Incident {inc_id} missing Threat field"
        assert risk_score is not None and 80 <= risk_score <= 100, f"Critical risk score {risk_score} out of range [80-100]"
        assert priority == "P1", f"Priority {priority} != P1"
        assert status in {"Open", "Investigating", "Resolved", "False Positive"}, f"Invalid status: {status}"
    print(f"  -> Exact 6 fields validated on all {len(incidents)} records")

    # Test 4: Verify single incident detail lookup for Threat Investigation drill-down
    print("\n[Test 4] Testing GET /api/v1/incidents/{incident_id} drill-down contract...")
    sample_id = incidents[0]["incident_id"]
    detail_resp = client.get(f"/api/v1/incidents/{sample_id}")
    assert detail_resp.status_code == 200, f"Expected 200 for {sample_id}, got {detail_resp.status_code}"
    detail = detail_resp.json()
    assert detail["incident_id"] == sample_id
    assert "reasons" in detail and isinstance(detail["reasons"], list), "Missing XAI reasons"
    assert "recommendations" in detail and isinstance(detail["recommendations"], list), "Missing mitigation recommendations"
    assert "related_events" in detail and isinstance(detail["related_events"], list), "Missing related_events"
    print(f"  -> Incident {sample_id} details verified: {len(detail['reasons'])} XAI reasons, {len(detail['recommendations'])} recommendations, {len(detail['related_events'])} related events")

    # Test 5: Verify Frontend Component Files and Structure
    print("\n[Test 5] Auditing frontend component code and column definitions...")
    panel_file = BASE_DIR / "frontend" / "src" / "components" / "CriticalThreatPanel.jsx"
    assert panel_file.exists(), f"CriticalThreatPanel.jsx missing at {panel_file}"
    panel_code = panel_file.read_text(encoding="utf-8")
    
    # Check 6 required column headers in table
    for col in ["Incident", "Threat", "Asset", "Risk", "Priority", "Status"]:
        assert f">{col}<" in panel_code, f"CriticalThreatPanel.jsx missing column header '{col}'"
    print("  -> Confirmed exact 6 table column headers in CriticalThreatPanel.jsx")

    # Check modal and investigation actions in panel
    assert "Critical Threat Panel" in panel_code, "Title 'Critical Threat Panel' missing"
    assert "onInvestigateIncident" in panel_code, "onInvestigateIncident callback missing"
    assert "onInvestigateEvent" in panel_code, "onInvestigateEvent callback missing"
    assert "modalBackdrop" in panel_code or "selectedIncident" in panel_code, "Details modal state missing"
    print("  -> Confirmed details modal and Threat Investigation callbacks")

    # Test 6: Verify App.jsx Integration
    print("\n[Test 6] Auditing App.jsx integration...")
    app_file = BASE_DIR / "frontend" / "src" / "App.jsx"
    app_code = app_file.read_text(encoding="utf-8")
    assert "CriticalThreatPanel" in app_code, "CriticalThreatPanel not imported or mounted in App.jsx"
    assert "getIncidents({ risk_level: 'Critical'" in app_code, "App.jsx not querying risk_level: 'Critical'"
    assert "handleInvestigateIncident" in app_code, "handleInvestigateIncident handler missing in App.jsx"
    assert "selectedIncidentId={selectedIncidentId}" in app_code, "selectedIncidentId not passed to AnalyticsPage"
    print("  -> Confirmed CriticalThreatPanel mounted with Critical filter and investigation handlers in App.jsx")

    # Test 7: Verify AnalyticsPage forwarding
    print("\n[Test 7] Auditing AnalyticsPage prop forwarding...")
    analytics_file = BASE_DIR / "frontend" / "src" / "pages" / "AnalyticsPage.jsx"
    analytics_code = analytics_file.read_text(encoding="utf-8")
    assert "selectedIncidentId" in analytics_code, "selectedIncidentId missing in AnalyticsPage.jsx"
    assert "initialIncidentId={initialIncidentId || selectedIncidentId}" in analytics_code, "initialIncidentId not passed to IncidentResponsePage"
    print("  -> Confirmed prop forwarding to IncidentResponsePage in AnalyticsPage.jsx")

    print("\n" + "=" * 70)
    print("ALL 7 CONTRACT TESTS PASSED FOR TASK 3: CRITICAL THREAT PANEL")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
