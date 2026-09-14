"""
scripts/verify_m4_task4_contracts.py

Milestone 4 — Module 4.3, Task 4: Threat Investigation Verification Suite

Validates:
1. Incident Details (12 exact fields):
   - Incident ID, Threat Type, Risk Score, Risk Level, Confidence, Affected Asset,
     Source IP, User, IOC, MITRE Technique, CVE, CVSS.
2. Risk Factors (6 exact factors):
   - Critical asset, High ML confidence, Malicious IOC, High CVSS, Multiple related events, Ransomware behavior detected.
3. Authoritative traceability through established related_events.
4. Clean None/"N/A" handling for unlinked data (no invented asset matching).
5. Zero hardcoded server names for Critical asset.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Ensure workspace root is in python path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.main import app

def run_verification():
    client = TestClient(app)
    print("=" * 70)
    print("MILIESTONE 4 — TASK 4: THREAT INVESTIGATION CONTRACT VERIFICATION")
    print("=" * 70)

    # 1. Single Incident Deep-Dive: INC-797B42E0
    print("\n[CHECK 1] Querying GET /api/v1/incidents/INC-797B42E0...")
    res = client.get("/api/v1/incidents/INC-797B42E0")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    inc = res.json()

    # Verify 12 exact Incident Details fields are present
    required_12_fields = [
        ("incident_id", "Incident ID"),
        ("threat_type", "Threat Type"),
        ("risk_score", "Risk Score"),
        ("risk_level", "Risk Level"),
        ("confidence_score", "Confidence"),
        ("affected_asset", "Affected Asset"),
        ("source_ip", "Source IP"),
        ("affected_user", "User"),
        ("ioc_status", "IOC"),
        ("mitre_techniques", "MITRE Technique"),
        ("cve_id", "CVE"),
        ("cvss_score", "CVSS")
    ]

    print("\nVerifying 12 exact Incident Details fields:")
    for key, label in required_12_fields:
        val = inc.get(key)
        print(f"  • {label:18} [{key:18}]: {val}")
        assert key in inc, f"Missing required field {key}"

    # Verify specific resolved values for INC-797B42E0
    assert inc["incident_id"] == "INC-797B42E0"
    assert inc["threat_type"] == "Brute Force"
    assert inc["risk_score"] == 94
    assert inc["risk_level"] == "Critical"
    assert inc["confidence_score"] == 89 or inc.get("ml_confidence") == 89
    assert inc["affected_asset"] == "DB-SRV-PROD-01"
    assert inc["source_ip"] in ("198.51.100.45", "170.151.142.64")
    assert inc["affected_user"] == "admin_mayank" or inc.get("username") == "admin_mayank"
    assert inc["ioc_status"] == "Malicious"
    assert "T1110" in inc.get("mitre_techniques", [])
    # CVSS traced from correlated event EVT00034 raw_cvss_score: 0.3
    assert inc["cvss_score"] == 0.3, f"Expected CVSS 0.3 from EVT00034, got {inc.get('cvss_score')}"
    # CVE is None on EVT00034 -> returns None (frontend displays N/A)
    assert inc["cve_id"] is None, f"Expected None for CVE, got {inc.get('cve_id')}"
    print("  [PASS] 12 Incident Details fields verified with authoritative values.")

    # 2. Verify 6 exact Risk Factors
    print("\n[CHECK 2] Verifying 6 exact Risk Factors for INC-797B42E0:")
    rf = inc.get("risk_factors")
    assert isinstance(rf, dict), f"Expected dict for risk_factors, got {type(rf)}"

    required_6_factors = [
        ("critical_asset", "Critical asset"),
        ("high_ml_confidence", "High ML confidence"),
        ("malicious_ioc", "Malicious IOC"),
        ("high_cvss", "High CVSS"),
        ("multiple_related_events", "Multiple related events"),
        ("ransomware_behavior_detected", "Ransomware behavior detected")
    ]

    for key, label in required_6_factors:
        status_bool = rf.get(key)
        print(f"  • {label:30} [{key:30}]: {status_bool}")
        assert key in rf, f"Missing risk factor {key}"

    # Critical asset: DB-SRV-PROD-01 is NOT Critical in M3 (asserts NO hardcoded server name rule!)
    assert rf["critical_asset"] is False, "Expected False for critical_asset (no hardcoded server names!)"
    # High ML confidence: confidence 89 >= 80 -> True
    assert rf["high_ml_confidence"] is True, "Expected True for high_ml_confidence (89% >= 80)"
    # Malicious IOC: ioc_status is Malicious -> True
    assert rf["malicious_ioc"] is True, "Expected True for malicious_ioc"
    # High CVSS: 0.3 < 7.0 -> False
    assert rf["high_cvss"] is False, "Expected False for high_cvss (0.3 < 7.0)"
    # Multiple related events: len(['EVT00034']) == 1 -> False
    assert rf["multiple_related_events"] is False, "Expected False for multiple_related_events"
    # Ransomware: threat is Brute Force -> False
    assert rf["ransomware_behavior_detected"] is False, "Expected False for ransomware_behavior_detected"
    print("  [PASS] All 6 Risk Factors accurately evaluated from authoritative M3 data.")

    # 3. Verify Multi-Event Incident: INC-FA144BF5
    print("\n[CHECK 3] Querying multi-event incident INC-FA144BF5...")
    res_multi = client.get("/api/v1/incidents/INC-FA144BF5")
    assert res_multi.status_code == 200
    inc_multi = res_multi.json()
    rf_multi = inc_multi.get("risk_factors", {})
    print(f"  • related_events: {inc_multi.get('related_events')}")
    print(f"  • multiple_related_events: {rf_multi.get('multiple_related_events')}")
    print(f"  • high_ml_confidence: {rf_multi.get('high_ml_confidence')}")
    assert rf_multi.get("multiple_related_events") is True, "Expected True for multiple_related_events (>1 events)"
    assert rf_multi.get("high_ml_confidence") is True, "Expected True for high_ml_confidence (88 >= 80)"
    print("  [PASS] Multi-event correlation accurately reflected.")

    # 4. Verify Unlinked Incident Returns Clean None (Rule 3 & 4)
    print("\n[CHECK 4] Verifying unlinked incident clean fallback...")
    res_unlinked = client.get("/api/v1/incidents/INC-2026-005")
    assert res_unlinked.status_code == 200
    inc_unlinked = res_unlinked.json()
    print(f"  • cve_id: {inc_unlinked.get('cve_id')} (Clean None for N/A display)")
    print(f"  • cvss_score: {inc_unlinked.get('cvss_score')} (Clean None for N/A display)")
    print(f"  • confidence_score: {inc_unlinked.get('confidence_score')} (Clean None for N/A display)")
    assert inc_unlinked.get("cve_id") is None
    assert inc_unlinked.get("cvss_score") is None
    print("  [PASS] No synthetic or guessed values for unlinked incidents.")

    # 5. Verify List API Endpoint GET /api/v1/incidents
    print("\n[CHECK 5] Querying GET /api/v1/incidents (paginated list)...")
    res_list = client.get("/api/v1/incidents?limit=5")
    assert res_list.status_code == 200
    items = res_list.json().get("data", [])
    assert len(items) > 0
    for itm in items:
        assert "cve_id" in itm
        assert "cvss_score" in itm
        assert "risk_factors" in itm
        assert isinstance(itm["risk_factors"], dict)
        assert len(itm["risk_factors"]) == 6
    print(f"  [PASS] All {len(items)} incidents in list endpoint provide complete Task 4 fields.")

    print("\n" + "=" * 70)
    print("ALL MILESTONE 4 TASK 4 CHECKS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
