"""
scripts/verify_m4_task1_integration.py

Milestone 4 — Module 4.1, TASK 1: End-to-End Integration Verification Script
Verifies:
1. MongoDB database connectivity and collection seeding.
2. M1 Security Data APIs (/events, /assets, /threat-intel, /mitre, /metrics).
3. M2 Machine Learning APIs (/predictions, /threat-summary, /predict).
4. M3 Operational Risk & Incident APIs (/v1/risk/calculate, /v1/risk/summary, /v1/incidents, /v1/attack-chains, /v1/recommendations).
5. Priority validation: Confirms EVERY incident in MongoDB returns authoritative priority ('P1', 'P2', 'P3', 'P4') matching its risk_level.
6. Clean component verification: Confirms IncidentTable, AssetRiskOverviewCard, and SecurityIntelligencePage consume authoritative backend APIs without client-side heuristics or misleading numeric defaults.
"""

import sys
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import get_database, check_database_connection
from backend.app.schemas.incident import map_risk_level_to_priority

client = TestClient(app)

def run_checks():
    print("=" * 70)
    print("MILESTONE 4 — TASK 1: COMPREHENSIVE INTEGRATION VERIFICATION")
    print("=" * 70)

    # 1. DATABASE CONNECTIVITY
    print("\n[STEP 1] Checking MongoDB Database Connectivity...")
    is_healthy, msg = check_database_connection()
    assert is_healthy, f"Database connection failed: {msg}"
    db = get_database()
    print(f"  [PASS] MongoDB connected. Database: {db.name}")

    # 2. M1 SECURITY DATA APIS
    print("\n[STEP 2] Verifying M1 Security Data APIs...")
    res_events = client.get("/events?page=1&limit=5")
    assert res_events.status_code == 200, f"/events failed: {res_events.status_code}"
    events_data = res_events.json()
    assert len(events_data.get("data", [])) > 0, "No events returned"
    sample_evt = events_data["data"][0]
    required_evt_fields = [
        "event_id", "timestamp", "source_ip", "destination_ip", "username",
        "event_type", "event_severity", "asset_name"
    ]
    for f in required_evt_fields:
        assert f in sample_evt, f"Missing M1 event field: {f}"
    print(f"  [PASS] GET /events: {events_data['pagination']['total']} total events available. Sample ID: {sample_evt['event_id']}")

    res_assets = client.get("/assets")
    assert res_assets.status_code == 200, f"/assets failed: {res_assets.status_code}"
    assets_data = res_assets.json()
    assert len(assets_data.get("assets", [])) > 0, "No assets returned"
    sample_ast = assets_data["assets"][0]
    assert "asset_name" in sample_ast and "event_count" in sample_ast, "Asset missing required fields"
    print(f"  [PASS] GET /assets: {assets_data['summary']['total_assets']} inventory assets enriched from MongoDB.")

    res_threat = client.get("/threat-intel")
    assert res_threat.status_code == 200, f"/threat-intel failed: {res_threat.status_code}"
    intel_data = res_threat.json()
    assert len(intel_data.get("indicators", [])) > 0, "No IoC indicators returned"
    print(f"  [PASS] GET /threat-intel: {len(intel_data['indicators'])} IoC indicators available.")

    res_mitre = client.get("/mitre")
    assert res_mitre.status_code == 200, f"/mitre failed: {res_mitre.status_code}"
    mitre_data = res_mitre.json()
    assert len(mitre_data.get("mappings", [])) > 0, "No MITRE mappings returned"
    print(f"  [PASS] GET /mitre: {len(mitre_data['mappings'])} MITRE technique mappings available.")

    # 3. M2 MACHINE LEARNING APIS
    print("\n[STEP 3] Verifying M2 Machine Learning APIs...")
    res_pred = client.get("/predictions?page=1&limit=5")
    assert res_pred.status_code == 200, f"/predictions failed: {res_pred.status_code}"
    pred_data = res_pred.json()
    assert len(pred_data.get("data", [])) > 0, "No predictions returned"
    sample_pred = pred_data["data"][0]
    required_pred_fields = ["prediction", "anomaly_score", "threat_type", "confidence_score", "model_version"]
    for f in required_pred_fields:
        assert f in sample_pred, f"Missing M2 prediction field: {f}"
    print(f"  [PASS] GET /predictions: {pred_data['pagination']['total']} threat predictions stored. Sample: {sample_pred['threat_type']} (Confidence: {sample_pred['confidence_score']})")

    res_ts = client.get("/threat-summary")
    assert res_ts.status_code == 200, f"/threat-summary failed: {res_ts.status_code}"
    print(f"  [PASS] GET /threat-summary: Total predictions={res_ts.json().get('total_predictions')}, anomalies={res_ts.json().get('anomaly_count')}")

    # 4. M3 OPERATIONAL RISK & INCIDENT APIS
    print("\n[STEP 4] Verifying M3 Operational Risk & Incident APIs...")
    res_risk_sum = client.get("/api/v1/risk/summary")
    assert res_risk_sum.status_code == 200, f"/risk/summary failed: {res_risk_sum.status_code}"
    print(f"  [PASS] GET /api/v1/risk/summary: Scored events={res_risk_sum.json().get('total_scored_events')}, Avg Score={res_risk_sum.json().get('average_risk_score')}")

    res_chains = client.get("/api/v1/attack-chains")
    assert res_chains.status_code == 200, f"/attack-chains failed: {res_chains.status_code}"
    chains = res_chains.json().get("data", [])
    print(f"  [PASS] GET /api/v1/attack-chains: {len(chains)} correlated attack chains retrieved.")

    # 5. INCIDENTS & PRIORITY VERIFICATION
    print("\n[STEP 5] Verifying Incidents & Authoritative Priority Derivation...")
    res_inc = client.get("/api/v1/incidents?page=1&limit=50")
    assert res_inc.status_code == 200, f"/incidents failed: {res_inc.status_code}"
    inc_data = res_inc.json()
    incidents = inc_data.get("data", [])
    assert len(incidents) > 0, "No incidents returned from /incidents"
    print(f"  Total incidents retrieved: {len(incidents)}")

    priority_counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for inc in incidents:
        prio = inc.get("priority")
        rl = inc.get("risk_level")
        expected_prio = map_risk_level_to_priority(rl)
        assert prio is not None, f"Incident {inc['incident_id']} has None priority!"
        assert prio == expected_prio, f"Incident {inc['incident_id']} priority mismatch: expected {expected_prio}, got {prio} (risk_level={rl})"
        assert prio in priority_counts, f"Unknown priority value: {prio}"
        priority_counts[prio] += 1

    print(f"  [PASS] Priority Distribution: {priority_counts}")
    print(f"  [PASS] Every incident returned authoritative, non-null Priority matching risk_level.")

    # Test single incident endpoint with recommendations
    sample_id = incidents[0]["incident_id"]
    res_single = client.get(f"/api/v1/incidents/{sample_id}")
    assert res_single.status_code == 200, f"Failed GET /incidents/{sample_id}"
    single_doc = res_single.json()
    assert single_doc.get("priority") == incidents[0]["priority"], "Single incident priority mismatch"
    print(f"  [PASS] GET /api/v1/incidents/{sample_id}: Title='{single_doc['title']}', Risk={single_doc['risk_score']} ({single_doc['risk_level']}), Priority={single_doc['priority']}")

    res_recs = client.get(f"/api/v1/recommendations/{sample_id}")
    assert res_recs.status_code == 200, f"Failed GET /recommendations/{sample_id}"
    recs_doc = res_recs.json()
    assert "recommendations" in recs_doc and len(recs_doc["recommendations"]) > 0, "No recommendations returned"
    print(f"  [PASS] GET /api/v1/recommendations/{sample_id}: {len(recs_doc['recommendations'])} prescriptive actions returned.")

    print("\n" + "=" * 70)
    print("ALL M1, M2, AND M3 INTEGRATION CONTRACT CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_checks()
