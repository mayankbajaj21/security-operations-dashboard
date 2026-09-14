"""
scripts/verify_m4_batch_a_contracts.py

Milestone 4 — Batch A Verification Suite (Tasks 5, 6, 7, 8):
- Task 5: Attack Chain (Stages derived from incident related_events, 7 required stage fields, drill-down event link)
- Task 6: MITRE Technique Analysis (Technique, Name, Events, Risk table & synchronized distribution chart)
- Task 7: Vulnerability Management (Critical/High/Medium CVEs, Affected Assets, Table: CVE, Asset, CVSS, Severity, Status)
- Task 8: IOC Intelligence (IP, Domain, URL, File Hash, Email types, Table: IOC, Type, Status, Threat Count, Affected Assets, First Seen, Last Seen)

Validates API contracts, dynamic derivations, empty-state honesty, and frontend integration code wiring.
"""

import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.main import app

def run_verification():
    client = TestClient(app)
    print("=" * 75)
    print("MILIESTONE 4 — BATCH A (TASKS 5-8) CONTRACT VERIFICATION SUITE")
    print("=" * 75)

    # =========================================================================
    # TASK 5: ATTACK CHAIN VERIFICATION
    # =========================================================================
    print("\n[TASK 5] Verifying Attack Chain endpoint GET /api/v1/incidents/{incident_id}/attack-chain...")
    
    # 1. Multi-event incident: INC-FA144BF5
    res = client.get("/api/v1/incidents/INC-FA144BF5/attack-chain")
    assert res.status_code == 200, f"Expected 200, got {res.status_code}"
    chain_data = res.json()
    assert chain_data["incident_id"] == "INC-FA144BF5"
    assert "stages" in chain_data
    stages = chain_data["stages"]
    print(f"  • Incident INC-FA144BF5 stages count: {len(stages)}")
    assert len(stages) == 3, f"Expected 3 stages for INC-FA144BF5, got {len(stages)}"
    assert chain_data["total_stages"] == 3

    # Required 7 stage fields: Event ID, Timestamp, Source, Destination, User, MITRE Technique, Risk
    required_7_fields = [
        ("event_id", "Event ID"),
        ("timestamp", "Timestamp"),
        ("source", "Source"),
        ("destination", "Destination"),
        ("user", "User"),
        ("mitre_technique", "MITRE Technique"),
        ("risk", "Risk")
    ]

    for stage in stages:
        print(f"    - Stage {stage.get('stage_number')}: Event ID={stage.get('event_id')} | Technique={stage.get('mitre_technique')} | Risk={stage.get('risk')} | User={stage.get('user')}")
        for key, label in required_7_fields:
            assert key in stage, f"Missing required stage field: {key} ({label})"
            assert stage[key] is not None, f"Stage field {key} should not be None"

    # Verify event ordering by timestamp (EVT00010 <= EVT00011 <= EVT00012)
    timestamps = [s["timestamp"] for s in stages]
    assert timestamps == sorted(timestamps), f"Stages not properly ordered by timestamp: {timestamps}"

    # 2. Single event incident: INC-797B42E0
    res_single = client.get("/api/v1/incidents/INC-797B42E0/attack-chain")
    assert res_single.status_code == 200
    single_chain = res_single.json()
    assert len(single_chain["stages"]) == 1
    assert single_chain["stages"][0]["event_id"] == "EVT00034"
    assert single_chain["stages"][0]["source"] == "170.151.142.64"
    assert single_chain["stages"][0]["destination"] == "10.0.6.192"
    assert single_chain["stages"][0]["user"] == "root"
    assert "T1110" in single_chain["stages"][0]["mitre_technique"]
    assert single_chain["stages"][0]["risk"] == "High"
    print("  • Incident INC-797B42E0 verified with EVT00034 authoritative data.")

    # 3. Non-existent incident handling (404)
    res_404 = client.get("/api/v1/incidents/INC-NONEXISTENT-999/attack-chain")
    assert res_404.status_code == 404
    print("  • 404 correctly returned for non-existent incident.")
    print("  [PASS] Task 5 Attack Chain verified successfully.")

    # =========================================================================
    # TASK 6: MITRE TECHNIQUE ANALYSIS VERIFICATION
    # =========================================================================
    print("\n[TASK 6] Verifying MITRE Technique Analysis (GET /mitre and GET /mitre/techniques)...")
    res_mitre = client.get("/mitre")
    assert res_mitre.status_code == 200
    mitre_payload = res_mitre.json()

    assert "techniques" in mitre_payload, "Missing 'techniques' in /mitre response"
    assert "distribution" in mitre_payload, "Missing 'distribution' in /mitre response"
    techniques = mitre_payload["techniques"]
    distribution = mitre_payload["distribution"]

    assert len(techniques) > 0, "Expected at least 1 MITRE technique"
    print(f"  • Authoritative techniques found: {len(techniques)}")

    # Required table columns: Technique, Name, Events, Risk
    required_mitre_cols = ["technique", "name", "events", "risk"]
    for t in techniques:
        print(f"    - Technique: {t.get('technique')} | Name: {t.get('name')} | Events: {t.get('events')} | Risk: {t.get('risk')}")
        for col in required_mitre_cols:
            assert col in t, f"Missing MITRE column: {col}"
            assert t[col] is not None, f"Column {col} is None"

    # Verify T1110 specific authoritative values
    t1110 = next((t for t in techniques if t["technique"] == "T1110"), None)
    assert t1110 is not None, "Technique T1110 not found"
    assert t1110["name"] == "Brute Force"
    assert t1110["events"] == 179
    assert t1110["risk"] in ["Critical", "High"]

    # Verify distribution matches techniques data (synchronization requirement)
    assert len(distribution) == len(techniques)
    for dist_item, tech_item in zip(distribution, techniques):
        assert dist_item["technique"] == tech_item["technique"]
        assert dist_item["events"] == tech_item["events"]
    print("  • Technique distribution chart data is synchronized with the table data.")

    # Verify dedicated endpoint GET /mitre/techniques
    res_tech = client.get("/mitre/techniques")
    assert res_tech.status_code == 200
    res_tech_data = res_tech.json()
    assert len(res_tech_data.get("data", [])) == len(techniques)
    print("  [PASS] Task 6 MITRE Technique Analysis verified successfully.")

    # =========================================================================
    # TASK 7: VULNERABILITY VERIFICATION
    # =========================================================================
    print("\n[TASK 7] Verifying Vulnerabilities (GET /vulnerabilities and GET /api/v1/vulnerabilities)...")
    res_vuln = client.get("/vulnerabilities")
    assert res_vuln.status_code == 200, f"Expected 200, got {res_vuln.status_code}"
    vuln_data = res_vuln.json()

    assert "summary" in vuln_data, "Missing 'summary' in /vulnerabilities"
    assert "vulnerabilities" in vuln_data, "Missing 'vulnerabilities' in /vulnerabilities"
    v_summary = vuln_data["summary"]
    v_list = vuln_data["vulnerabilities"]

    print(f"  • Summary KPI Counts:")
    print(f"    - Critical CVEs: {v_summary.get('critical_cves')}")
    print(f"    - High CVEs:     {v_summary.get('high_cves')}")
    print(f"    - Medium CVEs:   {v_summary.get('medium_cves')}")
    print(f"    - Total Records: {v_summary.get('total')}")
    print(f"    - Affected Assets: {v_summary.get('affected_assets')}")

    assert v_summary.get("critical_cves") == 15
    assert v_summary.get("high_cves") == 15
    assert v_summary.get("medium_cves") == 15
    assert v_summary.get("affected_assets") == 5

    # Required table columns: CVE, Asset, CVSS, Severity, Status
    required_vuln_cols = [
        ("cve", "CVE"),
        ("asset", "Asset"),
        ("cvss", "CVSS"),
        ("severity", "Severity"),
        ("status", "Status")
    ]

    print(f"  • Checking first 3 vulnerability records for exact M4 schema:")
    for v in v_list[:3]:
        print(f"    - CVE: {v.get('cve')} | Asset: {v.get('asset')} | CVSS: {v.get('cvss')} | Severity: {v.get('severity')} | Status: {v.get('status')}")
        for key, label in required_vuln_cols:
            assert key in v, f"Missing vulnerability field {key} ({label})"
            assert v[key] is not None, f"Field {key} is None"

    # Verify severity filtering
    res_crit = client.get("/vulnerabilities?severity=Critical")
    assert res_crit.status_code == 200
    crit_list = res_crit.json()["vulnerabilities"]
    assert len(crit_list) == 15
    assert all(v["severity"] == "Critical" for v in crit_list)
    print("  • Severity query filter verified (15 Critical returned).")
    print("  [PASS] Task 7 Vulnerabilities verified successfully.")

    # =========================================================================
    # TASK 8: IOC INTELLIGENCE VERIFICATION
    # =========================================================================
    print("\n[TASK 8] Verifying IOC Intelligence (GET /threat-intel and GET /threat-intel/iocs)...")
    res_intel = client.get("/threat-intel")
    assert res_intel.status_code == 200
    intel_data = res_intel.json()

    assert "iocs" in intel_data, "Missing 'iocs' in /threat-intel"
    iocs = intel_data["iocs"]
    print(f"  • Total IOC records in threat-intel: {len(iocs)}")
    assert len(iocs) > 0

    # Required fields: IOC, Type, Status, Threat Count, Affected Assets, First Seen, Last Seen
    required_ioc_cols = [
        ("ioc", "IOC"),
        ("type", "Type"),
        ("status", "Status"),
        ("threat_count", "Threat Count"),
        ("affected_assets", "Affected Assets"),
        ("first_seen", "First Seen"),
        ("last_seen", "Last Seen")
    ]

    print(f"  • Checking IOC records for exact M4 schema:")
    ioc_types_present = set()
    for item in iocs:
        ioc_types_present.add(item.get("type"))
        print(f"    - IOC: {item.get('ioc')} | Type: {item.get('type')} | Status: {item.get('status')} | Threat Count: {item.get('threat_count')} | Assets: {item.get('affected_assets')}")
        for key, label in required_ioc_cols:
            assert key in item, f"Missing IOC field {key} ({label})"
            assert item[key] is not None, f"Field {key} is None"

    # Verify authoritative types (e.g., IP)
    assert "IP" in ioc_types_present or "Domain" in ioc_types_present
    print(f"  • Authoritative IOC types present: {sorted(list(ioc_types_present))}")

    # Verify dedicated endpoint GET /threat-intel/iocs with filtering
    res_iocs = client.get("/threat-intel/iocs")
    assert res_iocs.status_code == 200
    res_iocs_data = res_iocs.json()
    assert "iocs" in res_iocs_data
    assert "summary" in res_iocs_data
    assert res_iocs_data["summary"]["total_iocs"] == len(iocs)

    # Filter by type: IP
    res_ip = client.get("/threat-intel/iocs?ioc_type=IP")
    assert res_ip.status_code == 200
    assert all(x["type"] == "IP" for x in res_ip.json()["iocs"])
    print("  • Type filter for IP verified successfully.")
    print("  [PASS] Task 8 IOC Intelligence verified successfully.")

    # =========================================================================
    # FRONTEND CODE WIRING AUDIT (STATIC NON-BROWSER CHECK)
    # =========================================================================
    print("\n[FRONTEND WIRING AUDIT] Checking frontend files for required M4 wiring...")
    
    # 1. Check api.js has new endpoints
    api_js = (ROOT / "frontend" / "src" / "services" / "api.js").read_text(encoding="utf-8")
    assert "getIncidentAttackChain" in api_js
    assert "getMitreTechniques" in api_js
    assert "getVulnerabilities" in api_js
    assert "getThreatIntelIocs" in api_js
    print("  • frontend/src/services/api.js contains all 4 service functions.")

    # 2. Check IncidentResponsePage.jsx has attack chain & drill-down wiring
    irp = (ROOT / "frontend" / "src" / "pages" / "IncidentResponsePage.jsx").read_text(encoding="utf-8")
    assert "attackChain" in irp
    assert "selectedStage" in irp
    assert "onInvestigateEvent" in irp
    assert "Event ID" in irp
    assert "MITRE Technique" in irp
    print("  • frontend/src/pages/IncidentResponsePage.jsx wires attack chain and onInvestigateEvent drill-down.")

    # 3. Check SecurityIntelligencePage.jsx has IOC panel, Vulnerability panel, MITRE table and chart
    sip = (ROOT / "frontend" / "src" / "pages" / "SecurityIntelligencePage.jsx").read_text(encoding="utf-8")
    assert "IOC Intelligence" in sip
    assert "Threat Count" in sip
    assert "Affected Assets" in sip
    assert "First Seen" in sip
    assert "Last Seen" in sip
    assert "Critical CVEs" in sip
    assert "High CVEs" in sip
    assert "Medium CVEs" in sip
    assert "CVSS" in sip
    assert "MITRE Technique Analysis" in sip
    print("  • frontend/src/pages/SecurityIntelligencePage.jsx contains all M4 panels and table columns.")

    print("\n" + "=" * 75)
    print("ALL MILESTONE 4 BATCH A (TASKS 5-8) VERIFICATION CHECKS PASSED!")
    print("=" * 75)

if __name__ == "__main__":
    run_verification()
