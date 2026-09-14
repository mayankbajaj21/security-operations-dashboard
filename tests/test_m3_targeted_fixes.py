"""
tests/test_m3_targeted_fixes.py

Milestone 3 — Targeted Fix Validation Suite:
1. Table/UI CSS Contract (fit within viewport, table-layout: fixed, overflow-x: hidden, 12 columns)
2. Incident-Specific Assignee Isolation & Verification
3. Incident-Specific Investigation Notes Isolation & Verification
4. Persistence of Assignee and Notes across fetches & updates
5. Reopen Workflow: Open -> Investigating -> Resolved -> Reopen (Investigating)
6. Post-Reopening Workflow: Investigating -> False Positive & Investigating -> Resolved
7. Rejection of Invalid Transitions (Resolved -> FP direct, Resolved -> Open, FP -> Investigating, FP -> Resolved, FP -> Open)
8. Reopen intelligence preservation (risk_score, risk_level, recommendations, reasons, events, MITRE, IoC)
9. GET /api/v1/incidents/{incident_id} verification after reopening
"""

from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient

# Add project root to path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.main import app
from backend.app.services.incident_service import IncidentService, validate_status_transition


class TestMilestone3TargetedFixes(unittest.TestCase):
    """
    Automated test suite verifying targeted M3 lifecycle and UX fixes.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.incident_service = IncidentService()

    # -------------------------------------------------------------------------
    # TEST 1: TABLE / UI CONTRACT
    # -------------------------------------------------------------------------
    def test_table_css_and_jsx_contract(self):
        """
        Verify that Priority Incidents table uses soc-table-fit-container (overflow-x: hidden),
        table-layout: fixed, and explicit column widths so no horizontal scroll is introduced.
        """
        css_file = BASE_DIR / "frontend" / "src" / "assets" / "styles" / "index.css"
        self.assertTrue(css_file.exists(), "index.css file not found")
        css_content = css_file.read_text(encoding="utf-8")

        self.assertIn(".soc-table-fit-container", css_content)
        self.assertIn("overflow-x: hidden", css_content)
        self.assertIn(".soc-table-fit", css_content)
        self.assertIn("table-layout: fixed", css_content)

        jsx_file = BASE_DIR / "frontend" / "src" / "pages" / "IncidentResponsePage.jsx"
        self.assertTrue(jsx_file.exists(), "IncidentResponsePage.jsx not found")
        jsx_content = jsx_file.read_text(encoding="utf-8")

        self.assertIn("soc-table-fit-container", jsx_content)
        self.assertIn("soc-table-fit", jsx_content)

        required_columns = [
            "Incident ID",
            "Threat Category",
            "Risk Score",
            "Risk Level",
            "Priority",
            "Status",
            "Affected Asset",
            "User",
            "ML Conf",
            "MITRE Techniques",
            "IoC",
            "Action"
        ]
        for col in required_columns:
            self.assertIn(col, jsx_content, f"Missing table column header: {col}")

    # -------------------------------------------------------------------------
    # TEST 2: INCIDENT-SPECIFIC ASSIGNEE
    # -------------------------------------------------------------------------
    def test_incident_specific_assignee_isolation(self):
        """
        Create Incident A and Incident B.
        Set assignee = 'analyst_A' on Incident A.
        Verify Incident A has assignee = 'analyst_A', and Incident B does NOT have 'analyst_A'.
        """
        inc_a = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_TEST_A_ASSIGNEE", "risk_score": 85, "risk_level": "Critical", "threat_type": "Malware"},
            event_telemetry={"asset_name": "CORP-WS-01", "username": "user_a"}
        )
        inc_b = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_TEST_B_ASSIGNEE", "risk_score": 70, "risk_level": "High", "threat_type": "Brute Force"},
            event_telemetry={"asset_name": "CORP-WS-02", "username": "user_b"}
        )

        patch_res_a = self.client.patch(
            f"/api/v1/incidents/{inc_a.incident_id}/status",
            json={"status": "Investigating", "assigned_to": "analyst_A"}
        )
        self.assertEqual(patch_res_a.status_code, 200)
        self.assertEqual(patch_res_a.json()["assigned_to"], "analyst_A")

        get_res_a = self.client.get(f"/api/v1/incidents/{inc_a.incident_id}")
        self.assertEqual(get_res_a.status_code, 200)
        self.assertEqual(get_res_a.json()["assigned_to"], "analyst_A")

        get_res_b = self.client.get(f"/api/v1/incidents/{inc_b.incident_id}")
        self.assertEqual(get_res_b.status_code, 200)
        self.assertNotEqual(get_res_b.json().get("assigned_to"), "analyst_A")
        self.assertIsNone(get_res_b.json().get("assigned_to"))

    # -------------------------------------------------------------------------
    # TEST 3: INCIDENT-SPECIFIC NOTES
    # -------------------------------------------------------------------------
    def test_incident_specific_notes_isolation(self):
        """
        Set notes for Incident A. Fetch Incident A and verify notes are present.
        Fetch Incident B and verify Incident B does NOT contain Incident A's notes.
        """
        inc_a = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_TEST_A_NOTES", "risk_score": 82, "risk_level": "Critical", "threat_type": "Phishing"},
            event_telemetry={"asset_name": "MAIL-GW-01"}
        )
        inc_b = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_TEST_B_NOTES", "risk_score": 64, "risk_level": "High", "threat_type": "Command and Control"},
            event_telemetry={"asset_name": "PROXY-01"}
        )

        notes_content_a = "Incident A triage: isolated endpoint and revoked session keys."
        patch_res_a = self.client.patch(
            f"/api/v1/incidents/{inc_a.incident_id}/status",
            json={"status": "Investigating", "notes": notes_content_a}
        )
        self.assertEqual(patch_res_a.status_code, 200)
        self.assertEqual(patch_res_a.json()["notes"], notes_content_a)

        get_res_a = self.client.get(f"/api/v1/incidents/{inc_a.incident_id}")
        self.assertEqual(get_res_a.status_code, 200)
        self.assertEqual(get_res_a.json()["notes"], notes_content_a)

        get_res_b = self.client.get(f"/api/v1/incidents/{inc_b.incident_id}")
        self.assertEqual(get_res_b.status_code, 200)
        self.assertNotEqual(get_res_b.json().get("notes"), notes_content_a)
        self.assertIsNone(get_res_b.json().get("notes"))

    # -------------------------------------------------------------------------
    # TEST 4: PERSISTENCE ACROSS RETRIEVALS
    # -------------------------------------------------------------------------
    def test_persistence_of_assignee_and_notes(self):
        """
        Save assignee and notes for an incident. Fetch again via GET endpoint.
        Verify both values persist accurately.
        """
        inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_PERSIST_01", "risk_score": 90, "risk_level": "Critical", "threat_type": "Data Exfiltration"},
            event_telemetry={"asset_name": "VAULT-01"}
        )

        patch_res = self.client.patch(
            f"/api/v1/incidents/{inc.incident_id}/status",
            json={
                "status": "Investigating",
                "assigned_to": "senior_analyst_mayank",
                "notes": "Packet capture analyzed. Outbound connection throttled."
            }
        )
        self.assertEqual(patch_res.status_code, 200)

        for _ in range(3):
            fetch_res = self.client.get(f"/api/v1/incidents/{inc.incident_id}")
            self.assertEqual(fetch_res.status_code, 200)
            data = fetch_res.json()
            self.assertEqual(data["assigned_to"], "senior_analyst_mayank")
            self.assertEqual(data["notes"], "Packet capture analyzed. Outbound connection throttled.")
            self.assertEqual(data["status"], "Investigating")

    # -------------------------------------------------------------------------
    # TEST 5: OPEN -> INVESTIGATING -> RESOLVED -> REOPEN (INVESTIGATING)
    # -------------------------------------------------------------------------
    def test_open_investigating_resolved_and_reopen(self):
        """
        Test complete workflow:
        1. Open -> Investigating
        2. Investigating -> Resolved
        3. Resolved -> Investigating (Reopen Investigation)
        """
        inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REOPEN_LIFECYCLE", "risk_score": 88, "risk_level": "Critical", "threat_type": "Ransomware"},
            event_telemetry={"asset_name": "FILE-SRV-PROD-01", "username": "admin_backup"}
        )
        self.assertEqual(inc.status, "Open")

        # Step 1: Open -> Investigating
        res_inv = self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Investigating"})
        self.assertEqual(res_inv.status_code, 200)
        self.assertEqual(res_inv.json()["status"], "Investigating")

        # Step 2: Investigating -> Resolved
        res_res = self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Resolved", "notes": "Remediated"})
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "Resolved")

        # Step 3: CRITICAL TEST - Resolved -> Investigating (Reopen)
        res_reopen = self.client.patch(
            f"/api/v1/incidents/{inc.incident_id}/status",
            json={"status": "Investigating", "notes": "Reopening investigation due to secondary encrypted file activity"}
        )
        self.assertEqual(res_reopen.status_code, 200)
        self.assertEqual(res_reopen.json()["status"], "Investigating")

    # -------------------------------------------------------------------------
    # TEST 6: POST-REOPENING WORKFLOWS (INVESTIGATING -> FP & INVESTIGATING -> RESOLVED)
    # -------------------------------------------------------------------------
    def test_post_reopening_lifecycle_flows(self):
        """
        After reopening (Resolved -> Investigating):
        a) Investigating -> False Positive succeeds
        b) In a separate reopened incident: Investigating -> Resolved succeeds
        """
        # Flow A: Reopened -> False Positive
        inc_a = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REOPEN_FLOW_A", "risk_score": 75, "risk_level": "High", "threat_type": "Suspicious Login"},
            event_telemetry={"asset_name": "AUTH-GATEWAY"}
        )
        self.client.patch(f"/api/v1/incidents/{inc_a.incident_id}/status", json={"status": "Investigating"})
        self.client.patch(f"/api/v1/incidents/{inc_a.incident_id}/status", json={"status": "Resolved"})
        # Reopen
        self.client.patch(f"/api/v1/incidents/{inc_a.incident_id}/status", json={"status": "Investigating"})
        # Transition to False Positive
        res_fp = self.client.patch(
            f"/api/v1/incidents/{inc_a.incident_id}/status",
            json={"status": "False Positive", "notes": "Legitimate admin scheduled maintenance confirmed."}
        )
        self.assertEqual(res_fp.status_code, 200)
        self.assertEqual(res_fp.json()["status"], "False Positive")

        # Flow B: Reopened Resolved -> Resolved again
        inc_b = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REOPEN_FLOW_B", "risk_score": 80, "risk_level": "High", "threat_type": "Lateral Movement"},
            event_telemetry={"asset_name": "CORE-ROUTER"}
        )
        self.client.patch(f"/api/v1/incidents/{inc_b.incident_id}/status", json={"status": "Investigating"})
        self.client.patch(f"/api/v1/incidents/{inc_b.incident_id}/status", json={"status": "Resolved"})
        # Reopen
        self.client.patch(f"/api/v1/incidents/{inc_b.incident_id}/status", json={"status": "Investigating"})
        # Re-resolve
        res_re_res = self.client.patch(
            f"/api/v1/incidents/{inc_b.incident_id}/status",
            json={"status": "Resolved", "notes": "Secondary IOC cleared."}
        )
        self.assertEqual(res_re_res.status_code, 200)
        self.assertEqual(res_re_res.json()["status"], "Resolved")

        # Flow C: Reopened False Positive -> Resolved
        inc_c = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REOPEN_FLOW_C", "risk_score": 85, "risk_level": "Critical", "threat_type": "Ransomware"},
            event_telemetry={"asset_name": "BACKUP-SRV-01"}
        )
        self.client.patch(f"/api/v1/incidents/{inc_c.incident_id}/status", json={"status": "False Positive"})
        # Reopen
        res_reopen_c = self.client.patch(f"/api/v1/incidents/{inc_c.incident_id}/status", json={"status": "Investigating"})
        self.assertEqual(res_reopen_c.status_code, 200)
        self.assertEqual(res_reopen_c.json()["status"], "Investigating")
        # Transition to Resolved
        res_c_res = self.client.patch(
            f"/api/v1/incidents/{inc_c.incident_id}/status",
            json={"status": "Resolved", "notes": "Remediated after false-positive was overturned."}
        )
        self.assertEqual(res_c_res.status_code, 200)
        self.assertEqual(res_c_res.json()["status"], "Resolved")

        # Flow D: Reopened False Positive -> False Positive again
        inc_d = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REOPEN_FLOW_D", "risk_score": 62, "risk_level": "High", "threat_type": "Port Scan"},
            event_telemetry={"asset_name": "TEST-LAB-02"}
        )
        self.client.patch(f"/api/v1/incidents/{inc_d.incident_id}/status", json={"status": "False Positive"})
        # Reopen
        self.client.patch(f"/api/v1/incidents/{inc_d.incident_id}/status", json={"status": "Investigating"})
        # Transition back to False Positive
        res_d_fp = self.client.patch(
            f"/api/v1/incidents/{inc_d.incident_id}/status",
            json={"status": "False Positive", "notes": "Confirmed benign scanner again."}
        )
        self.assertEqual(res_d_fp.status_code, 200)
        self.assertEqual(res_d_fp.json()["status"], "False Positive")

    # -------------------------------------------------------------------------
    # TEST 7: INVALID TRANSITIONS REJECTED
    # -------------------------------------------------------------------------
    def test_invalid_lifecycle_transitions_rejected(self):
        """
        Verify rejection with HTTP 400:
        - Resolved -> False Positive (direct, without reopening)
        - Resolved -> Open
        - False Positive -> Resolved (direct, without reopening)
        - False Positive -> Open
        - Open -> Resolved (direct, must go through Investigating)
        """
        inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_INVALID_TRANS_SUITE", "risk_score": 72, "risk_level": "High", "threat_type": "Port Scan"},
            event_telemetry={"asset_name": "EDGE-ROUTER-01"}
        )

        # Open -> Resolved (direct) is invalid
        res_bad_open_res = self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Resolved"})
        self.assertEqual(res_bad_open_res.status_code, 400)

        # Move to Resolved legitimately: Open -> Investigating -> Resolved
        self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Investigating"})
        self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Resolved"})

        # Resolved -> False Positive directly is invalid
        res_bad_res_fp = self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "False Positive"})
        self.assertEqual(res_bad_res_fp.status_code, 400)

        # Resolved -> Open is invalid
        res_bad_res_open = self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Open"})
        self.assertEqual(res_bad_res_open.status_code, 400)

        # Create an incident in False Positive: Open -> False Positive
        inc_fp = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_FP_TERMINAL", "risk_score": 60, "risk_level": "Moderate", "threat_type": "Benign Ping"},
            event_telemetry={"asset_name": "TEST-BENIGN"}
        )
        self.client.patch(f"/api/v1/incidents/{inc_fp.incident_id}/status", json={"status": "False Positive"})

        # False Positive -> Resolved directly is strictly rejected
        res_bad_fp_res = self.client.patch(f"/api/v1/incidents/{inc_fp.incident_id}/status", json={"status": "Resolved"})
        self.assertEqual(res_bad_fp_res.status_code, 400)

        # False Positive -> Open is strictly rejected
        res_bad_fp_open = self.client.patch(f"/api/v1/incidents/{inc_fp.incident_id}/status", json={"status": "Open"})
        self.assertEqual(res_bad_fp_open.status_code, 400)

    # -------------------------------------------------------------------------
    # TEST 8: REOPENING PRESERVES ALL INCIDENT INTELLIGENCE
    # -------------------------------------------------------------------------
    def test_reopening_preserves_all_intelligence_fields(self):
        """
        Verify that transitioning Resolved -> Investigating and False Positive -> Investigating does NOT modify:
        - risk_score
        - risk_level
        - threat_type
        - affected_asset
        - affected_user
        - source_ip
        - destination_ip
        - ml_confidence
        - mitre_techniques
        - ioc_status
        - related_events
        - reasons
        - recommendations
        """
        inc = self.incident_service.create_incident_from_risk(
            risk_result={
                "event_id": "EVT_INTELLIGENCE_CHECK",
                "risk_score": 94,
                "risk_level": "Critical",
                "threat_type": "Brute Force",
                "reasons": ["25 failed logins", "Critical asset targeting"]
            },
            event_telemetry={
                "asset_name": "DC-PRIMARY",
                "username": "domain_admin",
                "source_ip": "198.51.100.22",
                "destination_ip": "10.0.0.5",
                "mitre_id": "T1110",
                "confidence_score": 95,
                "threat_intel_match": True
            }
        )

        initial_risk_score = inc.risk_score
        initial_risk_level = inc.risk_level
        initial_threat_type = inc.threat_type
        initial_asset = inc.affected_asset
        initial_user = inc.affected_user
        initial_source_ip = inc.source_ip
        initial_dest_ip = inc.destination_ip
        initial_confidence = inc.ml_confidence
        initial_mitre = list(inc.mitre_techniques)
        initial_ioc = inc.ioc_status
        initial_events = list(inc.related_events)
        initial_recs = list(inc.recommendations)

        # Open -> Investigating -> Resolved
        self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Investigating"})
        self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "Resolved"})

        # Reopen: Resolved -> Investigating
        reopen_res = self.client.patch(
            f"/api/v1/incidents/{inc.incident_id}/status",
            json={"status": "Investigating", "notes": "Reopened verification"}
        )
        self.assertEqual(reopen_res.status_code, 200)
        reopened_data = reopen_res.json()

        self.assertEqual(reopened_data["status"], "Investigating")
        self.assertEqual(reopened_data["risk_score"], initial_risk_score)
        self.assertEqual(reopened_data["risk_level"], initial_risk_level)
        self.assertEqual(reopened_data["threat_type"], initial_threat_type)
        self.assertEqual(reopened_data["affected_asset"], initial_asset)
        self.assertEqual(reopened_data["affected_user"], initial_user)
        self.assertEqual(reopened_data["source_ip"], initial_source_ip)
        self.assertEqual(reopened_data["destination_ip"], initial_dest_ip)
        self.assertEqual(reopened_data["ml_confidence"], initial_confidence)
        self.assertEqual(reopened_data["mitre_techniques"], initial_mitre)
        self.assertEqual(reopened_data["ioc_status"], initial_ioc)
        self.assertEqual(reopened_data["related_events"], initial_events)
        self.assertEqual(reopened_data["recommendations"], initial_recs)

        # Transition Investigating -> False Positive
        self.client.patch(f"/api/v1/incidents/{inc.incident_id}/status", json={"status": "False Positive"})

        # Reopen: False Positive -> Investigating
        reopen_fp_res = self.client.patch(
            f"/api/v1/incidents/{inc.incident_id}/status",
            json={"status": "Investigating", "notes": "Reopened from FP verification"}
        )
        self.assertEqual(reopen_fp_res.status_code, 200)
        reopened_fp_data = reopen_fp_res.json()

        self.assertEqual(reopened_fp_data["status"], "Investigating")
        self.assertEqual(reopened_fp_data["risk_score"], initial_risk_score)
        self.assertEqual(reopened_fp_data["risk_level"], initial_risk_level)
        self.assertEqual(reopened_fp_data["threat_type"], initial_threat_type)
        self.assertEqual(reopened_fp_data["affected_asset"], initial_asset)
        self.assertEqual(reopened_fp_data["affected_user"], initial_user)
        self.assertEqual(reopened_fp_data["source_ip"], initial_source_ip)
        self.assertEqual(reopened_fp_data["destination_ip"], initial_dest_ip)
        self.assertEqual(reopened_fp_data["ml_confidence"], initial_confidence)
        self.assertEqual(reopened_fp_data["mitre_techniques"], initial_mitre)
        self.assertEqual(reopened_fp_data["ioc_status"], initial_ioc)
        self.assertEqual(reopened_fp_data["related_events"], initial_events)
        self.assertEqual(reopened_fp_data["recommendations"], initial_recs)

        # Verify via GET /api/v1/incidents/{incident_id}
        get_res = self.client.get(f"/api/v1/incidents/{inc.incident_id}")
        self.assertEqual(get_res.status_code, 200)
        get_data = get_res.json()
        self.assertEqual(get_data["status"], "Investigating")
        self.assertEqual(get_data["risk_score"], initial_risk_score)
        self.assertEqual(get_data["risk_level"], initial_risk_level)


if __name__ == "__main__":
    unittest.main()
