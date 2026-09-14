"""
tests/test_m3_api.py

Milestone 3 — Step 5: REST API Integration Test Suite

Tests all M3 REST API endpoints exposed via FastAPI:
1. POST  /api/v1/risk/calculate (Live risk calculation)
2. GET   /api/v1/risk/high (High-risk events list)
3. GET   /api/v1/risk/summary (Risk distribution & factor KPIs)
4. GET   /api/v1/incidents (Paginated incident feed with filters)
5. GET   /api/v1/incidents/{incident_id} (Single incident lookup)
6. PATCH /api/v1/incidents/{incident_id}/status (Lifecycle status transitions)
7. GET   /api/v1/recommendations/{incident_id} (Prescriptive analyst guidance)
8. GET   /api/v1/attack-chains (Correlated attack chains)
9. Regression verification for M1/M2 API endpoints (/health, /events, /metrics, /predictions)
"""

from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.main import app
from backend.app.services.incident_service import IncidentService


class TestMilestone3APIs(unittest.TestCase):
    """
    Automated integration tests for Milestone 3 FastAPI REST routes.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.incident_service = IncidentService()

    # -------------------------------------------------------------------------
    # 1. POST /api/v1/risk/calculate
    # -------------------------------------------------------------------------
    def test_post_risk_calculate_valid_response(self):
        payload = {
            "event_id": "EVT_TEST_API_001",
            "event_severity": "Critical",
            "confidence_score": 92,
            "asset_criticality": "Critical",
            "cvss_score": 9.2,
            "threat_intel_match": True,
            "threat_type": "Brute Force"
        }
        res = self.client.post("/api/v1/risk/calculate", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["event_id"], "EVT_TEST_API_001")
        self.assertEqual(data["risk_score"], 96)
        self.assertEqual(data["risk_score_raw"], 96.4)
        self.assertEqual(data["risk_level"], "Critical")
        self.assertEqual(data["threat_type"], "Brute Force")
        self.assertIn("breakdown", data)
        self.assertEqual(data["breakdown"]["threat_severity"]["normalized"], 100.0)
        self.assertEqual(data["breakdown"]["ml_confidence"]["normalized"], 92.0)
        self.assertEqual(data["breakdown"]["asset_criticality"]["normalized"], 100.0)
        self.assertEqual(data["breakdown"]["vulnerability_risk"]["normalized"], 92.0)
        self.assertEqual(data["breakdown"]["threat_intelligence"]["normalized"], 100.0)
        self.assertIsInstance(data["reasons"], list)

    def test_post_risk_calculate_validation_error(self):
        # Invalid cvss_score > 10.0
        payload = {
            "cvss_score": 25.0
        }
        res = self.client.post("/api/v1/risk/calculate", json=payload)
        self.assertEqual(res.status_code, 422)

    # -------------------------------------------------------------------------
    # 2. GET /api/v1/risk/high
    # -------------------------------------------------------------------------
    def test_get_risk_high_endpoint(self):
        res = self.client.get("/api/v1/risk/high?page=1&limit=10&min_risk=61")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("data", data)
        self.assertIn("pagination", data)
        self.assertEqual(data["pagination"]["page"], 1)
        self.assertEqual(data["pagination"]["limit"], 10)

        for item in data["data"]:
            self.assertGreaterEqual(item["risk_score"], 61)
            self.assertIn(item["risk_level"], ["High", "Critical"])

    # -------------------------------------------------------------------------
    # 3. GET /api/v1/risk/summary
    # -------------------------------------------------------------------------
    def test_get_risk_summary_endpoint(self):
        res = self.client.get("/api/v1/risk/summary")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("total_evaluated_events", data)
        self.assertIn("average_risk_score", data)
        self.assertIn("risk_distribution", data)
        self.assertIn("top_risk_factors", data)

        dist = data["risk_distribution"]
        self.assertIn("Low", dist)
        self.assertIn("Medium", dist)
        self.assertIn("Moderate", dist)
        self.assertIn("High", dist)
        self.assertIn("Critical", dist)

    # -------------------------------------------------------------------------
    # 4. GET /api/v1/incidents
    # -------------------------------------------------------------------------
    def test_get_incidents_list(self):
        res = self.client.get("/api/v1/incidents?page=1&limit=20")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("data", data)
        self.assertIn("pagination", data)
        self.assertEqual(data["pagination"]["page"], 1)

    # -------------------------------------------------------------------------
    # 5. GET /api/v1/incidents/{incident_id}
    # -------------------------------------------------------------------------
    def test_get_incident_by_id_and_404(self):
        # Create a test incident directly via service
        test_inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_API_INC_1", "risk_score": 88, "risk_level": "Critical", "threat_type": "Malware"},
            event_telemetry={"asset_name": "FINANCE-PC-01", "username": "finance_lead"}
        )

        res_found = self.client.get(f"/api/v1/incidents/{test_inc.incident_id}")
        self.assertEqual(res_found.status_code, 200)
        data = res_found.json()
        self.assertEqual(data["incident_id"], test_inc.incident_id)
        self.assertEqual(data["risk_score"], 88)
        self.assertEqual(data["risk_level"], "Critical")
        self.assertIsNone(data["priority"])  # Preserved as None

        # 404 test for nonexistent ID
        res_404 = self.client.get("/api/v1/incidents/INC_NONEXISTENT_99999")
        self.assertEqual(res_404.status_code, 404)

    # -------------------------------------------------------------------------
    # 6. PATCH /api/v1/incidents/{incident_id}/status (Lifecycle transitions)
    # -------------------------------------------------------------------------
    def test_patch_incident_lifecycle_transitions(self):
        # 1. Create Open incident
        test_inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_LIFE_01", "risk_score": 90, "risk_level": "Critical", "threat_type": "Brute Force"},
            event_telemetry={"asset_name": "DC-PRIMARY"}
        )
        self.assertEqual(test_inc.status, "Open")

        # 2. Valid: Open -> Investigating
        res_inv = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Investigating", "assigned_to": "Mayank Bajaj", "notes": "Active investigation"}
        )
        self.assertEqual(res_inv.status_code, 200)
        self.assertEqual(res_inv.json()["status"], "Investigating")
        self.assertEqual(res_inv.json()["assigned_to"], "Mayank Bajaj")

        # 3. Valid: Investigating -> Resolved
        res_res = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Resolved", "notes": "Host isolated and credentials rotated"}
        )
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["status"], "Resolved")

        # 4. Valid Reopen: Resolved -> Investigating
        res_reopen = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Investigating", "notes": "New telemetry detected, reopening"}
        )
        self.assertEqual(res_reopen.status_code, 200)
        self.assertEqual(res_reopen.json()["status"], "Investigating")

        # 5. Valid Reopened -> False Positive
        res_reopened_fp = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "False Positive", "notes": "Re-evaluated and marked as false positive"}
        )
        self.assertEqual(res_reopened_fp.status_code, 200)
        self.assertEqual(res_reopened_fp.json()["status"], "False Positive")

        # 6. Invalid: False Positive -> Resolved directly (Must reopen to Investigating first)
        res_invalid_direct = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Resolved"}
        )
        self.assertEqual(res_invalid_direct.status_code, 400)

        # 7. Invalid: False Positive -> Open directly
        res_invalid_open = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Open"}
        )
        self.assertEqual(res_invalid_open.status_code, 400)

        # 8. Valid: False Positive -> Investigating (Reopen Investigation from False Positive)
        res_reopen_fp = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Investigating", "notes": "Reopening false positive after discovering real IOC"}
        )
        self.assertEqual(res_reopen_fp.status_code, 200)
        self.assertEqual(res_reopen_fp.json()["status"], "Investigating")

        # 9. Valid: Reopened incident (Investigating) -> Resolved
        res_reopen_res = self.client.patch(
            f"/api/v1/incidents/{test_inc.incident_id}/status",
            json={"status": "Resolved", "notes": "Remediated threat"}
        )
        self.assertEqual(res_reopen_res.status_code, 200)
        self.assertEqual(res_reopen_res.json()["status"], "Resolved")

        # 10. Valid: Open -> False Positive
        test_fp = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_LIFE_FP", "risk_score": 65, "risk_level": "High", "threat_type": "Port Scan"},
            event_telemetry={"asset_name": "TEST-LAB"}
        )
        res_fp = self.client.patch(
            f"/api/v1/incidents/{test_fp.incident_id}/status",
            json={"status": "False Positive", "notes": "Authorized scan by internal pentester"}
        )
        self.assertEqual(res_fp.status_code, 200)
        self.assertEqual(res_fp.json()["status"], "False Positive")

    # -------------------------------------------------------------------------
    # 7. GET /api/v1/recommendations/{incident_id}
    # -------------------------------------------------------------------------
    def test_get_recommendations_for_incident(self):
        test_inc = self.incident_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_REC_01", "risk_score": 92, "risk_level": "Critical", "threat_type": "Data Exfiltration"},
            event_telemetry={"asset_name": "DATA-VAULT-01"}
        )

        res = self.client.get(f"/api/v1/recommendations/{test_inc.incident_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["incident_id"], test_inc.incident_id)
        self.assertEqual(data["threat_type"], "Data Exfiltration")
        self.assertIsInstance(data["recommendations"], list)
        self.assertGreaterEqual(len(data["recommendations"]), 3)
        self.assertTrue(any("Investigate destination" in r for r in data["recommendations"]))

        # 404 for missing incident
        res_404 = self.client.get("/api/v1/recommendations/INC_NONEXISTENT_REC")
        self.assertEqual(res_404.status_code, 404)

    # -------------------------------------------------------------------------
    # 8. GET /api/v1/attack-chains
    # -------------------------------------------------------------------------
    def test_get_attack_chains_endpoint(self):
        res = self.client.get("/api/v1/attack-chains?window_minutes=15")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertIn("data", data)
        self.assertIn("total", data)
        self.assertIn("metrics", data)
        self.assertIsInstance(data["data"], list)

    # -------------------------------------------------------------------------
    # 9. Regression: Existing M1 & M2 Routes Still Function
    # -------------------------------------------------------------------------
    def test_m1_and_m2_routes_regression(self):
        # M1 Routes
        res_health = self.client.get("/health")
        self.assertEqual(res_health.status_code, 200)

        res_events = self.client.get("/events?limit=5")
        self.assertEqual(res_events.status_code, 200)

        res_metrics = self.client.get("/metrics")
        self.assertEqual(res_metrics.status_code, 200)

        res_mitre = self.client.get("/mitre")
        self.assertEqual(res_mitre.status_code, 200)

        # M2 Routes
        res_pred = self.client.post("/predict", json={"event_type": "Failed Login", "failed_login_attempts": 15})
        self.assertEqual(res_pred.status_code, 200)

        res_threat_sum = self.client.get("/threat-summary")
        self.assertEqual(res_threat_sum.status_code, 200)


if __name__ == "__main__":
    unittest.main()
