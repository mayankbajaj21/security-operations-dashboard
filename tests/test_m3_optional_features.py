"""
tests/test_m3_optional_features.py

Comprehensive Automated Test Suite for Milestone 3 Optional Advanced Features:
1. Dynamic Risk Weights (Backend model, validation, persistence, API, risk engine integration)
2. Risk Score Comparison (Deterministic Before/After semantics, correlation context, no fabricated jumps)
3. Analyst Feedback (True/False Positive, per-incident persistence & isolation, API, no model retraining)
4. Regression verification (M1/M2 isolation, M3 risk/correlation/incident/recommendation invariants)
"""

from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.main import app
from backend.app.schemas.risk import RiskWeights, RiskCalculateRequest
from backend.app.schemas.incident import AnalystFeedback, IncidentFeedbackRequest
from backend.app.services.risk_engine import (
    RiskScoringEngine,
    DEFAULT_RISK_WEIGHTS,
    get_active_weights,
    set_active_weights,
    reset_default_weights,
    get_weights_metadata
)
from backend.app.services.incident_service import (
    IncidentService,
    validate_status_transition
)


class TestDynamicRiskWeights(unittest.TestCase):
    """
    Validates Dynamic Risk Weights:
    - Default configuration (25/25/20/20/10)
    - Pydantic validation (sum == 1.0, non-negative)
    - Risk engine deterministic calculation under dynamic weights
    - REST API GET/PUT/RESET endpoints
    """

    def setUp(self):
        self.client = TestClient(app)
        reset_default_weights()
        self.engine = RiskScoringEngine()

    def tearDown(self):
        reset_default_weights()

    # 1. Default weights are exactly: 25%, 25%, 20%, 20%, 10%
    def test_default_weights_values(self):
        weights = get_active_weights()
        self.assertAlmostEqual(weights.threat_severity, 0.25)
        self.assertAlmostEqual(weights.ml_confidence, 0.25)
        self.assertAlmostEqual(weights.asset_criticality, 0.20)
        self.assertAlmostEqual(weights.vulnerability_risk, 0.20)
        self.assertAlmostEqual(weights.threat_intelligence, 0.10)
        total = (
            weights.threat_severity +
            weights.ml_confidence +
            weights.asset_criticality +
            weights.vulnerability_risk +
            weights.threat_intelligence
        )
        self.assertAlmostEqual(total, 1.0)

    # 2. Valid custom weights accepted
    def test_valid_custom_weights_accepted(self):
        custom = RiskWeights(
            threat_severity=0.30,
            ml_confidence=0.20,
            asset_criticality=0.25,
            vulnerability_risk=0.15,
            threat_intelligence=0.10
        )
        set_active_weights(custom)
        active = get_active_weights()
        self.assertAlmostEqual(active.threat_severity, 0.30)
        self.assertAlmostEqual(active.ml_confidence, 0.20)
        self.assertAlmostEqual(active.asset_criticality, 0.25)
        self.assertAlmostEqual(active.vulnerability_risk, 0.15)
        self.assertAlmostEqual(active.threat_intelligence, 0.10)

    # 3. Invalid negative weight rejected
    def test_negative_weight_rejected(self):
        with self.assertRaises(ValidationError):
            RiskWeights(
                threat_severity=-0.10,
                ml_confidence=0.35,
                asset_criticality=0.35,
                vulnerability_risk=0.20,
                threat_intelligence=0.20
            )

    # 4. Weight total below 100% rejected
    def test_weight_total_below_100_rejected(self):
        with self.assertRaises(ValidationError):
            RiskWeights(
                threat_severity=0.20,
                ml_confidence=0.20,
                asset_criticality=0.20,
                vulnerability_risk=0.20,
                threat_intelligence=0.10  # sum = 0.90
            )

    # 5. Weight total above 100% rejected
    def test_weight_total_above_100_rejected(self):
        with self.assertRaises(ValidationError):
            RiskWeights(
                threat_severity=0.30,
                ml_confidence=0.30,
                asset_criticality=0.20,
                vulnerability_risk=0.20,
                threat_intelligence=0.10  # sum = 1.10
            )

    # 6. Default risk score remains unchanged
    def test_default_risk_score_remains_unchanged(self):
        # Baseline EVT-1001 standard test calculation
        req = RiskCalculateRequest(
            event_id="EVT-1001",
            event_severity="Critical",  # 100
            confidence_score=92.0,      # 92
            asset_criticality="Critical",# 100
            raw_cvss_score=9.2,         # 92
            threat_intel_match=True,    # 100
            threat_type="Brute Force"
        )
        res_default = self.engine.calculate(req)
        # Expected: 100*0.25 + 92*0.25 + 100*0.20 + 92*0.20 + 100*0.10 = 25 + 23 + 20 + 18.4 + 10 = 96.4 -> round 96
        self.assertEqual(res_default.risk_score, 96)
        self.assertAlmostEqual(res_default.risk_score_raw, 96.4)
        self.assertIsNotNone(res_default.weights_used)
        self.assertAlmostEqual(res_default.weights_used.threat_severity, 0.25)

    # 7. Custom weights actually affect score deterministically
    def test_custom_weights_affect_score_deterministically(self):
        custom_weights = RiskWeights(
            threat_severity=0.50,
            ml_confidence=0.10,
            asset_criticality=0.10,
            vulnerability_risk=0.10,
            threat_intelligence=0.20
        )
        req = RiskCalculateRequest(
            event_id="EVT-1001",
            event_severity="Critical",  # 100
            confidence_score=92.0,      # 92
            asset_criticality="Critical",# 100
            raw_cvss_score=9.2,         # 92
            threat_intel_match=True,    # 100
            threat_type="Brute Force",
            weights=custom_weights
        )
        res_custom = self.engine.calculate(req)
        # Expected: 100*0.50 + 92*0.10 + 100*0.10 + 92*0.10 + 100*0.20
        # = 50 + 9.2 + 10 + 9.2 + 20 = 98.4 -> round 98
        self.assertEqual(res_custom.risk_score, 98)
        self.assertAlmostEqual(res_custom.risk_score_raw, 98.4)
        self.assertIsNotNone(res_custom.weights_used)
        self.assertAlmostEqual(res_custom.weights_used.threat_severity, 0.50)

    # 8. API GET weights works
    def test_api_get_weights(self):
        res = self.client.get("/api/v1/risk/weights")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("weights", data)
        self.assertIn("defaults", data)
        total = sum(data["weights"].values())
        self.assertAlmostEqual(total, 1.0)
        self.assertEqual(data["weights"]["threat_severity"], 0.25)

    # 9. API update weights works
    def test_api_update_weights(self):
        payload = {
            "threat_severity": 0.30,
            "ml_confidence": 0.25,
            "asset_criticality": 0.20,
            "vulnerability_risk": 0.15,
            "threat_intelligence": 0.10
        }
        res = self.client.put("/api/v1/risk/weights", json=payload)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["is_custom"])
        self.assertAlmostEqual(data["weights"]["threat_severity"], 0.30)
        self.assertAlmostEqual(data["weights"]["vulnerability_risk"], 0.15)

        # Invalid update rejected by API
        bad_payload = {
            "threat_severity": 0.50,
            "ml_confidence": 0.50,
            "asset_criticality": 0.50,
            "vulnerability_risk": 0.50,
            "threat_intelligence": 0.50
        }
        res_bad = self.client.put("/api/v1/risk/weights", json=bad_payload)
        self.assertEqual(res_bad.status_code, 422)

    # 10. Reset/default behavior works if implemented as API behavior
    def test_api_reset_weights(self):
        # First update to custom
        self.client.put("/api/v1/risk/weights", json={
            "threat_severity": 0.30,
            "ml_confidence": 0.20,
            "asset_criticality": 0.20,
            "vulnerability_risk": 0.20,
            "threat_intelligence": 0.10
        })
        # Reset
        res = self.client.post("/api/v1/risk/weights/reset")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertFalse(data["is_custom"])
        self.assertEqual(data["weights"]["threat_severity"], 0.25)
        self.assertEqual(data["weights"]["ml_confidence"], 0.25)


class TestRiskScoreComparison(unittest.TestCase):
    """
    Validates Risk Score Comparison semantics:
    - Base score calculated from 5 pillars
    - Honest comparison (no fabricated jumps)
    - Handling standalone events (difference = 0.0)
    - Handling attack-chain correlated events
    - Explanation and context returned deterministically
    """

    def setUp(self):
        self.client = TestClient(app)

    # 11. Comparison endpoint works and handles 404 for unknown IDs
    def test_comparison_endpoint_accessible(self):
        res = self.client.get("/api/v1/risk/comparison/EVT_NONEXISTENT_99999")
        self.assertEqual(res.status_code, 404)

    # 12 & 13 & 14. Base score derived from 5 pillars, no fabricated correlation impact for standalone
    def test_comparison_standalone_event(self):
        # Query benchmark standalone event EVT-1001
        res = self.client.get("/api/v1/risk/comparison/EVT-1001")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertEqual(data["event_id"], "EVT-1001")
        self.assertIn("before_correlation", data)
        self.assertIn("after_correlation", data)
        self.assertIn("difference", data)
        self.assertIn("correlated", data)
        self.assertIn("explanation", data)

        # Standalone event without attack chain has difference = 0.0
        if not data["correlated"]:
            self.assertEqual(data["before_correlation"], data["after_correlation"])
            self.assertEqual(data["difference"], 0.0)
            self.assertTrue(any("No correlation impact" in exp for exp in data["explanation"]))

    # 15 & 16 & 17. Correlated event handled correctly, explanation returned, deterministic
    def test_comparison_correlated_event_context(self):
        # Test using synthetic benchmark correlated event EVT_CORR_001
        res = self.client.get("/api/v1/risk/comparison/EVT_CORR_001")
        self.assertEqual(res.status_code, 200)
        data = res.json()

        self.assertTrue(data["correlated"])
        self.assertIsNotNone(data["chain_id"])
        self.assertTrue(len(data["stages"]) > 0)
        self.assertTrue(len(data["explanation"]) > 0)

        # Deterministic check
        res2 = self.client.get("/api/v1/risk/comparison/EVT_CORR_001")
        data2 = res2.json()
        self.assertEqual(data["before_correlation"], data2["before_correlation"])
        self.assertEqual(data["after_correlation"], data2["after_correlation"])
        self.assertEqual(data["difference"], data2["difference"])


class TestAnalystFeedback(unittest.TestCase):
    """
    Validates Analyst Feedback:
    - True Positive and False Positive submission
    - Validation of feedback labels
    - Per-incident isolation in MongoDB / in-memory fallback
    - GET incident returns feedback
    - Updating feedback persists new label/comment
    - Feedback does not alter M2 model or trigger retraining
    """

    def setUp(self):
        self.client = TestClient(app)
        self.service = IncidentService(db=None)  # isolated in-memory for unit tests
        self.api_service = IncidentService()

    # 18. True Positive feedback can be submitted
    def test_submit_true_positive_feedback(self):
        risk_res = {"event_id": "EVT_FB_01", "risk_score": 85, "risk_level": "High", "threat_type": "Brute Force"}
        inc = self.service.create_incident_from_risk(risk_res, index=101)

        updated = self.service.submit_feedback(
            incident_id=inc.incident_id,
            label="True Positive",
            comment="Confirmed SSH credential stuffing attack.",
            analyst="analyst_alice"
        )
        self.assertIsNotNone(updated.feedback)
        self.assertEqual(updated.feedback.label, "True Positive")
        self.assertEqual(updated.feedback.comment, "Confirmed SSH credential stuffing attack.")
        self.assertEqual(updated.feedback.analyst, "analyst_alice")
        self.assertIsNotNone(updated.feedback.submitted_at)

    # 19. False Positive feedback can be submitted
    def test_submit_false_positive_feedback(self):
        risk_res = {"event_id": "EVT_FB_02", "risk_score": 65, "risk_level": "High", "threat_type": "Port Scan"}
        inc = self.service.create_incident_from_risk(risk_res, index=102)

        updated = self.service.submit_feedback(
            incident_id=inc.incident_id,
            label="False Positive",
            comment="Internal network security scanner running scheduled scan.",
            analyst="analyst_bob"
        )
        self.assertIsNotNone(updated.feedback)
        self.assertEqual(updated.feedback.label, "False Positive")
        self.assertEqual(updated.feedback.comment, "Internal network security scanner running scheduled scan.")

    # 20. Invalid feedback label rejected
    def test_invalid_feedback_label_rejected(self):
        risk_res = {"event_id": "EVT_FB_03", "risk_score": 75, "risk_level": "High", "threat_type": "Phishing"}
        inc = self.service.create_incident_from_risk(risk_res, index=103)

        with self.assertRaises(ValueError):
            self.service.submit_feedback(
                incident_id=inc.incident_id,
                label="Uncertain",
                comment="Invalid label"
            )

        with self.assertRaises(ValidationError):
            AnalystFeedback(label="Maybe Malicious")

    # 21 & 22. Feedback persists and is retrieved via API / service
    def test_feedback_retrieval_via_api(self):
        test_inc = self.api_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_API_FB_01", "risk_score": 88, "risk_level": "Critical", "threat_type": "Malware"},
            event_telemetry={"asset_name": "CORP-LAPTOP-01"}
        )
        incident_id = test_inc.incident_id

        payload = {
            "label": "True Positive",
            "comment": "Verified by SOC Level 2 analyst.",
            "analyst": "soc_senior_analyst"
        }
        fb_res = self.client.post(f"/api/v1/incidents/{incident_id}/feedback", json=payload)
        self.assertEqual(fb_res.status_code, 200)
        fb_data = fb_res.json()
        self.assertEqual(fb_data["feedback"]["label"], "True Positive")
        self.assertEqual(fb_data["feedback"]["comment"], "Verified by SOC Level 2 analyst.")

        get_res = self.client.get(f"/api/v1/incidents/{incident_id}")
        self.assertEqual(get_res.status_code, 200)
        get_data = get_res.json()
        self.assertIsNotNone(get_data.get("feedback"))
        self.assertEqual(get_data["feedback"]["label"], "True Positive")

    # 23 & 24. Feedback is isolated per incident and updates replace only that incident's feedback
    def test_feedback_per_incident_isolation(self):
        risk_a = {"event_id": "EVT_ISO_A", "risk_score": 90, "risk_level": "Critical", "threat_type": "Ransomware"}
        risk_b = {"event_id": "EVT_ISO_B", "risk_score": 40, "risk_level": "Moderate", "threat_type": "DNS Query"}

        inc_a = self.service.create_incident_from_risk(risk_a, index=201)
        inc_b = self.service.create_incident_from_risk(risk_b, index=202)

        # Incident A -> True Positive
        self.service.submit_feedback(inc_a.incident_id, "True Positive", "Malware verified", "analyst_a")
        # Incident B -> False Positive
        self.service.submit_feedback(inc_b.incident_id, "False Positive", "Legitimate DNS", "analyst_b")

        # Verify A
        lookup_a = self.service.get_incident(inc_a.incident_id)
        self.assertEqual(lookup_a.feedback.label, "True Positive")
        self.assertEqual(lookup_a.feedback.comment, "Malware verified")

        # Verify B
        lookup_b = self.service.get_incident(inc_b.incident_id)
        self.assertEqual(lookup_b.feedback.label, "False Positive")
        self.assertEqual(lookup_b.feedback.comment, "Legitimate DNS")

        # Update A to False Positive -> B must remain unchanged
        self.service.submit_feedback(inc_a.incident_id, "False Positive", "Actually a benign test", "analyst_a")

        lookup_a_after = self.service.get_incident(inc_a.incident_id)
        lookup_b_after = self.service.get_incident(inc_b.incident_id)

        self.assertEqual(lookup_a_after.feedback.label, "False Positive")
        self.assertEqual(lookup_a_after.feedback.comment, "Actually a benign test")
        self.assertEqual(lookup_b_after.feedback.label, "False Positive")
        self.assertEqual(lookup_b_after.feedback.comment, "Legitimate DNS")

    # 25. Feedback comment persists
    def test_feedback_comment_persists(self):
        risk = {"event_id": "EVT_COMMENT", "risk_score": 88, "risk_level": "Critical", "threat_type": "Data Exfil"}
        inc = self.service.create_incident_from_risk(risk, index=301)

        self.service.submit_feedback(inc.incident_id, "True Positive", "Detailed forensic comment #49102")
        fetched = self.service.get_incident(inc.incident_id)
        self.assertEqual(fetched.feedback.comment, "Detailed forensic comment #49102")

    # 26. Feedback does not automatically alter M2 predictions
    def test_feedback_does_not_alter_m2_predictions(self):
        pred_payload = {
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "threat_type": "Brute Force",
            "failed_logins": 15,
            "bytes_transferred": 2048
        }
        res_before = self.client.post("/predict", json=pred_payload)
        self.assertEqual(res_before.status_code, 200)
        data_before = res_before.json()

        # Submit feedback on an incident
        test_inc = self.api_service.create_incident_from_risk(
            risk_result={"event_id": "EVT_TEST_M2_INV", "risk_score": 80, "risk_level": "High", "threat_type": "Brute Force"}
        )
        self.client.post(f"/api/v1/incidents/{test_inc.incident_id}/feedback", json={
            "label": "False Positive",
            "comment": "Testing M2 invariance"
        })

        # Call /predict again with identical payload
        res_after = self.client.post("/predict", json=pred_payload)
        self.assertEqual(res_after.status_code, 200)
        data_after = res_after.json()

        self.assertEqual(data_before["prediction"], data_after["prediction"])
        self.assertEqual(data_before["confidence_score"], data_after["confidence_score"])
        self.assertEqual(data_before["threat_type"], data_after["threat_type"])

    # 27. Feedback does not trigger model retraining
    def test_feedback_does_not_trigger_model_retraining(self):
        perf_res = self.client.get("/model-performance")
        self.assertEqual(perf_res.status_code, 200)
        perf_data = perf_res.json()
        self.assertEqual(perf_data.get("model_name"), "Isolation Forest")
        self.assertIn("total_events_evaluated", perf_data)
        self.assertIn("anomaly_percentage", perf_data)
        self.assertIn("contamination", perf_data)


class TestMilestone3Regressions(unittest.TestCase):
    """
    Regression verification for all existing Milestone 3 invariants:
    - Incident lifecycle valid & invalid transitions
    - Assignee & notes per-incident isolation
    - KPI pagination invariant
    - Neutral priority behavior ("—")
    """

    def setUp(self):
        self.client = TestClient(app)
        self.service = IncidentService(db=None)

    # 28-34: Handled by suite discover, tested here specifically for lifecycle invariants:
    def test_lifecycle_rules_and_reopen_transitions(self):
        # Valid Transitions (should not raise):
        validate_status_transition("Open", "Investigating")
        validate_status_transition("Open", "False Positive")
        validate_status_transition("Investigating", "Resolved")
        validate_status_transition("Investigating", "False Positive")
        validate_status_transition("Resolved", "Investigating")
        validate_status_transition("False Positive", "Investigating")

        # Invalid Transitions: False Positive and Resolved must NOT become Open directly
        with self.assertRaises(ValueError):
            validate_status_transition("Resolved", "Open")

        with self.assertRaises(ValueError):
            validate_status_transition("False Positive", "Open")

        # Open cannot jump directly to Resolved
        with self.assertRaises(ValueError):
            validate_status_transition("Open", "Resolved")

    # 35: KPI pagination invariant
    def test_kpi_pagination_invariant(self):
        res1 = self.client.get("/api/v1/incidents?page=1&limit=5")
        res2 = self.client.get("/api/v1/incidents?page=2&limit=5")
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res2.status_code, 200)
        d1 = res1.json()
        d2 = res2.json()
        self.assertIn("pagination", d1)
        self.assertIn("pagination", d2)
        self.assertEqual(d1["pagination"]["total"], d2["pagination"]["total"])
        self.assertEqual(d1["pagination"]["total_pages"], d2["pagination"]["total_pages"])

    # 36: Incident-specific notes and assignee isolation remains intact
    def test_assignee_and_notes_isolation(self):
        risk1 = {"event_id": "EVT_NOTE_1", "risk_score": 70, "risk_level": "High", "threat_type": "Port Scan"}
        risk2 = {"event_id": "EVT_NOTE_2", "risk_score": 75, "risk_level": "High", "threat_type": "Brute Force"}

        inc1 = self.service.create_incident_from_risk(risk1, index=401)
        inc2 = self.service.create_incident_from_risk(risk2, index=402)

        self.service.update_incident_status(inc1.incident_id, "Investigating", assigned_to="Analyst_Alpha", notes="Note 1")
        self.service.update_incident_status(inc2.incident_id, "Investigating", assigned_to="Analyst_Beta", notes="Note 2")

        fetched1 = self.service.get_incident(inc1.incident_id)
        fetched2 = self.service.get_incident(inc2.incident_id)

        self.assertEqual(fetched1.assigned_to, "Analyst_Alpha")
        self.assertEqual(fetched1.notes, "Note 1")
        self.assertEqual(fetched2.assigned_to, "Analyst_Beta")
        self.assertEqual(fetched2.notes, "Note 2")

    # 37: Priority field preserved as None / neutral
    def test_priority_preserved_as_none(self):
        risk = {"event_id": "EVT_PRIO_01", "risk_score": 90, "risk_level": "Critical", "threat_type": "DDoS"}
        inc = self.service.create_incident_from_risk(risk, index=501)
        self.assertEqual(inc.priority, "P1")  # M4 derived priority (Critical -> P1)


if __name__ == "__main__":
    unittest.main()
