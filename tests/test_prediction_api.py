"""
tests/test_prediction_api.py

Milestone 2 — Step 8: Prediction APIs Test Suite

Tests all six Step 8 prediction REST endpoints, live model inference execution,
MongoDB data retrieval, error handling for unknown event IDs, and M1 endpoint regression.
"""

import sys
from pathlib import Path
import unittest
from fastapi.testclient import TestClient

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.main import app

client = TestClient(app)


class TestPredictionAPI(unittest.TestCase):

    def test_01_post_predict_live_inference_success(self):
        """1. Test POST /predict returns HTTP 200 and executes live model inference."""
        payload = {
            "event_id": "EVT_TEST_001",
            "event_type": "Brute Force",
            "failed_login_attempts": 18,
            "raw_cvss_score": 8.9,
            "malware_detected": "No",
            "event_severity": "Critical",
            "protocol": "SSH",
            "event_status": "Failed",
            "username": "root"
        }
        response = client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["event_id"], "EVT_TEST_001")
        self.assertIn(data["prediction"], ["Normal", "Suspicious"])
        self.assertIsInstance(data["anomaly_score"], float)
        self.assertIsInstance(data["confidence_score"], int)
        self.assertTrue(0 <= data["confidence_score"] <= 100)
        self.assertIn(data["threat_level"], ["Normal", "Low Threat", "Medium Threat", "High Threat", "Critical Threat"])
        self.assertIsInstance(data["reasons"], list)

    def test_02_post_predict_required_fields(self):
        """2. Test POST /predict response contains all required M2 output fields."""
        payload = {"event_type": "Failed Login", "failed_login_attempts": 1}
        response = client.post("/predict", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        required_keys = [
            "event_id", "prediction", "anomaly_score", "threat_type",
            "threat_level", "confidence_score", "reasons", "model_version"
        ]
        for key in required_keys:
            self.assertIn(key, data)

    def test_03_get_predictions_list(self):
        """3. Test GET /predictions returns paginated MongoDB stored prediction documents."""
        response = client.get("/predictions?page=1&limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("data", data)
        self.assertIn("pagination", data)
        self.assertGreaterEqual(len(data["data"]), 1)
        first_doc = data["data"][0]
        self.assertIn("event_id", first_doc)
        self.assertIn("prediction", first_doc)
        self.assertIn("confidence_score", first_doc)

    def test_04_get_prediction_by_valid_event_id(self):
        """4. Test GET /predictions/{event_id} works for representative event EVT00034."""
        response = client.get("/predictions/EVT00034")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["event_id"], "EVT00034")
        self.assertIn("prediction", data)
        self.assertIn("event_details", data)
        self.assertIsNotNone(data["event_details"])
        self.assertEqual(data["event_details"]["event_id"], "EVT00034")

    def test_05_get_prediction_by_invalid_event_id_returns_404(self):
        """5. Test GET /predictions/{event_id} returns HTTP 404 for unknown event_id."""
        response = client.get("/predictions/EVT99999_NONEXISTENT")
        self.assertEqual(response.status_code, 404)
        data = response.json()
        self.assertIn("detail", data)

    def test_06_get_anomalies_filtered_suspicious(self):
        """6. Test GET /anomalies returns only predictions where prediction == 'Suspicious'."""
        response = client.get("/anomalies?limit=20")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("data", data)
        self.assertGreaterEqual(len(data["data"]), 1)
        for item in data["data"]:
            self.assertEqual(item["prediction"], "Suspicious")

    def test_07_get_model_performance_diagnostics(self):
        """7. Test GET /model-performance returns verified M2 evaluation metrics."""
        response = client.get("/model-performance")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["model_name"], "Isolation Forest")
        self.assertEqual(data["model_version"], "isolation_forest_v1")
        self.assertEqual(data["total_events_evaluated"], 1800)
        self.assertEqual(data["normal_count"], 1710)
        self.assertEqual(data["suspicious_count"], 90)
        self.assertEqual(data["anomaly_percentage"], 5.0)
        self.assertEqual(data["feature_count"], 29)
        self.assertEqual(data["contamination"], 0.05)
        self.assertIn("score_distribution", data)

    def test_08_get_threat_summary_database_derived(self):
        """8. Test GET /threat-summary returns database-derived aggregation metrics."""
        response = client.get("/threat-summary")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["total_events"], 1800)
        self.assertEqual(data["anomalies_detected"], 90)
        self.assertEqual(data["normal_events"], 1710)
        self.assertIn("threat_levels", data)
        self.assertIn("threat_types", data)
        self.assertGreater(data["average_confidence_score"], 0)

    def test_09_existing_m1_endpoints_regression(self):
        """9. Test existing Milestone 1 REST endpoints remain operational."""
        health_resp = client.get("/health")
        self.assertEqual(health_resp.status_code, 200)
        
        events_resp = client.get("/events?limit=5")
        self.assertEqual(events_resp.status_code, 200)

        metrics_resp = client.get("/metrics")
        self.assertEqual(metrics_resp.status_code, 200)

    def test_10_openapi_routes_registered(self):
        """10. Test OpenAPI schema includes all six Step 8 prediction endpoints."""
        response = client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        paths = schema.get("paths", {})
        
        required_endpoints = [
            "/predict",
            "/predictions",
            "/predictions/{event_id}",
            "/anomalies",
            "/model-performance",
            "/threat-summary"
        ]
        for ep in required_endpoints:
            self.assertIn(ep, paths, f"Endpoint '{ep}' missing from OpenAPI schema!")


if __name__ == "__main__":
    unittest.main()
