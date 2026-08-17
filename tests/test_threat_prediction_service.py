"""
tests/test_threat_prediction_service.py

Unit and Integration Test Suite for ThreatPredictionService & MongoDB Storage Layer.
"""

from datetime import datetime
from pathlib import Path
import sys
import unittest
import pandas as pd

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.core.database import check_database_connection
from backend.app.services.threat_prediction_service import ThreatPredictionService, MODEL_VERSION


class TestThreatPredictionService(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        is_healthy, _ = check_database_connection()
        if not is_healthy:
            raise unittest.SkipTest("MongoDB instance is not reachable.")
        cls.service = ThreatPredictionService()

    def test_document_transformation(self):
        sample_raw = {
            "event_id": "EVT99999",
            "prediction": "Suspicious",
            "anomaly_score": "0.054321",
            "threat_type": "Brute Force",
            "threat_level": "Critical Threat",
            "confidence_score": "88.4",
            "reasons": '["15 failed login attempts", "Isolation Forest ML anomaly"]'
        }
        formatted = self.service.format_prediction_document(sample_raw)
        
        self.assertEqual(formatted["event_id"], "EVT99999")
        self.assertEqual(formatted["prediction"], "Suspicious")
        self.assertAlmostEqual(formatted["anomaly_score"], 0.054321)
        self.assertEqual(formatted["threat_type"], "Brute Force")
        self.assertEqual(formatted["threat_level"], "Critical Threat")
        self.assertEqual(formatted["confidence_score"], 88)
        self.assertIsInstance(formatted["reasons"], list)
        self.assertEqual(len(formatted["reasons"]), 2)
        self.assertEqual(formatted["model_version"], MODEL_VERSION)
        self.assertIsInstance(formatted["created_at"], datetime)

    def test_score_bounds_validation(self):
        sample_low = {"event_id": "EVT_LOW", "confidence_score": -50}
        formatted_low = self.service.format_prediction_document(sample_low)
        self.assertEqual(formatted_low["confidence_score"], 0)

        sample_high = {"event_id": "EVT_HIGH", "confidence_score": 150}
        formatted_high = self.service.format_prediction_document(sample_high)
        self.assertEqual(formatted_high["confidence_score"], 100)

    def test_missing_event_id_raises_value_error(self):
        sample_invalid = {"prediction": "Normal"}
        with self.assertRaises(ValueError):
            self.service.format_prediction_document(sample_invalid)

    def test_mongodb_document_count_and_integrity(self):
        ref_stats = self.service.validate_referential_integrity()
        
        self.assertTrue(ref_stats["is_valid"])
        self.assertEqual(ref_stats["prediction_count"], 1800)
        self.assertEqual(ref_stats["security_events_count"], 1800)
        self.assertEqual(ref_stats["matching_count"], 1800)
        self.assertEqual(ref_stats["orphan_predictions"], 0)
        self.assertEqual(ref_stats["duplicate_predictions"], 0)

    def test_representative_events_retrieval(self):
        representative_ids = ['EVT00034', 'EVT00036', 'EVT00144', 'EVT01233', 'EVT01600']
        for eid in representative_ids:
            doc = self.service.get_prediction_by_event_id(eid)
            self.assertIsNotNone(doc, f"Document for {eid} should exist in MongoDB")
            self.assertEqual(doc["event_id"], eid)
            self.assertIn(doc["prediction"], ["Normal", "Suspicious"])
            self.assertIn(doc["threat_level"], ["Normal", "Low Threat", "Medium Threat", "High Threat", "Critical Threat"])
            self.assertTrue(0 <= doc["confidence_score"] <= 100)
            self.assertIsInstance(doc["reasons"], list)

    def test_query_methods(self):
        suspicious_list = self.service.get_suspicious_predictions(limit=10)
        self.assertLessEqual(len(suspicious_list), 10)
        for item in suspicious_list:
            self.assertEqual(item["prediction"], "Suspicious")

        critical_list = self.service.get_predictions_by_threat_level("Critical Threat", limit=10)
        self.assertLessEqual(len(critical_list), 10)
        for item in critical_list:
            self.assertEqual(item["threat_level"], "Critical Threat")

        brute_force_list = self.service.get_predictions_by_threat_type("Brute Force", limit=10)
        self.assertLessEqual(len(brute_force_list), 10)
        for item in brute_force_list:
            self.assertEqual(item["threat_type"], "Brute Force")


if __name__ == "__main__":
    unittest.main()
