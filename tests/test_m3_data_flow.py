"""
tests/test_m3_data_flow.py

Milestone 3 — End-to-End Data Flow & Schema Validation Test Suite

Validates that real M2 MongoDB data flows seamlessly through M3 Risk Scoring,
Event Correlation, Attack Chains, Incidents, and Security Intelligence APIs.
"""

import unittest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import check_database_connection


class TestM3DataFlow(unittest.TestCase):
    """
    Test suite verifying end-to-end data flow for all Milestone 3 APIs.
    """

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        cls.is_db_connected, _ = check_database_connection()

    def test_01_attack_chains_data_flow(self):
        """
        Verify GET /api/v1/attack-chains and GET /v1/attack-chains return correlated chains and non-zero metrics.
        """
        for route in ["/api/v1/attack-chains", "/v1/attack-chains"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Failed for route {route}")
            body = res.json()
            
            self.assertIn("data", body)
            self.assertIn("total", body)
            self.assertIn("metrics", body)

            if self.is_db_connected:
                metrics = body["metrics"]
                self.assertEqual(metrics["total_events_analyzed"], 1800)
                self.assertGreater(metrics["suspicious_events_count"], 0)
                self.assertGreater(metrics["attack_chains_count"], 0)
                self.assertEqual(body["total"], metrics["attack_chains_count"])

                # Validate schema of first chain
                chains = body["data"]
                self.assertGreater(len(chains), 0)
                chain = chains[0]
                self.assertIn("attack_chain_id", chain)
                self.assertIn("events", chain)
                self.assertIn("related_events", chain)
                self.assertIn("techniques", chain)
                self.assertIn("stages", chain)
                self.assertIn("stage", chain)
                self.assertIn("risk_score", chain)
                self.assertIn("confidence", chain)
                self.assertIn("affected_asset", chain)
                self.assertIn("target_user", chain)
                self.assertIn("source_ip", chain)
                self.assertIn("participating_entities", chain)
                self.assertIn("username", chain["participating_entities"])
                self.assertIn("asset_name", chain["participating_entities"])

    def test_02_threat_intel_data_flow(self):
        """
        Verify GET /threat-intel returns indicators and summary metrics.
        """
        res = self.client.get("/threat-intel")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("summary", body)
        self.assertIn("indicators", body)
        
        if self.is_db_connected:
            self.assertGreaterEqual(body["summary"]["total_indicators"], 1)
            self.assertGreaterEqual(len(body["indicators"]), 1)
            ioc = body["indicators"][0]
            self.assertIn("indicator_id", ioc)
            self.assertIn("indicator_type", ioc)
            self.assertIn("indicator_value", ioc)

    def test_03_mitre_mapping_data_flow(self):
        """
        Verify GET /mitre returns framework mappings and coverage summary.
        """
        res = self.client.get("/mitre")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("summary", body)
        self.assertIn("mappings", body)

        if self.is_db_connected:
            self.assertEqual(body["summary"]["total_events"], 1800)
            self.assertGreater(body["summary"]["mapped_events"], 0)
            self.assertGreater(len(body["mappings"]), 0)
            mapping = body["mappings"][0]
            self.assertIn("mitre_id", mapping)
            self.assertIn("technique_name", mapping)
            self.assertIn("tactic", mapping)

    def test_04_assets_data_flow(self):
        """
        Verify GET /assets returns asset catalog and CVE vulnerability details.
        """
        res = self.client.get("/assets")
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn("summary", body)
        self.assertIn("assets", body)

        if self.is_db_connected:
            self.assertGreaterEqual(body["summary"]["total_assets"], 1)
            self.assertGreaterEqual(len(body["assets"]), 1)
            asset = body["assets"][0]
            self.assertIn("asset_name", asset)
            self.assertIn("criticality", asset)
            self.assertIn("vulnerabilities", asset)

    def test_05_incidents_data_flow(self):
        """
        Verify GET /api/v1/incidents returns incidents with canonical and alias fields.
        """
        for route in ["/api/v1/incidents", "/v1/incidents"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertIn("data", body)
            self.assertIn("pagination", body)

            if self.is_db_connected:
                self.assertGreater(len(body["data"]), 0)
                inc = body["data"][0]
                self.assertIn("incident_id", inc)
                self.assertIn("threat_type", inc)
                self.assertIn("risk_score", inc)
                self.assertIn("risk_level", inc)
                self.assertIn("status", inc)
                # Ensure both canonical and alias fields are present
                self.assertIn("affected_asset", inc)
                self.assertIn("asset_id", inc)
                self.assertIn("affected_user", inc)
                self.assertIn("username", inc)
                self.assertIn("ml_confidence", inc)
                self.assertIn("confidence_score", inc)
                self.assertIn("related_events", inc)
                self.assertIn("event_ids", inc)
                self.assertIn("mitre_techniques", inc)
                self.assertIn("mitre_technique", inc)

    def test_06_risk_summary_data_flow(self):
        """
        Verify GET /api/v1/risk/summary evaluates all 1,800 telemetry records.
        """
        for route in ["/api/v1/risk/summary", "/v1/risk/summary"]:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200)
            body = res.json()
            self.assertIn("total_evaluated_events", body)
            self.assertIn("average_risk_score", body)
            self.assertIn("risk_distribution", body)
            self.assertIn("top_risk_factors", body)

            if self.is_db_connected:
                self.assertEqual(body["total_evaluated_events"], 1800)
                self.assertIn("Critical", body["risk_distribution"])
                self.assertIn("High", body["risk_distribution"])
                self.assertIn("Moderate", body["risk_distribution"])
                self.assertIn("Medium", body["risk_distribution"])
                self.assertIn("Low", body["risk_distribution"])


if __name__ == "__main__":
    unittest.main()
