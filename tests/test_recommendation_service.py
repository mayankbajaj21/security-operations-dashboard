"""
tests/test_recommendation_service.py

Milestone 3 — Step 4: Prescriptive Analyst Recommendation Service Test Suite

Validates:
A. Brute Force recommendations (M3 Benchmark)
B. Malware recommendations (M3 Benchmark)
C. Data Exfiltration recommendations (M3 Benchmark)
D. Phishing recommendations
E. SQL Injection recommendations
F. Privilege Escalation recommendations
G. Port Scan recommendations
H. Contextual Augmentations (Critical Asset, Malicious IoC, Attack Chain)
I. Normal Activity / Unsupported threat type handling
J. Non-Destructive safety guarantee (analyst guidance strings only)
"""

from pathlib import Path
import sys
import unittest

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.services.recommendation_service import (
    RecommendationService,
    THREAT_RECOMMENDATION_MATRIX
)


class TestRecommendationService(unittest.TestCase):
    """
    Unit test suite for prescriptive analyst mitigation recommendations.
    """

    # -------------------------------------------------------------------------
    # A. Brute Force Benchmark
    # -------------------------------------------------------------------------
    def test_brute_force_recommendations(self):
        recs = RecommendationService.get_recommendations("Brute Force")
        self.assertIsInstance(recs, list)
        self.assertGreaterEqual(len(recs), 4)

        recs_text = " ".join(recs)
        self.assertIn("Temporarily lock account", recs_text)
        self.assertIn("Investigate source IP", recs_text)
        self.assertIn("Check authentication logs", recs_text)
        self.assertIn("Enable Multi-Factor Authentication", recs_text)

    # -------------------------------------------------------------------------
    # B. Malware Benchmark
    # -------------------------------------------------------------------------
    def test_malware_recommendations(self):
        recs = RecommendationService.get_recommendations("Malware")
        self.assertIsInstance(recs, list)
        self.assertGreaterEqual(len(recs), 3)

        recs_text = " ".join(recs)
        self.assertIn("Isolate endpoint", recs_text)
        self.assertIn("Scan system", recs_text)
        self.assertIn("Investigate file hash", recs_text)

    # -------------------------------------------------------------------------
    # C. Data Exfiltration Benchmark
    # -------------------------------------------------------------------------
    def test_data_exfiltration_recommendations(self):
        recs = RecommendationService.get_recommendations("Data Exfiltration")
        self.assertIsInstance(recs, list)
        self.assertGreaterEqual(len(recs), 4)

        recs_text = " ".join(recs)
        self.assertIn("Investigate destination", recs_text)
        self.assertIn("Restrict suspicious outbound connection", recs_text)
        self.assertIn("Review data transfer volume", recs_text)
        self.assertIn("Escalate to Tier-3", recs_text)

    # -------------------------------------------------------------------------
    # D. Phishing Recommendations
    # -------------------------------------------------------------------------
    def test_phishing_recommendations(self):
        recs = RecommendationService.get_recommendations("Phishing Email")
        self.assertIsInstance(recs, list)
        recs_text = " ".join(recs)
        self.assertIn("Block sender domain", recs_text)
        self.assertIn("Check mailbox delivery logs", recs_text)
        self.assertIn("Reset credentials", recs_text)

    # -------------------------------------------------------------------------
    # E. SQL Injection Recommendations
    # -------------------------------------------------------------------------
    def test_sql_injection_recommendations(self):
        recs = RecommendationService.get_recommendations("SQL Injection")
        recs_text = " ".join(recs)
        self.assertIn("Inspect web application firewall", recs_text)
        self.assertIn("parameterized queries", recs_text)
        self.assertIn("Audit database access logs", recs_text)

    # -------------------------------------------------------------------------
    # F. Privilege Escalation Recommendations
    # -------------------------------------------------------------------------
    def test_privilege_escalation_recommendations(self):
        recs = RecommendationService.get_recommendations("Privilege Escalation")
        recs_text = " ".join(recs)
        self.assertIn("Revoke escalated administrative permissions", recs_text)
        self.assertIn("Audit user account privilege change logs", recs_text)

    # -------------------------------------------------------------------------
    # G. Port Scan Recommendations
    # -------------------------------------------------------------------------
    def test_port_scan_recommendations(self):
        recs = RecommendationService.get_recommendations("Port Scan")
        recs_text = " ".join(recs)
        self.assertIn("firewall drop logs", recs_text)
        self.assertIn("Verify target ports", recs_text)

    # -------------------------------------------------------------------------
    # H. Contextual Augmentations
    # -------------------------------------------------------------------------
    def test_contextual_augmentations(self):
        # 1. Critical Asset Augmentation
        recs_crit = RecommendationService.get_recommendations(
            threat_type="Brute Force",
            asset_criticality="Critical"
        )
        self.assertTrue(any("forensic snapshot" in r for r in recs_crit))

        # 2. Malicious IoC Augmentation
        recs_ioc = RecommendationService.get_recommendations(
            threat_type="Brute Force",
            ioc_status="Malicious"
        )
        self.assertTrue(any("blackhole list" in r for r in recs_ioc))

        # 3. Attack Chain Augmentation
        recs_chain = RecommendationService.get_recommendations(
            threat_type="Brute Force",
            attack_chain_id="AC-001"
        )
        self.assertTrue(any("AC-001" in r for r in recs_chain))

    # -------------------------------------------------------------------------
    # I. Normal Activity / Unknown Threat Type
    # -------------------------------------------------------------------------
    def test_normal_activity_or_unsupported_threat(self):
        recs_normal = RecommendationService.get_recommendations("Normal Activity")
        self.assertEqual(len(recs_normal), 0)

        recs_unknown = RecommendationService.get_recommendations("Unseen Nonexistent Threat")
        self.assertEqual(len(recs_unknown), 0)

    # -------------------------------------------------------------------------
    # J. Non-Destructive Safety Guarantee
    # -------------------------------------------------------------------------
    def test_recommendations_are_purely_advisory_strings(self):
        structured = RecommendationService.get_structured_recommendations("Brute Force")
        for item in structured:
            self.assertIsInstance(item.action, str)
            self.assertIsInstance(item.category, str)
            self.assertIn(item.category, ["Immediate Containment", "Investigation", "Remediation"])
            self.assertIsInstance(item.rationale, str)


if __name__ == "__main__":
    unittest.main()
