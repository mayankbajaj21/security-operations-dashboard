"""
tests/test_risk_engine.py

Milestone 3 — Step 2: Multi-Factor Risk Scoring Engine Test Suite

Validates:
A. Component Normalization (Severity, ML Confidence, Asset Criticality, CVSS, Threat Intel)
B. Linear Weighted Calculation (25% / 25% / 20% / 20% / 10%)
C. Bounded Outputs [0, 100]
D. 5-Tier Risk Level Classification Boundaries (20, 21, 40, 41, 60, 61, 80, 81, 100)
E. Missing Asset Criticality Fallback (25 / Low)
F. CVSS 0 / Missing Vulnerability (0.0)
G. Clean Threat Intelligence (0.0)
H. Malicious Threat Intelligence (100.0)
I. Explainable XAI Reason Generation
J. Anomaly Score Contextual Invariance (does NOT alter 5-pillar weights)
K. Canonical EVT-1001 Benchmark Scenario (Raw: 96.4, Integer: 96, Critical)
L. M2 Prediction Contract Compatibility
"""

from pathlib import Path
import sys
import unittest

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.schemas.risk import RiskCalculateRequest, RiskCalculateResponse
from backend.app.services.risk_engine import (
    RiskScoringEngine,
    normalize_threat_severity,
    normalize_ml_confidence,
    normalize_asset_criticality,
    normalize_vulnerability_risk,
    normalize_threat_intel,
    classify_risk_level,
    WEIGHT_SEVERITY,
    WEIGHT_CONFIDENCE,
    WEIGHT_CRITICALITY,
    WEIGHT_VULNERABILITY,
    WEIGHT_THREAT_INTEL
)


class TestRiskScoringEngine(unittest.TestCase):
    """
    Comprehensive test suite for the Milestone 3 Risk Scoring Engine.
    """

    # -------------------------------------------------------------------------
    # A. Component Normalization Tests
    # -------------------------------------------------------------------------
    def test_normalize_threat_severity(self):
        self.assertEqual(normalize_threat_severity("Critical"), 100.0)
        self.assertEqual(normalize_threat_severity("CRITICAL"), 100.0)
        self.assertEqual(normalize_threat_severity("High"), 75.0)
        self.assertEqual(normalize_threat_severity("high"), 75.0)
        self.assertEqual(normalize_threat_severity("Medium"), 50.0)
        self.assertEqual(normalize_threat_severity("Low"), 25.0)
        self.assertEqual(normalize_threat_severity("None"), 0.0)
        self.assertEqual(normalize_threat_severity("Normal"), 0.0)
        self.assertEqual(normalize_threat_severity(None), 0.0)
        self.assertEqual(normalize_threat_severity(""), 0.0)

    def test_normalize_ml_confidence(self):
        self.assertEqual(normalize_ml_confidence(92), 92.0)
        self.assertEqual(normalize_ml_confidence(0), 0.0)
        self.assertEqual(normalize_ml_confidence(100), 100.0)
        self.assertEqual(normalize_ml_confidence("85.5"), 85.5)
        # Clamping
        self.assertEqual(normalize_ml_confidence(-10), 0.0)
        self.assertEqual(normalize_ml_confidence(150), 100.0)
        # Missing
        self.assertEqual(normalize_ml_confidence(None), 0.0)
        self.assertEqual(normalize_ml_confidence("invalid"), 0.0)

    def test_normalize_asset_criticality(self):
        self.assertEqual(normalize_asset_criticality("Critical"), 100.0)
        self.assertEqual(normalize_asset_criticality("critical"), 100.0)
        self.assertEqual(normalize_asset_criticality("High"), 75.0)
        self.assertEqual(normalize_asset_criticality("Medium"), 50.0)
        self.assertEqual(normalize_asset_criticality("Low"), 25.0)
        # Missing / Unregistered Asset -> Conservative Low Default (25.0)
        self.assertEqual(normalize_asset_criticality(None), 25.0)
        self.assertEqual(normalize_asset_criticality(""), 25.0)
        self.assertEqual(normalize_asset_criticality("Unregistered-Server"), 25.0)

    def test_normalize_vulnerability_risk(self):
        self.assertEqual(normalize_vulnerability_risk(9.2), 92.0)
        self.assertEqual(normalize_vulnerability_risk(10.0), 100.0)
        self.assertEqual(normalize_vulnerability_risk(5.5), 55.0)
        self.assertEqual(normalize_vulnerability_risk(0.0), 0.0)
        self.assertEqual(normalize_vulnerability_risk("7.4"), 74.0)
        # Clamping
        self.assertEqual(normalize_vulnerability_risk(-2.0), 0.0)
        self.assertEqual(normalize_vulnerability_risk(15.0), 100.0)
        # Missing
        self.assertEqual(normalize_vulnerability_risk(None), 0.0)
        self.assertEqual(normalize_vulnerability_risk(""), 0.0)

    def test_normalize_threat_intel(self):
        self.assertEqual(normalize_threat_intel(True), 100.0)
        self.assertEqual(normalize_threat_intel(False), 0.0)
        self.assertEqual(normalize_threat_intel("Malicious"), 100.0)
        self.assertEqual(normalize_threat_intel("malicious"), 100.0)
        self.assertEqual(normalize_threat_intel("Clean"), 0.0)
        self.assertEqual(normalize_threat_intel("Benign"), 0.0)
        self.assertEqual(normalize_threat_intel(1), 100.0)
        self.assertEqual(normalize_threat_intel(0), 0.0)
        self.assertEqual(normalize_threat_intel(None), 0.0)

    # -------------------------------------------------------------------------
    # B. Weights Verification & Calculation
    # -------------------------------------------------------------------------
    def test_weights_sum_to_one(self):
        total_weight = (
            WEIGHT_SEVERITY +
            WEIGHT_CONFIDENCE +
            WEIGHT_CRITICALITY +
            WEIGHT_VULNERABILITY +
            WEIGHT_THREAT_INTEL
        )
        self.assertAlmostEqual(total_weight, 1.00, places=5)

    def test_zero_baseline_calculation(self):
        req = RiskCalculateRequest(
            event_id="EVT_ZERO",
            severity="None",
            ml_confidence=0.0,
            asset_criticality="Low", # 25.0 * 0.20 = 5.0 pts
            cvss_score=0.0,
            ioc_status=False
        )
        res = RiskScoringEngine.calculate(req)
        # 0.25*0 + 0.25*0 + 0.20*25 + 0.20*0 + 0.10*0 = 5.0
        self.assertEqual(res.risk_score_raw, 5.0)
        self.assertEqual(res.risk_score, 5)
        self.assertEqual(res.risk_level, "Low")

    def test_maximum_risk_calculation(self):
        req = RiskCalculateRequest(
            event_id="EVT_MAX",
            severity="Critical",     # 100 * 0.25 = 25.0
            ml_confidence=100.0,     # 100 * 0.25 = 25.0
            asset_criticality="Critical", # 100 * 0.20 = 20.0
            cvss_score=10.0,         # 100 * 0.20 = 20.0
            ioc_status=True          # 100 * 0.10 = 10.0
        )
        res = RiskScoringEngine.calculate(req)
        self.assertEqual(res.risk_score_raw, 100.0)
        self.assertEqual(res.risk_score, 100)
        self.assertEqual(res.risk_level, "Critical")

    # -------------------------------------------------------------------------
    # C. Bounded Outputs [0, 100]
    # -------------------------------------------------------------------------
    def test_score_bounding(self):
        res_min = RiskScoringEngine.calculate({
            "event_id": "EVT_MIN",
            "severity": "None",
            "ml_confidence": -50,
            "asset_criticality": "Low",
            "cvss_score": -5,
            "ioc_status": False
        })
        self.assertGreaterEqual(res_min.risk_score, 0)
        self.assertLessEqual(res_min.risk_score, 100)

        res_max = RiskScoringEngine.calculate({
            "event_id": "EVT_OVERFLOW",
            "severity": "Critical",
            "ml_confidence": 200,
            "asset_criticality": "Critical",
            "cvss_score": 15,
            "ioc_status": True
        })
        self.assertEqual(res_max.risk_score, 100)
        self.assertEqual(res_max.risk_score_raw, 100.0)

    # -------------------------------------------------------------------------
    # D. 5-Tier Risk Level Classification Boundaries
    # -------------------------------------------------------------------------
    def test_risk_level_boundaries(self):
        # 0 - 20: Low
        self.assertEqual(classify_risk_level(0), "Low")
        self.assertEqual(classify_risk_level(20), "Low")
        self.assertEqual(classify_risk_level(20.4), "Low")

        # 21 - 40: Medium
        self.assertEqual(classify_risk_level(21), "Medium")
        self.assertEqual(classify_risk_level(30), "Medium")
        self.assertEqual(classify_risk_level(40), "Medium")

        # 41 - 60: Moderate
        self.assertEqual(classify_risk_level(41), "Moderate")
        self.assertEqual(classify_risk_level(50), "Moderate")
        self.assertEqual(classify_risk_level(60), "Moderate")

        # 61 - 80: High
        self.assertEqual(classify_risk_level(61), "High")
        self.assertEqual(classify_risk_level(70), "High")
        self.assertEqual(classify_risk_level(80), "High")

        # 81 - 100: Critical
        self.assertEqual(classify_risk_level(81), "Critical")
        self.assertEqual(classify_risk_level(90), "Critical")
        self.assertEqual(classify_risk_level(100), "Critical")

    # -------------------------------------------------------------------------
    # E. Missing Asset Criticality Handling
    # -------------------------------------------------------------------------
    def test_missing_asset_criticality_defaults_to_low(self):
        req = RiskCalculateRequest(
            event_id="EVT_NO_ASSET",
            severity="Medium",       # 50 * 0.25 = 12.5
            ml_confidence=60.0,      # 60 * 0.25 = 15.0
            asset_criticality=None,  # 25 * 0.20 = 5.0 (Fallback)
            cvss_score=0.0,          # 0 * 0.20 = 0.0
            ioc_status=False         # 0 * 0.10 = 0.0
        )
        res = RiskScoringEngine.calculate(req)
        # 12.5 + 15.0 + 5.0 + 0 + 0 = 32.5 -> round to 33 or 32.5
        self.assertEqual(res.breakdown.asset_criticality.normalized, 25.0)
        self.assertEqual(res.breakdown.asset_criticality.weighted, 5.0)
        self.assertEqual(res.risk_score_raw, 32.5)
        self.assertEqual(res.risk_score, 32)
        self.assertEqual(res.risk_level, "Medium")

    # -------------------------------------------------------------------------
    # F. CVSS 0 / Missing Vulnerability
    # -------------------------------------------------------------------------
    def test_cvss_zero_contributes_zero_risk(self):
        res = RiskScoringEngine.calculate({
            "event_id": "EVT_NO_VULN",
            "severity": "Low",
            "ml_confidence": 0,
            "asset_criticality": "Low",
            "cvss_score": 0.0,
            "ioc_status": False
        })
        self.assertEqual(res.breakdown.vulnerability_risk.normalized, 0.0)
        self.assertEqual(res.breakdown.vulnerability_risk.weighted, 0.0)

    # -------------------------------------------------------------------------
    # G. Clean Threat Intelligence
    # -------------------------------------------------------------------------
    def test_clean_threat_intelligence_contributes_zero(self):
        res = RiskScoringEngine.calculate({
            "event_id": "EVT_CLEAN_IOC",
            "severity": "Low",
            "ioc_status": "Clean"
        })
        self.assertEqual(res.breakdown.threat_intelligence.normalized, 0.0)
        self.assertEqual(res.breakdown.threat_intelligence.weighted, 0.0)

    # -------------------------------------------------------------------------
    # H. Malicious Threat Intelligence
    # -------------------------------------------------------------------------
    def test_malicious_threat_intelligence_contributes_ten_points(self):
        res = RiskScoringEngine.calculate({
            "event_id": "EVT_MALICIOUS_IOC",
            "severity": "Low",
            "ioc_status": "Malicious"
        })
        self.assertEqual(res.breakdown.threat_intelligence.normalized, 100.0)
        self.assertEqual(res.breakdown.threat_intelligence.weighted, 10.0)

    # -------------------------------------------------------------------------
    # I. Explainable Reasons Generation
    # -------------------------------------------------------------------------
    def test_explainable_reasons_generated(self):
        req = RiskCalculateRequest(
            event_id="EVT_REASONS",
            severity="Critical",
            ml_confidence=85.0,
            asset_criticality="Critical",
            asset_name="AUTH-DC-01",
            cvss_score=8.5,
            ioc_status=True,
            anomaly_score=-0.045
        )
        res = RiskScoringEngine.calculate(req)
        self.assertIsInstance(res.reasons, list)
        self.assertGreater(len(res.reasons), 3)
        reasons_text = " ".join(res.reasons)
        self.assertIn("Critical operational severity", reasons_text)
        self.assertIn("High ML threat confidence", reasons_text)
        self.assertIn("AUTH-DC-01", reasons_text)
        self.assertIn("High active vulnerability exposure", reasons_text)
        self.assertIn("Indicator of Compromise", reasons_text)

    # -------------------------------------------------------------------------
    # J. Anomaly Score Invariance (Not a 6th weighted component)
    # -------------------------------------------------------------------------
    def test_anomaly_score_does_not_change_weights(self):
        res_with_anomaly = RiskScoringEngine.calculate({
            "event_id": "EVT_A1",
            "severity": "High",
            "ml_confidence": 80.0,
            "asset_criticality": "High",
            "cvss_score": 7.0,
            "ioc_status": True,
            "anomaly_score": -0.85
        })

        res_without_anomaly = RiskScoringEngine.calculate({
            "event_id": "EVT_A2",
            "severity": "High",
            "ml_confidence": 80.0,
            "asset_criticality": "High",
            "cvss_score": 7.0,
            "ioc_status": True,
            "anomaly_score": 0.0
        })

        # Exact same multi-factor score because anomaly_score is NOT weighted
        self.assertEqual(res_with_anomaly.risk_score_raw, res_without_anomaly.risk_score_raw)
        self.assertEqual(res_with_anomaly.risk_score, res_without_anomaly.risk_score)

    # -------------------------------------------------------------------------
    # K. Canonical EVT-1001 Benchmark Scenario
    # -------------------------------------------------------------------------
    def test_canonical_evt_1001_scenario(self):
        """
        Canonical Milestone 3 Benchmark Scenario (EVT-1001):
        - Threat: Brute Force
        - Log Severity: Critical (100.0) -> Weighted: 25.00 pts
        - ML Confidence: 92% (92.0)     -> Weighted: 23.00 pts
        - Asset Criticality: Critical (100.0) -> Weighted: 20.00 pts
        - Vulnerability CVSS: 9.2 (92.0) -> Weighted: 18.40 pts
        - Threat Intelligence: Malicious (100.0) -> Weighted: 10.00 pts
        -------------------------------------------------------------
        Total Raw Risk Score = 25.0 + 23.0 + 20.0 + 18.4 + 10.0 = 96.40
        Rounded Integer Risk Score = 96
        Risk Level = Critical
        """
        req = RiskCalculateRequest(
            event_id="EVT-1001",
            severity="Critical",
            ml_prediction="Suspicious",
            ml_confidence=92.0,
            anomaly_score=-0.74,
            asset_name="Production Database",
            asset_criticality="Critical",
            cvss_score=9.2,
            ioc_status="Malicious",
            threat_type="Brute Force"
        )
        res = RiskScoringEngine.calculate(req)

        # 1. Component breakdown verification
        self.assertEqual(res.breakdown.threat_severity.normalized, 100.0)
        self.assertEqual(res.breakdown.threat_severity.weighted, 25.0)

        self.assertEqual(res.breakdown.ml_confidence.normalized, 92.0)
        self.assertEqual(res.breakdown.ml_confidence.weighted, 23.0)

        self.assertEqual(res.breakdown.asset_criticality.normalized, 100.0)
        self.assertEqual(res.breakdown.asset_criticality.weighted, 20.0)

        self.assertEqual(res.breakdown.vulnerability_risk.normalized, 92.0)
        self.assertEqual(res.breakdown.vulnerability_risk.weighted, 18.4)

        self.assertEqual(res.breakdown.threat_intelligence.normalized, 100.0)
        self.assertEqual(res.breakdown.threat_intelligence.weighted, 10.0)

        # 2. Total score verification
        self.assertEqual(res.risk_score_raw, 96.4)
        self.assertEqual(res.risk_score, 96)
        self.assertEqual(res.risk_level, "Critical")
        self.assertEqual(res.threat_type, "Brute Force")

    # -------------------------------------------------------------------------
    # L. M2 Prediction Output Compatibility
    # -------------------------------------------------------------------------
    def test_m2_prediction_document_consumption(self):
        m2_output_doc = {
            "event_id": "EVT00034",
            "prediction": "Suspicious",
            "anomaly_score": 0.061516,
            "threat_type": "Brute Force",
            "threat_level": "Critical Threat",
            "confidence_score": 81,
            "reasons": [
                "Excessive failed login attempts (18 attempts exceeded threshold of 10)",
                "Activity occurred outside standard operational hours (02:00)",
                "Isolation Forest flagged event as anomalous (score: 0.061516)"
            ],
            "event_severity": "High",
            "asset_criticality": "Critical",
            "raw_cvss_score": 8.0,
            "threat_intel_match": True
        }
        res = RiskScoringEngine.calculate(m2_output_doc)
        
        # Severity High (75 * 0.25 = 18.75)
        # Conf 81 (81 * 0.25 = 20.25)
        # Crit (100 * 0.20 = 20.00)
        # CVSS 8.0 (80 * 0.20 = 16.00)
        # Intel (100 * 0.10 = 10.00)
        # Total = 18.75 + 20.25 + 20.0 + 16.0 + 10.0 = 85.0
        self.assertEqual(res.risk_score_raw, 85.0)
        self.assertEqual(res.risk_score, 85)
        self.assertEqual(res.risk_level, "Critical")
        self.assertEqual(res.event_id, "EVT00034")


if __name__ == "__main__":
    unittest.main()
