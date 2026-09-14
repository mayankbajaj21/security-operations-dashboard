"""
backend/app/services/risk_engine.py

Milestone 3 — Step 2: Multi-Factor Risk Scoring Engine Service Module

Implements the deterministic Multi-Factor Risk Scoring Engine for the Security
Operations Dashboard based on the 5-pillar mathematical formula:

    Risk Score = 0.25 * Threat Severity
               + 0.25 * ML Confidence
               + 0.20 * Asset Criticality
               + 0.20 * Vulnerability Risk
               + 0.10 * Threat Intelligence

All components are strictly normalized to a [0.0, 100.0] scale before applying weights.
Final output scores are bounded in [0, 100] and mapped to the 5-tier SOC risk scale:
    - 0  - 20 : Low
    - 21 - 40 : Medium
    - 41 - 60 : Moderate
    - 61 - 80 : High
    - 81 - 100: Critical
"""

from datetime import datetime, timezone
import logging
import math
from typing import Dict, Any, List, Optional, Union

from backend.app.core.database import get_database
from backend.app.schemas.risk import (
    RiskCalculateRequest,
    RiskCalculateResponse,
    RiskComponentBreakdown,
    ComponentScore,
    RiskWeights
)

logger = logging.getLogger("RiskScoringEngine")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

# Authoritative Milestone 3 Mathematical Default Weights (Sum = 1.00)
WEIGHT_SEVERITY = 0.25
WEIGHT_CONFIDENCE = 0.25
WEIGHT_CRITICALITY = 0.20
WEIGHT_VULNERABILITY = 0.20
WEIGHT_THREAT_INTEL = 0.10

DEFAULT_RISK_WEIGHTS = RiskWeights(
    threat_severity=WEIGHT_SEVERITY,
    ml_confidence=WEIGHT_CONFIDENCE,
    asset_criticality=WEIGHT_CRITICALITY,
    vulnerability_risk=WEIGHT_VULNERABILITY,
    threat_intelligence=WEIGHT_THREAT_INTEL
)

_active_weights: Optional[RiskWeights] = None
_weights_updated_at: Optional[str] = None


def get_active_weights(db: Optional[Any] = None) -> RiskWeights:
    """
    Returns the currently active calculation weights.
    Loads from MongoDB risk_configuration collection if available, falling back to M3 defaults.
    """
    global _active_weights, _weights_updated_at
    if _active_weights is not None:
        return _active_weights

    try:
        database = db if db is not None else get_database()
        config_coll = database["risk_configuration"]
        doc = config_coll.find_one({"_id": "active_weights"})
        if doc and "weights" in doc:
            _active_weights = RiskWeights(**doc["weights"])
            _weights_updated_at = doc.get("updated_at")
            return _active_weights
    except Exception:
        pass

    _active_weights = DEFAULT_RISK_WEIGHTS
    return _active_weights


def set_active_weights(new_weights: RiskWeights, db: Optional[Any] = None) -> RiskWeights:
    """
    Updates the active risk weights and persists to MongoDB if available.
    """
    global _active_weights, _weights_updated_at
    _active_weights = new_weights
    now_iso = datetime.now(timezone.utc).isoformat()
    _weights_updated_at = now_iso

    try:
        database = db if db is not None else get_database()
        config_coll = database["risk_configuration"]
        config_coll.update_one(
            {"_id": "active_weights"},
            {"$set": {"weights": new_weights.model_dump(), "updated_at": now_iso}},
            upsert=True
        )
    except Exception:
        pass

    return _active_weights


def reset_default_weights(db: Optional[Any] = None) -> RiskWeights:
    """
    Resets active weights back to the authoritative M3 baseline (25/25/20/20/10).
    """
    global _active_weights, _weights_updated_at
    _active_weights = DEFAULT_RISK_WEIGHTS
    now_iso = datetime.now(timezone.utc).isoformat()
    _weights_updated_at = now_iso

    try:
        database = db if db is not None else get_database()
        config_coll = database["risk_configuration"]
        config_coll.delete_one({"_id": "active_weights"})
    except Exception:
        pass

    return _active_weights


def get_weights_metadata(db: Optional[Any] = None) -> dict:
    """
    Returns active weights container with custom status and authoritative defaults.
    """
    active = get_active_weights(db)
    is_custom = (
        active.threat_severity != DEFAULT_RISK_WEIGHTS.threat_severity or
        active.ml_confidence != DEFAULT_RISK_WEIGHTS.ml_confidence or
        active.asset_criticality != DEFAULT_RISK_WEIGHTS.asset_criticality or
        active.vulnerability_risk != DEFAULT_RISK_WEIGHTS.vulnerability_risk or
        active.threat_intelligence != DEFAULT_RISK_WEIGHTS.threat_intelligence
    )
    return {
        "weights": active,
        "is_custom": is_custom,
        "defaults": DEFAULT_RISK_WEIGHTS,
        "updated_at": _weights_updated_at
    }


def normalize_threat_severity(severity: Any) -> float:
    """
    Normalizes log event severity to a 0.0 - 100.0 continuous scale.
    - Critical : 100.0
    - High     : 75.0
    - Medium   : 50.0
    - Low      : 25.0
    - None/Missing/Normal : 0.0
    """
    if severity is None:
        return 0.0

    sev_str = str(severity).strip().lower()
    if sev_str == "critical":
        return 100.0
    elif sev_str == "high":
        return 75.0
    elif sev_str == "medium":
        return 50.0
    elif sev_str == "low":
        return 25.0
    elif sev_str in ("none", "normal", "info", "informational", "0"):
        return 0.0

    return 0.0


def normalize_ml_confidence(confidence: Any) -> float:
    """
    Normalizes ML threat confidence score to 0.0 - 100.0.
    Directly consumes the M2 confidence score (already calibrated on 0 - 100 scale).
    Missing values default to 0.0.
    """
    if confidence is None:
        return 0.0

    try:
        val = float(confidence)
        return max(0.0, min(100.0, val))
    except (ValueError, TypeError):
        return 0.0


def normalize_asset_criticality(criticality: Any) -> float:
    """
    Normalizes asset business impact criticality to a 0.0 - 100.0 scale.
    - Critical : 100.0
    - High     : 75.0
    - Medium   : 50.0
    - Low      : 25.0
    - Missing/Unregistered asset : 25.0 (Conservative Low baseline default)
    """
    if criticality is None:
        return 25.0

    crit_str = str(criticality).strip().lower()
    if crit_str == "critical":
        return 100.0
    elif crit_str == "high":
        return 75.0
    elif crit_str == "medium":
        return 50.0
    elif crit_str == "low":
        return 25.0

    # Fallback for unmapped or missing asset references
    return 25.0


def normalize_vulnerability_risk(cvss: Any) -> float:
    """
    Normalizes CVSS vulnerability base score (0.0 - 10.0) to a 0.0 - 100.0 scale.
    Formula: CVSS * 10.0
    Missing / 0.0 CVSS defaults to 0.0.
    """
    if cvss is None:
        return 0.0

    try:
        val = float(cvss)
        if val <= 0.0:
            return 0.0
        normalized = val * 10.0
        return max(0.0, min(100.0, normalized))
    except (ValueError, TypeError):
        return 0.0


def normalize_threat_intel(ioc: Any) -> float:
    """
    Normalizes Threat Intelligence Indicator of Compromise (IoC) match.
    - True / 'Malicious' / Count > 0 : 100.0
    - False / 'Clean' / 'Benign' / None : 0.0
    """
    if ioc is None:
        return 0.0

    if isinstance(ioc, bool):
        return 100.0 if ioc else 0.0

    if isinstance(ioc, (int, float)):
        return 100.0 if ioc > 0 else 0.0

    ioc_str = str(ioc).strip().lower()
    if ioc_str in ("true", "malicious", "high", "critical", "positive", "yes", "detected", "match"):
        return 100.0
    elif ioc_str in ("false", "clean", "benign", "low", "no", "none", "0"):
        return 0.0

    return 0.0


def classify_risk_level(score: Union[int, float]) -> str:
    """
    Classifies a continuous or integer risk score into the 5-tier M3 risk hierarchy:
    - 0  - 20 : Low
    - 21 - 40 : Medium
    - 41 - 60 : Moderate
    - 61 - 80 : High
    - 81 - 100: Critical
    """
    try:
        val = round(float(score))
    except (ValueError, TypeError):
        val = 0

    if val <= 20:
        return "Low"
    elif val <= 40:
        return "Medium"
    elif val <= 60:
        return "Moderate"
    elif val <= 80:
        return "High"
    else:
        return "Critical"


class RiskScoringEngine:
    """
    Deterministic Multi-Factor Risk Scoring Engine service.
    Evaluates threat severity, ML confidence, asset criticality, vulnerability risk,
    and threat intelligence to produce audit-compliant risk scores.
    """

    @classmethod
    def calculate(
        cls, 
        input_data: Union[RiskCalculateRequest, Dict[str, Any]],
        weights: Optional[Union[RiskWeights, Dict[str, float]]] = None
    ) -> RiskCalculateResponse:
        """
        Executes multi-factor risk calculation from a request model or dictionary payload.
        Supports explicit dynamic weights override or active system weights.
        """
        if isinstance(input_data, dict):
            # Extract fields handling both standard names and common aliases
            event_id = str(input_data.get("event_id", "EVT_LIVE_001"))
            severity_raw = input_data.get("severity", input_data.get("event_severity", "Low"))
            ml_prediction_raw = input_data.get("ml_prediction", input_data.get("prediction", "Normal"))
            confidence_raw = input_data.get("ml_confidence", input_data.get("confidence_score", 0.0))
            anomaly_score_raw = input_data.get("anomaly_score", 0.0)
            cvss_raw = input_data.get("cvss_score", input_data.get("raw_cvss_score", 0.0))
            criticality_raw = input_data.get("asset_criticality", input_data.get("criticality", "Low"))
            ioc_raw = input_data.get("ioc_status", input_data.get("threat_intel_match", False))
            threat_type = str(input_data.get("threat_type", "Normal Activity"))
            asset_name = input_data.get("asset_name")
            username = input_data.get("username")
            existing_reasons = input_data.get("reasons", [])
            data_weights = input_data.get("weights")
        elif isinstance(input_data, RiskCalculateRequest):
            event_id = input_data.event_id or "EVT_LIVE_001"
            severity_raw = input_data.severity
            ml_prediction_raw = input_data.ml_prediction
            confidence_raw = input_data.ml_confidence
            anomaly_score_raw = input_data.anomaly_score
            cvss_raw = input_data.cvss_score
            criticality_raw = input_data.asset_criticality
            ioc_raw = input_data.ioc_status
            threat_type = input_data.threat_type or "Normal Activity"
            asset_name = input_data.asset_name
            username = input_data.username
            existing_reasons = input_data.reasons or []
            data_weights = input_data.weights
        else:
            raise ValueError(f"Unsupported input data type for risk calculation: {type(input_data)}")

        # Resolve active calculation weights: explicit arg > payload weights > system active weights
        if weights is not None:
            active_weights = weights if isinstance(weights, RiskWeights) else RiskWeights(**weights)
        elif data_weights is not None:
            active_weights = data_weights if isinstance(data_weights, RiskWeights) else RiskWeights(**data_weights)
        else:
            active_weights = get_active_weights()

        # 1. Normalize all 5 risk pillars to [0.0, 100.0]
        norm_severity = normalize_threat_severity(severity_raw)
        norm_confidence = normalize_ml_confidence(confidence_raw)
        norm_criticality = normalize_asset_criticality(criticality_raw)
        norm_vulnerability = normalize_vulnerability_risk(cvss_raw)
        norm_threat_intel = normalize_threat_intel(ioc_raw)

        # 2. Compute weighted contributions using active weights
        w_sev = active_weights.threat_severity
        w_conf = active_weights.ml_confidence
        w_crit = active_weights.asset_criticality
        w_vuln = active_weights.vulnerability_risk
        w_intel = active_weights.threat_intelligence

        weight_sev = norm_severity * w_sev
        weight_conf = norm_confidence * w_conf
        weight_crit = norm_criticality * w_crit
        weight_vuln = norm_vulnerability * w_vuln
        weight_intel = norm_threat_intel * w_intel

        # 3. Sum components and clamp to [0.0, 100.0]
        raw_score = weight_sev + weight_conf + weight_crit + weight_vuln + weight_intel
        raw_score_clamped = max(0.0, min(100.0, raw_score))
        rounded_score = int(round(raw_score_clamped))

        # 4. Determine 5-tier categorical risk level
        risk_level = classify_risk_level(rounded_score)

        # 5. Build component breakdown model
        breakdown = RiskComponentBreakdown(
            threat_severity=ComponentScore(
                raw=severity_raw,
                normalized=round(norm_severity, 2),
                weighted=round(weight_sev, 2)
            ),
            ml_confidence=ComponentScore(
                raw=confidence_raw,
                normalized=round(norm_confidence, 2),
                weighted=round(weight_conf, 2)
            ),
            asset_criticality=ComponentScore(
                raw=criticality_raw,
                normalized=round(norm_criticality, 2),
                weighted=round(weight_crit, 2)
            ),
            vulnerability_risk=ComponentScore(
                raw=cvss_raw,
                normalized=round(norm_vulnerability, 2),
                weighted=round(weight_vuln, 2)
            ),
            threat_intelligence=ComponentScore(
                raw=ioc_raw,
                normalized=round(norm_threat_intel, 2),
                weighted=round(weight_intel, 2)
            )
        )

        # 6. Generate explainable contributing reasons
        generated_reasons = cls._generate_reasons(
            norm_severity=norm_severity,
            norm_confidence=norm_confidence,
            norm_criticality=norm_criticality,
            norm_vulnerability=norm_vulnerability,
            norm_threat_intel=norm_threat_intel,
            severity_raw=severity_raw,
            confidence_raw=confidence_raw,
            criticality_raw=criticality_raw,
            cvss_raw=cvss_raw,
            asset_name=asset_name,
            anomaly_score=anomaly_score_raw,
            existing_reasons=existing_reasons,
            weights=active_weights
        )

        return RiskCalculateResponse(
            event_id=event_id,
            risk_score=rounded_score,
            risk_score_raw=round(raw_score_clamped, 2),
            risk_level=risk_level,
            breakdown=breakdown,
            threat_type=threat_type,
            reasons=generated_reasons,
            weights_used=active_weights
        )

    @classmethod
    def _generate_reasons(
        cls,
        norm_severity: float,
        norm_confidence: float,
        norm_criticality: float,
        norm_vulnerability: float,
        norm_threat_intel: float,
        severity_raw: Any,
        confidence_raw: Any,
        criticality_raw: Any,
        cvss_raw: Any,
        asset_name: Optional[str],
        anomaly_score: Optional[float],
        existing_reasons: List[str],
        weights: Optional[RiskWeights] = None
    ) -> List[str]:
        """
        Generates explainable, evidence-backed XAI reasons detailing why the score is high/low.
        """
        reasons: List[str] = []
        asset_label = str(asset_name).strip() if asset_name else "target host"

        w_sev = weights.threat_severity if weights else WEIGHT_SEVERITY
        w_conf = weights.ml_confidence if weights else WEIGHT_CONFIDENCE
        w_crit = weights.asset_criticality if weights else WEIGHT_CRITICALITY
        w_vuln = weights.vulnerability_risk if weights else WEIGHT_VULNERABILITY
        w_intel = weights.threat_intelligence if weights else WEIGHT_THREAT_INTEL

        # 1. Threat Severity Factor
        if norm_severity >= 100.0:
            reasons.append(f"Event logged with Critical operational severity (+{norm_severity * w_sev:.1f} pts)")
        elif norm_severity >= 75.0:
            reasons.append(f"Event logged with High operational severity (+{norm_severity * w_sev:.1f} pts)")
        elif norm_severity >= 50.0:
            reasons.append(f"Event logged with Medium operational severity (+{norm_severity * w_sev:.1f} pts)")

        # 2. ML Threat Confidence Factor
        if norm_confidence >= 80.0:
            reasons.append(f"High ML threat confidence ({confidence_raw}% certainty, +{norm_confidence * w_conf:.1f} pts)")
        elif norm_confidence >= 50.0:
            reasons.append(f"Moderate ML threat confidence ({confidence_raw}%, +{norm_confidence * w_conf:.1f} pts)")

        # 3. Asset Criticality Factor
        if norm_criticality >= 100.0:
            reasons.append(f"Target asset '{asset_label}' has Critical business impact (+{norm_criticality * w_crit:.1f} pts)")
        elif norm_criticality >= 75.0:
            reasons.append(f"Target asset '{asset_label}' has High business impact (+{norm_criticality * w_crit:.1f} pts)")

        # 4. Vulnerability Risk Factor
        if norm_vulnerability >= 70.0:
            reasons.append(f"High active vulnerability exposure (CVSS {cvss_raw}/10, +{norm_vulnerability * w_vuln:.1f} pts)")
        elif norm_vulnerability > 0.0:
            reasons.append(f"Known CVE vulnerability associated with host (CVSS {cvss_raw}/10, +{norm_vulnerability * w_vuln:.1f} pts)")

        # 5. Threat Intelligence Factor
        if norm_threat_intel >= 100.0:
            reasons.append(f"Confirmed Indicator of Compromise (IoC) match in threat intelligence (+{norm_threat_intel * w_intel:.1f} pts)")

        # 6. Contextual Anomaly Score Diagnostic (Supporting, non-weighted)
        if anomaly_score is not None:
            try:
                a_val = float(anomaly_score)
                if a_val < 0.0:
                    reasons.append(f"Isolation Forest decision function flagged anomalous telemetry (anomaly score: {a_val:.4f})")
            except (ValueError, TypeError):
                pass

        # 7. Preserve prior M2 XAI explanation strings if present and non-duplicate
        if existing_reasons and isinstance(existing_reasons, list):
            for r in existing_reasons:
                clean_r = str(r).strip()
                if clean_r and clean_r not in reasons:
                    reasons.append(clean_r)

        # Baseline explanation if no high factors were triggered
        if not reasons:
            reasons.append("Telemetry evaluated with standard baseline operational risk metrics.")

        return reasons
