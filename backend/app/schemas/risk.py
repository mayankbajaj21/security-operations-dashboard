"""
backend/app/schemas/risk.py

Milestone 3 — Step 2: Risk Scoring Schemas & Pydantic Validation Models

Defines request, response, and component breakdown models for the Milestone 3
Multi-Factor Risk Scoring Engine.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict, model_validator


class ComponentScore(BaseModel):
    """
    Individual risk component score container with raw, normalized (0-100), and weighted values.
    """
    raw: Any = Field(..., description="Raw input value before normalization")
    normalized: float = Field(..., ge=0.0, le=100.0, description="Normalized score on standard 0-100 scale")
    weighted: float = Field(..., ge=0.0, le=100.0, description="Component contribution after applying weight")


class RiskComponentBreakdown(BaseModel):
    """
    Detailed 5-pillar mathematical breakdown of the multi-factor risk score.
    Weights: Threat Severity (25%), ML Confidence (25%), Asset Criticality (20%),
             Vulnerability Risk (20%), Threat Intelligence (10%).
    """
    threat_severity: ComponentScore = Field(..., description="Threat Severity component (25% weight)")
    ml_confidence: ComponentScore = Field(..., description="ML Threat Confidence component (25% weight)")
    asset_criticality: ComponentScore = Field(..., description="Asset Criticality component (20% weight)")
    vulnerability_risk: ComponentScore = Field(..., description="Vulnerability Risk component (20% weight)")
    threat_intelligence: ComponentScore = Field(..., description="Threat Intelligence component (10% weight)")


class RiskWeights(BaseModel):
    """
    Configurable 5-pillar mathematical weights for the Multi-Factor Risk Scoring Engine.
    All weights must be non-negative and sum exactly to 1.0 (100%).
    """
    threat_severity: float = Field(default=0.25, ge=0.0, le=1.0, description="Threat Severity weight (default 0.25)")
    ml_confidence: float = Field(default=0.25, ge=0.0, le=1.0, description="ML Confidence weight (default 0.25)")
    asset_criticality: float = Field(default=0.20, ge=0.0, le=1.0, description="Asset Criticality weight (default 0.20)")
    vulnerability_risk: float = Field(default=0.20, ge=0.0, le=1.0, description="Vulnerability Risk weight (default 0.20)")
    threat_intelligence: float = Field(default=0.10, ge=0.0, le=1.0, description="Threat Intelligence weight (default 0.10)")

    @model_validator(mode="after")
    def validate_sum_equals_one(self) -> "RiskWeights":
        total = round(
            float(self.threat_severity) + float(self.ml_confidence) + float(self.asset_criticality) + 
            float(self.vulnerability_risk) + float(self.threat_intelligence), 4
        )
        if total != 1.0:
            raise ValueError(f"Risk weights must sum exactly to 1.0 (100%). Current sum: {total * 100:.2f}%")
        return self


class RiskCalculateRequest(BaseModel):
    """
    Request schema for calculating Multi-Factor Risk Score.
    Accepts aliases matching both M1 telemetry (`security_events`) and M2 ML outputs (`threat_predictions`).
    """
    model_config = ConfigDict(populate_by_name=True)

    event_id: Optional[str] = Field(default="EVT_LIVE_001", description="Unique security event identifier")
    severity: Optional[str] = Field(
        default="Low", 
        alias="event_severity", 
        description="Log severity level ('Low', 'Medium', 'High', 'Critical')"
    )
    ml_prediction: Optional[str] = Field(
        default="Normal", 
        alias="prediction", 
        description="Isolation Forest prediction ('Normal' or 'Suspicious')"
    )
    ml_confidence: Optional[float] = Field(
        default=0.0, 
        ge=0.0, 
        le=100.0, 
        alias="confidence_score", 
        description="ML confidence score (0-100)"
    )
    anomaly_score: Optional[float] = Field(
        default=0.0, 
        description="Continuous anomaly score (contextual diagnostic, not a weighted risk pillar)"
    )
    cvss_score: Optional[float] = Field(
        default=0.0, 
        ge=0.0, 
        le=10.0, 
        alias="raw_cvss_score", 
        description="Base CVSS vulnerability score (0.0 - 10.0)"
    )
    asset_criticality: Optional[str] = Field(
        default="Low", 
        alias="criticality", 
        description="Asset business impact tier ('Low', 'Medium', 'High', 'Critical')"
    )
    ioc_status: Optional[Union[bool, str, int]] = Field(
        default=False, 
        alias="threat_intel_match", 
        description="Threat intelligence IoC match indicator (bool, 'Malicious'/'Clean', or count)"
    )

    # Contextual metadata for explanation generation and auditability
    threat_type: Optional[str] = Field(default="Normal Activity", description="Categorical threat classification")
    asset_name: Optional[str] = Field(default=None, description="Target asset hostname or system name")
    username: Optional[str] = Field(default=None, description="Target user account name")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    reasons: Optional[List[str]] = Field(default_factory=list, description="Prior XAI explanation strings from M2")
    weights: Optional[RiskWeights] = Field(default=None, description="Optional dynamic risk weights override")


class RiskWeightsResponse(BaseModel):
    """Container schema for active and default risk scoring weights."""
    weights: RiskWeights = Field(..., description="Currently active calculation weights")
    is_custom: bool = Field(default=False, description="True if active weights deviate from the M3 defaults")
    defaults: RiskWeights = Field(..., description="Authoritative M3 default weights (25/25/20/20/10)")
    updated_at: Optional[str] = Field(None, description="UTC ISO timestamp of last configuration update")


class RiskCalculateResponse(BaseModel):
    """
    Response schema returning the calculated multi-factor risk score,
    5-tier risk level, mathematical breakdown, and explainable reasons.
    """
    event_id: str = Field(..., description="Evaluated event identifier")
    risk_score: int = Field(..., ge=0, le=100, description="Bounded integer multi-factor risk score (0-100)")
    risk_score_raw: float = Field(..., ge=0.0, le=100.0, description="Exact floating-point risk score (0.0-100.0)")
    risk_level: str = Field(..., description="5-tier categorical risk hierarchy ('Low', 'Medium', 'Moderate', 'High', 'Critical')")
    breakdown: RiskComponentBreakdown = Field(..., description="Mathematical 5-component breakdown")
    threat_type: str = Field(default="Normal Activity", description="Evaluated threat category")
    reasons: List[str] = Field(default_factory=list, description="Prescriptive explainability factors")
    weights_used: Optional[RiskWeights] = Field(default=None, description="Weights applied during this calculation")


class RiskScoreComparisonResponse(BaseModel):
    """
    Mathematically honest comparison of standalone Event Risk Score (before correlation)
    vs Correlated Attack Campaign Risk Assessment (after correlation context).
    """
    event_id: str = Field(..., description="Evaluated event identifier")
    before_correlation: float = Field(..., description="Standalone event 5-pillar Multi-Factor Risk Score")
    after_correlation: float = Field(..., description="Contextual campaign risk assessment after correlation")
    difference: float = Field(..., description="Numerical score delta (after - before)")
    correlated: bool = Field(..., description="True if event participates in an active attack chain")
    chain_id: Optional[str] = Field(default=None, description="Associated Attack Chain ID if correlated")
    correlation_rule: Optional[str] = Field(default=None, description="Triggering correlation rule description")
    stages: List[str] = Field(default_factory=list, description="Progression of MITRE kill chain stages in chain")
    related_events_count: int = Field(default=1, description="Total number of events in the correlated campaign")
    incident_id: Optional[str] = Field(default=None, description="Associated Incident ID if created")
    explanation: List[str] = Field(default_factory=list, description="Transparent reasoning detailing context contribution")
