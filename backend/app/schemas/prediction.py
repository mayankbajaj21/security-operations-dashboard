"""
backend/app/schemas/prediction.py

Milestone 2 — Step 8: Prediction APIs Pydantic Schemas

Defines request and response validation models for Milestone 2 threat prediction
endpoints including live inference, prediction retrieval, model performance,
and database-derived threat summaries.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class PredictRequest(BaseModel):
    """
    Request schema for POST /predict live inference endpoint.
    Provides flexible input for event features while supplying sensible defaults
    for missing telemetry to support on-the-fly model prediction.
    """
    model_config = ConfigDict(populate_by_name=True)

    event_id: Optional[str] = Field(default="EVT_LIVE_001", description="Identifier for the input security event")
    event_type: Optional[str] = Field(default="Failed Login", description="Category of security event")
    failed_login_attempts: Optional[int] = Field(default=0, ge=0, description="Count of failed login attempts")
    raw_cvss_score: Optional[float] = Field(default=0.0, ge=0.0, le=10.0, alias="cvss_score", description="CVSS vulnerability score")
    malware_detected: Optional[str] = Field(default="No", description="Malware detection status ('Yes' or 'No')")
    event_severity: Optional[str] = Field(default="Low", alias="severity", description="Log severity level ('Low', 'Medium', 'High', 'Critical')")
    login_hour: Optional[int] = Field(default=None, ge=0, le=23, description="Hour of day (0-23)")
    after_hours_activity: Optional[int] = Field(default=0, ge=0, le=1, description="Binary flag indicating off-peak activity (1 or 0)")
    events_per_user_1h: Optional[float] = Field(default=1.0, ge=0.0, description="Rolling 1-hour event volume per user")
    login_frequency_1h: Optional[float] = Field(default=1.0, ge=0.0, description="Rolling 1-hour login event frequency")
    unique_destinations_24h: Optional[int] = Field(default=1, ge=0, description="Unique destination IPs accessed in 24 hours")
    vulnerability_present: Optional[int] = Field(default=0, ge=0, le=1, description="Binary flag for associated CVE (1 or 0)")
    protocol: Optional[str] = Field(default="TCP", description="Network protocol")
    event_status: Optional[str] = Field(default="Success", description="Execution outcome ('Success', 'Failed', 'Blocked', 'Detected')")
    username: Optional[str] = Field(default="analyst", description="Target user account name")
    timestamp: Optional[str] = Field(default=None, description="ISO 8601 timestamp of event execution")
    source_ip: Optional[str] = Field(default="192.168.1.100", description="Source IP address")
    destination_ip: Optional[str] = Field(default="10.0.0.1", description="Destination IP address")


class PredictResponse(BaseModel):
    """
    Response schema for POST /predict live inference endpoint.
    Returns ML prediction, calibrated threat classification, bounded confidence score, and XAI reasons.
    """
    event_id: str = Field(..., description="Event identifier evaluated")
    prediction: str = Field(..., description="Isolation Forest model prediction ('Normal' or 'Suspicious')")
    anomaly_score: float = Field(..., description="Continuous decision function anomaly score")
    threat_type: str = Field(..., description="Categorical threat classification (e.g. 'Brute Force', 'Malware')")
    threat_level: str = Field(..., description="5-tier SOC threat hierarchy ('Normal', 'Low Threat', 'Medium Threat', 'High Threat', 'Critical Threat')")
    confidence_score: int = Field(..., ge=0, le=100, description="Bounded Threat Confidence Score (0-100)")
    reasons: List[str] = Field(default_factory=list, description="Array of human-readable explainable AI strings")
    model_version: str = Field(default="isolation_forest_v1", description="Tracked ML model version")


class PredictionDocumentResponse(BaseModel):
    """
    Schema for stored threat prediction documents retrieved from MongoDB.
    """
    event_id: str
    prediction: str
    anomaly_score: float
    threat_type: str
    threat_level: str
    confidence_score: int
    reasons: List[str]
    model_version: str
    created_at: str


class PaginationMeta(BaseModel):
    """Pagination metadata model."""
    page: int
    limit: int
    total: int
    total_pages: int


class PaginatedPredictionsResponse(BaseModel):
    """
    Response schema for GET /predictions and GET /anomalies endpoints.
    """
    data: List[PredictionDocumentResponse]
    pagination: PaginationMeta


class PredictionWithEventDetailsResponse(PredictionDocumentResponse):
    """
    Response schema for GET /predictions/{event_id} endpoint.
    Includes prediction outputs joined with authoritative security event telemetry.
    """
    event_details: Optional[Dict[str, Any]] = Field(default=None, description="Full security event telemetry joined from security_events collection")


class ScoreDistribution(BaseModel):
    """Statistical summary of decision function scores."""
    min: float
    max: float
    mean: float
    median: float


class ModelPerformanceResponse(BaseModel):
    """
    Response schema for GET /model-performance diagnostic endpoint.
    """
    model_name: str = Field(default="Isolation Forest")
    model_version: str = Field(default="isolation_forest_v1")
    total_events_evaluated: int = Field(default=1800)
    normal_count: int = Field(default=1710)
    suspicious_count: int = Field(default=90)
    anomaly_percentage: float = Field(default=5.0)
    feature_count: int = Field(default=29)
    contamination: float = Field(default=0.05)
    score_distribution: ScoreDistribution
    evaluation_note: str = Field(default="Evaluated via unsupervised anomaly detection diagnostics and feature variance stability.")


class ThreatSummaryResponse(BaseModel):
    """
    Response schema for GET /threat-summary aggregated KPI endpoint.
    """
    total_events: int
    anomalies_detected: int
    normal_events: int
    threat_levels: Dict[str, int]
    threat_types: Dict[str, int]
    average_confidence_score: float
