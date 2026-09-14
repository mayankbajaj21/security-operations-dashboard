"""
backend/app/schemas/correlation.py

Milestone 3 — Step 3: Event Correlation & Attack Chain Schemas

Defines Pydantic models for correlated security events and multi-stage attack chains
in accordance with the Milestone 3 specification.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class CorrelatedEventSummary(BaseModel):
    """
    Summary representation of an individual event participating in an attack chain.
    """
    model_config = ConfigDict(populate_by_name=True)

    event_id: str = Field(..., description="Unique event identifier")
    timestamp: Optional[str] = Field(default=None, description="ISO 8601 timestamp of event occurrence")
    event_type: Optional[str] = Field(default=None, description="Event classification")
    threat_type: Optional[str] = Field(default=None, description="Evaluated threat category")
    severity: Optional[str] = Field(default=None, alias="event_severity", description="Log severity level")
    username: Optional[str] = Field(default=None, alias="user_id", description="Target or actor username")
    source_ip: Optional[str] = Field(default=None, description="Source IP address")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP address")
    asset_name: Optional[str] = Field(default=None, alias="asset_id", description="Target asset name")
    mitre_id: Optional[str] = Field(default=None, description="Associated MITRE technique ID")
    stage: Optional[str] = Field(default=None, description="Mapped MITRE attack stage")
    risk_score: Optional[int] = Field(default=None, ge=0, le=100, description="Calculated multi-factor risk score")
    confidence: Optional[int] = Field(default=None, ge=0, le=100, alias="confidence_score", description="ML threat confidence score")


class AttackChain(BaseModel):
    """
    Canonical representation of a correlated multi-stage cyber attack chain.
    Supports the exact Milestone 3 specification structure:
    {
      "attack_chain_id": "AC-001",
      "events": ["EVT00012", "EVT00034", "EVT00089", "EVT00104"],
      "techniques": ["T1110", "T1078", "T1021", "T1041"],
      "stage": "Data Exfiltration",
      "risk_score": 94,
      "confidence": 89
    }
    """
    model_config = ConfigDict(populate_by_name=True)

    attack_chain_id: str = Field(..., description="Deterministic attack chain identifier (e.g. 'AC-001' or 'AC-a1b2c3d4')")
    name: Optional[str] = Field(default=None, description="Descriptive title of the attack campaign")
    events: List[str] = Field(..., description="Array of correlated event_id strings in chronological sequence")
    techniques: List[str] = Field(default_factory=list, description="List of unique MITRE ATT&CK technique IDs observed")
    stages: List[str] = Field(default_factory=list, description="Chronological sequence of distinct attack stages detected")
    stage: str = Field(..., description="Current or highest-severity progression stage reached in the kill chain")
    risk_score: int = Field(..., ge=0, le=100, description="Composite multi-factor risk score for the attack chain")
    confidence: int = Field(..., ge=0, le=100, description="Overall threat confidence rating for the correlated chain")

    # Contextual metadata
    correlation_rules: List[str] = Field(default_factory=list, description="Correlation rules satisfied (Rule 1, Rule 2, Rule 3, Rule 4)")
    affected_asset: Optional[str] = Field(default=None, description="Primary asset targeted by the attack chain")
    target_user: Optional[str] = Field(default=None, description="Primary user account targeted or compromised")
    source_ip: Optional[str] = Field(default=None, description="Originating IP address of the attack activity")
    event_details: Optional[List[CorrelatedEventSummary]] = Field(default=None, description="Detailed summaries of participating events")
    created_at: Optional[Any] = Field(default=None, description="UTC ISO timestamp of attack chain detection")


class CorrelationResult(BaseModel):
    """
    Output model containing detected attack chains and correlation metrics.
    """
    total_events_analyzed: int = Field(..., description="Total input security events evaluated")
    suspicious_events_count: int = Field(..., description="Count of events flagged as suspicious/threats")
    attack_chains_count: int = Field(..., description="Total correlated attack chains formed")
    attack_chains: List[AttackChain] = Field(default_factory=list, description="List of detected attack chains")
    correlated_event_ids: List[str] = Field(default_factory=list, description="Unique set of all event IDs clustered into attack chains")
    isolated_event_ids: List[str] = Field(default_factory=list, description="Event IDs that did not correlate into multi-event chains")
