"""
backend/app/schemas/incident.py

Milestone 3 — Step 4: Incident Management & Recommendation Schemas

Defines Pydantic models for SOC security incidents, lifecycle status transitions,
and prescriptive analyst mitigation recommendations.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, model_validator


class IncidentStatus(str, Enum):
    """
    Standard Milestone 3 Incident Lifecycle States.
    Lifecycle: Open -> Investigating -> Resolved (or terminal False Positive).
    """
    OPEN = "Open"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    FALSE_POSITIVE = "False Positive"


class RecommendationItem(BaseModel):
    """
    Individual prescriptive analyst recommendation with actionable guidance and category.
    """
    action: str = Field(..., description="Prescriptive analyst action description")
    category: Optional[str] = Field(default="Containment", description="Action phase ('Immediate Containment', 'Investigation', 'Remediation')")
    rationale: Optional[str] = Field(default=None, description="Security rationale for recommendation")


class AnalystFeedback(BaseModel):
    """
    Dedicated analyst assessment distinguishing True Positive from False Positive.
    Preserved per incident; not automatically fed into model retraining.
    """
    label: str = Field(..., description="Analyst evaluation ('True Positive' or 'False Positive')")
    submitted_at: str = Field(..., description="UTC ISO timestamp of feedback submission")
    analyst: Optional[str] = Field(default="SOC Analyst", description="Analyst username who submitted feedback")
    comment: Optional[str] = Field(default=None, description="Optional triage notes or justification")

    @model_validator(mode="after")
    def validate_feedback_label(self) -> "AnalystFeedback":
        clean_lbl = str(self.label).strip()
        if clean_lbl not in {"True Positive", "False Positive"}:
            raise ValueError(f"Invalid feedback label: '{self.label}'. Supported labels are: 'True Positive', 'False Positive'.")
        self.label = clean_lbl
        return self


class IncidentFeedbackRequest(BaseModel):
    """
    Request schema for submitting analyst True/False Positive feedback on an incident.
    """
    label: str = Field(..., description="Analyst evaluation ('True Positive' or 'False Positive')")
    comment: Optional[str] = Field(default=None, description="Optional triage notes or justification")
    analyst: Optional[str] = Field(default=None, description="Optional submitting analyst username")

    @model_validator(mode="after")
    def validate_feedback_label(self) -> "IncidentFeedbackRequest":
        clean_lbl = str(self.label).strip()
        if clean_lbl not in {"True Positive", "False Positive"}:
            raise ValueError(f"Invalid feedback label: '{self.label}'. Supported labels are: 'True Positive', 'False Positive'.")
        self.label = clean_lbl
        return self


class Incident(BaseModel):
    """
    Canonical representation of a Milestone 3 Security Incident.
    Corresponds to the `incidents` MongoDB collection document model.
    """
    model_config = ConfigDict(populate_by_name=True)

    incident_id: str = Field(..., description="Unique human-readable incident identifier (e.g. 'INC-2026-001')")
    title: str = Field(..., description="Concise summary title of the security incident")
    threat_type: str = Field(..., description="Primary threat category from M2 classification")
    risk_score: int = Field(..., ge=0, le=100, description="Multi-Factor Risk Score (0-100) preserved from M3 risk engine")
    risk_level: str = Field(..., description="5-tier risk hierarchy level ('Critical', 'High', 'Moderate', 'Medium', 'Low')")
    priority: Optional[str] = Field(
        default=None, 
        description="SOC Priority level. Note: Formal priority calculation stage is pending explicit specification."
    )
    affected_asset: Optional[str] = Field(default=None, description="Compromised or targeted asset hostname/ID")
    asset_id: Optional[str] = Field(default=None, description="Alias for affected_asset")
    affected_user: Optional[str] = Field(default=None, description="Targeted or compromised user account")
    username: Optional[str] = Field(default=None, description="Alias for affected_user")
    source_ip: Optional[str] = Field(default=None, description="Originating network IP address of threat activity")
    destination_ip: Optional[str] = Field(default=None, description="Target destination IP address")
    ml_confidence: Optional[int] = Field(default=None, ge=0, le=100, description="ML threat confidence score (0-100)")
    confidence_score: Optional[int] = Field(default=None, ge=0, le=100, description="Alias for ml_confidence")
    related_events: List[str] = Field(default_factory=list, description="Array of associated event_id strings")
    event_ids: List[str] = Field(default_factory=list, description="Alias for related_events")
    mitre_techniques: List[str] = Field(default_factory=list, description="List of associated MITRE technique IDs")
    mitre_technique: List[str] = Field(default_factory=list, description="Alias for mitre_techniques")
    ioc_status: Optional[str] = Field(default=None, description="Threat intelligence IoC match status ('Malicious', 'Clean', etc.)")
    attack_chain_id: Optional[str] = Field(default=None, description="Linked attack chain identifier if correlated")
    status: str = Field(default=IncidentStatus.OPEN.value, description="Lifecycle status ('Open', 'Investigating', 'Resolved', 'False Positive')")
    assigned_to: Optional[str] = Field(default=None, description="Assigned SOC analyst username")
    assignee: Optional[str] = Field(default=None, description="Alias for assigned_to")
    notes: Optional[str] = Field(default=None, description="Analyst triage or resolution notes")
    investigation_notes: Optional[str] = Field(default=None, description="Alias for notes")
    reasons: List[str] = Field(default_factory=list, description="Array of XAI explainability factors")
    recommendations: List[str] = Field(default_factory=list, description="Prescriptive analyst mitigation actions")
    feedback: Optional[AnalystFeedback] = Field(default=None, description="Dedicated analyst feedback ('True Positive' or 'False Positive')")
    created_at: str = Field(..., description="UTC ISO timestamp of incident creation")
    updated_at: str = Field(..., description="UTC ISO timestamp of latest status update")

    @model_validator(mode="before")
    @classmethod
    def sync_before(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "asset_id" in data and "affected_asset" not in data:
                data["affected_asset"] = data["asset_id"]
            if "username" in data and "affected_user" not in data:
                data["affected_user"] = data["username"]
            if "confidence_score" in data and "ml_confidence" not in data:
                data["ml_confidence"] = data["confidence_score"]
            if "event_ids" in data and "related_events" not in data:
                data["related_events"] = data["event_ids"]
            if "mitre_technique" in data and "mitre_techniques" not in data:
                data["mitre_techniques"] = data["mitre_technique"]
            if "assignee" in data and "assigned_to" not in data:
                data["assigned_to"] = data["assignee"]
            if "investigation_notes" in data and "notes" not in data:
                data["notes"] = data["investigation_notes"]
        return data

    @model_validator(mode="after")
    def sync_after(self) -> "Incident":
        if self.affected_asset and not self.asset_id:
            self.asset_id = self.affected_asset
        elif self.asset_id and not self.affected_asset:
            self.affected_asset = self.asset_id

        if self.affected_user and not self.username:
            self.username = self.affected_user
        elif self.username and not self.affected_user:
            self.affected_user = self.username

        if self.ml_confidence is not None and self.confidence_score is None:
            self.confidence_score = self.ml_confidence
        elif self.confidence_score is not None and self.ml_confidence is None:
            self.ml_confidence = self.confidence_score

        if self.related_events and not self.event_ids:
            self.event_ids = list(self.related_events)
        elif self.event_ids and not self.related_events:
            self.related_events = list(self.event_ids)

        if self.mitre_techniques and not self.mitre_technique:
            self.mitre_technique = list(self.mitre_techniques)
        elif self.mitre_technique and not self.mitre_techniques:
            self.mitre_techniques = list(self.mitre_technique)

        if self.assigned_to and not self.assignee:
            self.assignee = self.assigned_to
        elif self.assignee and not self.assigned_to:
            self.assigned_to = self.assignee

        if self.notes and not self.investigation_notes:
            self.investigation_notes = self.notes
        elif self.investigation_notes and not self.notes:
            self.notes = self.investigation_notes
        return self


class IncidentCreate(BaseModel):
    """
    Schema for creating a new incident document.
    """
    model_config = ConfigDict(populate_by_name=True)

    incident_id: Optional[str] = Field(default=None, description="Optional custom incident ID (auto-generated if omitted)")
    title: Optional[str] = Field(default=None, description="Incident summary title")
    threat_type: str = Field(default="Suspicious Activity", description="Primary threat category")
    risk_score: int = Field(..., ge=0, le=100, description="Multi-factor risk score preserved from risk engine")
    risk_level: str = Field(..., description="Risk level classification")
    priority: Optional[str] = Field(default=None, description="Optional priority string")
    affected_asset: Optional[str] = Field(default=None, alias="asset_id")
    affected_user: Optional[str] = Field(default=None, alias="username")
    source_ip: Optional[str] = Field(default=None)
    destination_ip: Optional[str] = Field(default=None)
    ml_confidence: Optional[int] = Field(default=None, ge=0, le=100, alias="confidence_score")
    related_events: List[str] = Field(default_factory=list, alias="event_ids")
    mitre_techniques: List[str] = Field(default_factory=list, alias="mitre_technique")
    ioc_status: Optional[str] = Field(default=None)
    attack_chain_id: Optional[str] = Field(default=None)
    status: str = Field(default=IncidentStatus.OPEN.value)
    assigned_to: Optional[str] = Field(default=None)
    assignee: Optional[str] = Field(default=None)
    notes: Optional[str] = Field(default=None)
    investigation_notes: Optional[str] = Field(default=None)
    reasons: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    feedback: Optional[AnalystFeedback] = Field(default=None)


class IncidentStatusUpdate(BaseModel):
    """
    Schema for updating an incident's lifecycle status, assignee, and investigation notes.
    """
    model_config = ConfigDict(populate_by_name=True)

    status: Optional[str] = Field(default=None, description="New lifecycle state ('Investigating', 'Resolved', 'False Positive')")
    assigned_to: Optional[str] = Field(default=None, description="Assignee username")
    assignee: Optional[str] = Field(default=None, description="Assignee username alias")
    notes: Optional[str] = Field(default=None, description="Analyst triage or resolution notes")
    investigation_notes: Optional[str] = Field(default=None, description="Analyst triage or resolution notes alias")

    @model_validator(mode="before")
    @classmethod
    def sync_inputs(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "assignee" in data and "assigned_to" not in data:
                data["assigned_to"] = data["assignee"]
            elif "assigned_to" in data and "assignee" not in data:
                data["assignee"] = data["assigned_to"]

            if "investigation_notes" in data and "notes" not in data:
                data["notes"] = data["investigation_notes"]
            elif "notes" in data and "investigation_notes" not in data:
                data["investigation_notes"] = data["notes"]
        return data


class IncidentRecommendationResponse(BaseModel):
    """
    Response schema returning prescriptive analyst recommendations for an incident.
    """
    incident_id: str = Field(..., description="Identifier of the incident evaluated")
    threat_type: str = Field(..., description="Threat category")
    risk_level: str = Field(..., description="Incident risk level")
    priority: Optional[str] = Field(default=None, description="Priority string")
    recommendations: List[str] = Field(default_factory=list, description="Prescriptive analyst guidance strings")
    structured_recommendations: Optional[List[RecommendationItem]] = Field(
        default=None, 
        description="Structured recommendations with category classifications"
    )
