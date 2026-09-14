"""
backend/app/services/incident_service.py

Milestone 3 — Step 4: Incident Management Service Module

Manages the lifecycle, creation, MongoDB persistence, and status state machine for
the `incidents` collection in the `security_operations` database.

LIFECYCLE STATE MACHINE:
    Open -> Investigating -> Resolved
    (with terminal transition to False Positive from Open or Investigating)

PRIORITY HANDLING:
    The `priority` field is preserved in the Incident model as `None`.
    Per specification rules, no unapproved P1-P4 formula is fabricated.
"""

from datetime import datetime, timezone
import hashlib
import logging
from typing import Dict, Any, List, Optional, Set, Union
from pymongo.database import Database
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database, check_database_connection
from backend.app.schemas.incident import (
    Incident,
    IncidentCreate,
    IncidentStatus,
    IncidentStatusUpdate,
    AnalystFeedback
)
from backend.app.schemas.risk import RiskCalculateResponse
from backend.app.schemas.correlation import AttackChain
from backend.app.services.recommendation_service import RecommendationService
from backend.app.services.risk_engine import classify_risk_level

logger = logging.getLogger("IncidentService")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

COLLECTION_NAME = "incidents"

# Canonical Milestone 3 Incident Lifecycle Transitions
VALID_LIFECYCLE_TRANSITIONS: Dict[str, Set[str]] = {
    IncidentStatus.OPEN.value: {
        IncidentStatus.INVESTIGATING.value,
        IncidentStatus.FALSE_POSITIVE.value
    },
    IncidentStatus.INVESTIGATING.value: {
        IncidentStatus.RESOLVED.value,
        IncidentStatus.FALSE_POSITIVE.value
    },
    IncidentStatus.RESOLVED.value: {
        IncidentStatus.INVESTIGATING.value   # Reopen Investigation
    },
    IncidentStatus.FALSE_POSITIVE.value: {
        IncidentStatus.INVESTIGATING.value   # Reopen Investigation
    }
}


def validate_status_transition(current_status: str, new_status: str) -> None:
    """
    Validates whether a lifecycle status transition is permitted under M3 rules.
    Raises ValueError on invalid transitions.
    """
    c_stat = str(current_status).strip()
    n_stat = str(new_status).strip()

    if c_stat == n_stat:
        return  # No-op transition permitted

    allowed = VALID_LIFECYCLE_TRANSITIONS.get(c_stat)
    if allowed is None:
        raise ValueError(f"Unknown current incident status: '{c_stat}'")

    if n_stat not in allowed:
        raise ValueError(
            f"Invalid incident lifecycle transition: '{c_stat}' -> '{n_stat}'. "
            f"Allowed transitions from '{c_stat}': {sorted(list(allowed)) or 'None (Terminal State)'}"
        )


def generate_deterministic_incident_id(event_ids: List[str], index: Optional[int] = None) -> str:
    """
    Generates a deterministic incident identifier.
    If an index is provided, formats as 'INC-2026-001'.
    Otherwise, generates an 8-character hex digest from sorted event IDs: 'INC-A1B2C3D4'.
    """
    if index is not None and index > 0:
        return f"INC-2026-{index:03d}"

    sorted_ids = ",".join(sorted(event_ids or ["GENERIC"]))
    digest = hashlib.sha256(sorted_ids.encode("utf-8")).hexdigest()[:8].upper()
    return f"INC-{digest}"


class IncidentService:
    """
    Service layer providing Incident creation, retrieval, MongoDB storage,
    and lifecycle management.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = None
        self._in_memory_store: Dict[str, Dict[str, Any]] = {}

        if db is not None:
            self.db = db
            self.collection = self.db[COLLECTION_NAME]
        else:
            try:
                is_healthy, _ = check_database_connection()
                if is_healthy:
                    self.db = get_database()
                    self.collection = self.db[COLLECTION_NAME]
            except Exception as e:
                logger.warning(f"MongoDB not connected. Operating in in-memory mode: {e}")

    def create_incident_from_risk(
        self,
        risk_result: Union[RiskCalculateResponse, Dict[str, Any]],
        event_telemetry: Optional[Dict[str, Any]] = None,
        attack_chain: Optional[AttackChain] = None,
        index: Optional[int] = None
    ) -> Incident:
        """
        Constructs and persists a new Incident document from an M3 risk result and contextual telemetry.
        """
        evt = event_telemetry or {}

        # 1. Extract risk score and level directly from M3 risk result
        if isinstance(risk_result, RiskCalculateResponse):
            risk_score = risk_result.risk_score
            risk_level = risk_result.risk_level
            threat_type = risk_result.threat_type or evt.get("threat_type", "Suspicious Activity")
            reasons = list(risk_result.reasons)
            primary_event_id = risk_result.event_id
        elif isinstance(risk_result, dict):
            risk_score = int(risk_result.get("risk_score", 0))
            risk_level = classify_risk_level(risk_score)
            threat_type = str(risk_result.get("threat_type", evt.get("threat_type", "Suspicious Activity")))
            reasons = list(risk_result.get("reasons", []))
            primary_event_id = str(risk_result.get("event_id", "EVT_UNKNOWN"))
        else:
            raise ValueError(f"Unsupported risk_result type: {type(risk_result)}")

        # 2. Determine participating events and attack chain metadata
        if attack_chain:
            related_events = list(attack_chain.events)
            mitre_techniques = list(attack_chain.techniques)
            attack_chain_id = attack_chain.attack_chain_id
            affected_asset = attack_chain.affected_asset or evt.get("asset_name", evt.get("asset_id"))
            affected_user = attack_chain.target_user or evt.get("username", evt.get("user_id"))
            source_ip = attack_chain.source_ip or evt.get("source_ip")
            ml_confidence = attack_chain.confidence
        else:
            related_events = [primary_event_id] if primary_event_id else []
            raw_mitre = evt.get("mitre_id")
            mitre_techniques = [str(raw_mitre)] if raw_mitre and str(raw_mitre).lower() != "none" else []
            attack_chain_id = None
            affected_asset = evt.get("asset_name", evt.get("asset_id"))
            affected_user = evt.get("username", evt.get("user_id"))
            source_ip = evt.get("source_ip")
            ml_confidence = evt.get("confidence_score", evt.get("ml_confidence"))

        destination_ip = evt.get("destination_ip")
        ioc_status = "Malicious" if (evt.get("threat_intel_match") is True or str(evt.get("ioc_status")).lower() == "malicious") else "Clean"

        # 3. Generate Prescriptive Analyst Recommendations
        recommendations = RecommendationService.get_recommendations(
            threat_type=threat_type,
            asset_criticality=evt.get("asset_criticality", evt.get("criticality")),
            ioc_status=ioc_status,
            attack_chain_id=attack_chain_id
        )

        # 4. Generate Deterministic Incident ID
        incident_id = generate_deterministic_incident_id(related_events, index=index)

        # 5. Build Descriptive Title
        asset_label = str(affected_asset).strip() if affected_asset else "Infrastructure"
        title = f"{threat_type} Alert on {asset_label}"
        if attack_chain:
            title = f"Correlated {threat_type} Attack Campaign on {asset_label}"

        now_utc = datetime.now(timezone.utc).isoformat()

        incident = Incident(
            incident_id=incident_id,
            title=title,
            threat_type=threat_type,
            risk_score=risk_score,
            risk_level=risk_level,
            priority=None,  # Preserved as None (formal priority formula pending)
            affected_asset=affected_asset,
            affected_user=affected_user,
            source_ip=source_ip,
            destination_ip=destination_ip,
            ml_confidence=int(ml_confidence) if ml_confidence is not None else None,
            related_events=related_events,
            mitre_techniques=mitre_techniques,
            ioc_status=ioc_status,
            attack_chain_id=attack_chain_id,
            status=IncidentStatus.OPEN.value,
            assigned_to=None,
            reasons=reasons,
            recommendations=recommendations,
            created_at=evt.get("timestamp") or now_utc,
            updated_at=now_utc
        )

        return self.save_incident(incident)

    def save_incident(self, incident: Incident) -> Incident:
        """
        Saves or updates an incident document in MongoDB (or in-memory store fallback).
        """
        doc = incident.model_dump(by_alias=True)

        if self.db is not None and hasattr(self, "collection"):
            try:
                self.collection.replace_one(
                    {"incident_id": incident.incident_id},
                    doc,
                    upsert=True
                )
            except PyMongoError as e:
                logger.error(f"Failed to persist incident in MongoDB: {e}")
                self._in_memory_store[incident.incident_id] = doc
        else:
            self._in_memory_store[incident.incident_id] = doc

        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """
        Retrieves a single incident by its unique ID.
        """
        if not incident_id:
            return None

        clean_id = str(incident_id).strip()

        if self.db is not None and hasattr(self, "collection"):
            try:
                doc = self.collection.find_one({"incident_id": clean_id}, {"_id": 0})
                if doc:
                    return Incident(**doc)
            except PyMongoError as e:
                logger.error(f"Failed to query MongoDB for incident {clean_id}: {e}")

        raw_mem = self._in_memory_store.get(clean_id)
        if raw_mem:
            return Incident(**raw_mem)

        return None

    def update_incident_status(
        self,
        incident_id: str,
        new_status: Optional[str] = None,
        assigned_to: Optional[str] = None,
        notes: Optional[str] = None
    ) -> Incident:
        """
        Updates an incident's lifecycle status, assignee, and investigation notes.
        Enforces valid state machine transitions when status is modified.
        """
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        now_utc = datetime.now(timezone.utc).isoformat()

        if new_status is not None and str(new_status).strip():
            clean_status = str(new_status).strip()
            if clean_status != incident.status:
                validate_status_transition(incident.status, clean_status)
                incident.status = clean_status

        if assigned_to is not None:
            clean_assigned = str(assigned_to).strip()
            incident.assigned_to = clean_assigned if clean_assigned else None

        if notes is not None:
            clean_notes = str(notes).strip()
            incident.notes = clean_notes if clean_notes else None

        incident.updated_at = now_utc
        return self.save_incident(incident)

    def submit_feedback(
        self,
        incident_id: str,
        label: str,
        comment: Optional[str] = None,
        analyst: Optional[str] = None
    ) -> Incident:
        """
        Records dedicated analyst feedback (True Positive / False Positive) for a specific incident.
        Strictly isolated per incident document.
        Does not trigger model retraining or force status transitions.
        """
        incident = self.get_incident(incident_id)
        if not incident:
            raise KeyError(f"Incident with ID '{incident_id}' not found.")

        clean_label = str(label).strip()
        if clean_label not in {"True Positive", "False Positive"}:
            raise ValueError(f"Invalid feedback label: '{clean_label}'. Must be 'True Positive' or 'False Positive'.")

        now_utc = datetime.now(timezone.utc).isoformat()
        feedback_obj = AnalystFeedback(
            label=clean_label,
            submitted_at=now_utc,
            analyst=str(analyst).strip() if analyst else (incident.assigned_to or "SOC Analyst"),
            comment=str(comment).strip() if comment else None
        )

        incident.feedback = feedback_obj
        incident.updated_at = now_utc
        return self.save_incident(incident)

    def list_incidents(
        self,
        status: Optional[str] = None,
        limit: int = 20,
        offset: int = 0
    ) -> List[Incident]:
        """
        Lists stored incidents with optional lifecycle status filtering.
        """
        incidents: List[Incident] = []
        filter_query: Dict[str, Any] = {}
        if status and str(status).strip():
            filter_query["status"] = str(status).strip()

        if self.db is not None and hasattr(self, "collection"):
            try:
                cursor = self.collection.find(filter_query, {"_id": 0}).skip(offset).limit(limit)
                for doc in cursor:
                    incidents.append(Incident(**doc))
                return incidents
            except PyMongoError as e:
                logger.error(f"Failed to list incidents from MongoDB: {e}")

        # In-memory fallback
        for doc in self._in_memory_store.values():
            if not status or doc.get("status") == str(status).strip():
                incidents.append(Incident(**doc))

        return incidents[offset:offset + limit]
