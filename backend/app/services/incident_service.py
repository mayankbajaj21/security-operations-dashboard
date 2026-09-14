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
    AnalystFeedback,
    map_risk_level_to_priority
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
            priority=map_risk_level_to_priority(risk_level),
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

        incident = self._enrich_incident_m4(incident)
        return self.save_incident(incident)

    def _enrich_incident_m4(self, incident: Incident) -> Incident:
        """
        Milestone 4 — Module 4.3, Task 4: Authoritative Threat Investigation Enrichment.
        
        DATA INTEGRITY RULES:
        1. Traceable correlation:
           Incident -> established related_events -> security_events / threat_predictions / vulnerabilities -> authoritative data.
        2. Zero hardcoded server names:
           Critical asset must reuse authoritative M3 asset criticality or M3 reason explanation.
        3. Authoritative CVE/CVSS:
           Resolve CVE/CVSS strictly from established related events / M3 vulnerability data.
           If unassociated, return None (displayed as 'N/A' in frontend).
        4. Authoritative ML confidence:
           Resolve from established related event and M2 prediction. If unassociated, return None.
        5. 6 M3 Risk Factors:
           Derive structurally from authoritative M3 calculation results and reasons.
        """
        related_events = incident.related_events or incident.event_ids or []
        primary_evt = None
        primary_pred = None
        asset_crit = None

        if self.db is not None and related_events:
            try:
                primary_evt = self.db["security_events"].find_one({"event_id": {"$in": related_events}})
            except Exception as e:
                logger.warning(f"Failed to query security_events for incident {incident.incident_id}: {e}")

        if primary_evt:
            # Resolve primary prediction from M2 threat_predictions
            if self.db is not None:
                try:
                    primary_pred = self.db["threat_predictions"].find_one({"event_id": primary_evt["event_id"]})
                except Exception as e:
                    logger.warning(f"Failed to query threat_predictions for {primary_evt['event_id']}: {e}")

            # Correlated CVE ID
            if not incident.cve_id:
                if primary_evt.get("cve_id"):
                    incident.cve_id = str(primary_evt["cve_id"]).strip()
                elif primary_evt.get("vulnerability_id") and str(primary_evt["vulnerability_id"]).strip().startswith("CVE-"):
                    incident.cve_id = str(primary_evt["vulnerability_id"]).strip()

            # Correlated CVSS Score
            if incident.cvss_score is None:
                if primary_evt.get("cvss_score") is not None:
                    try:
                        incident.cvss_score = float(primary_evt["cvss_score"])
                    except (ValueError, TypeError):
                        pass
                elif primary_evt.get("raw_cvss_score") is not None:
                    try:
                        incident.cvss_score = float(primary_evt["raw_cvss_score"])
                    except (ValueError, TypeError):
                        pass

                # If still None but we have a valid correlated cve_id, check M3 vulnerabilities collection
                if incident.cvss_score is None and incident.cve_id and self.db is not None:
                    try:
                        vuln_doc = self.db["vulnerabilities"].find_one({"cve_id": incident.cve_id})
                        if vuln_doc and vuln_doc.get("cvss_score") is not None:
                            incident.cvss_score = float(vuln_doc["cvss_score"])
                    except Exception:
                        pass

            # ML Confidence
            if incident.ml_confidence is None and primary_pred and primary_pred.get("confidence_score") is not None:
                try:
                    incident.ml_confidence = int(primary_pred["confidence_score"])
                    incident.confidence_score = incident.ml_confidence
                except (ValueError, TypeError):
                    pass

            # Fill missing telemetry fields if absent on incident
            if not incident.source_ip and primary_evt.get("source_ip"):
                incident.source_ip = primary_evt["source_ip"]
            if not incident.affected_user and primary_evt.get("username"):
                incident.affected_user = primary_evt["username"]
                incident.username = primary_evt["username"]
            if not incident.affected_asset and primary_evt.get("asset_name"):
                incident.affected_asset = primary_evt["asset_name"]
                incident.asset_id = primary_evt["asset_name"]
            if not incident.mitre_techniques and primary_evt.get("mitre_id"):
                incident.mitre_techniques = [str(primary_evt["mitre_id"])]
                incident.mitre_technique = [str(primary_evt["mitre_id"])]

            asset_crit = primary_evt.get("asset_criticality")

        # Resolve asset criticality and department from authoritative M3 assets collection
        asset_key = str(incident.affected_asset or "").strip()
        ast_doc = None
        if asset_key and self.db is not None:
            if not hasattr(self, "_asset_cache"):
                self._asset_cache = {}
            if asset_key in self._asset_cache:
                ast_doc = self._asset_cache[asset_key]
            else:
                try:
                    ast_doc = self.db["assets"].find_one({
                        "$or": [
                            {"asset_name": asset_key},
                            {"asset_id": asset_key}
                        ]
                    })
                    self._asset_cache[asset_key] = ast_doc
                except Exception:
                    pass

        if ast_doc:
            if not asset_crit and ast_doc.get("criticality"):
                asset_crit = ast_doc["criticality"]
            if not incident.department and ast_doc.get("department"):
                incident.department = str(ast_doc["department"]).strip()

        # If still unassigned, resolve from authoritative security event telemetry
        if not incident.department and primary_evt:
            evt_dept = primary_evt.get("department") or primary_evt.get("asset_department")
            if evt_dept and str(evt_dept).strip() and str(evt_dept).strip().lower() not in ("none", "n/a", "unknown"):
                incident.department = str(evt_dept).strip()

        # If asset has no authoritative department, it remains None / N/A. DO NOT default to 'IT'.

        # Evaluate the 6 M3 Risk Factors strictly reusing authoritative M3 logic
        reasons_lower = [str(r).lower() for r in (incident.reasons or [])]
        threat_type_str = str(incident.threat_type or "").lower()
        ioc_status_str = str(incident.ioc_status or "").lower()

        # 1. Critical asset: authoritative M3 criticality or M3 explanation (NO hardcoded server names)
        crit_asset = (
            any("critical business impact" in r for r in reasons_lower) or
            (asset_crit is not None and str(asset_crit).strip().lower() == "critical")
        )

        # 2. High ML confidence: M3 threshold >= 80 or M3 explanation
        conf_val = incident.ml_confidence if incident.ml_confidence is not None else incident.confidence_score
        high_conf = (
            any("high ml threat confidence" in r for r in reasons_lower) or
            (conf_val is not None and conf_val >= 80)
        )

        # 3. Malicious IOC: M3 threat intel factor or status
        mal_ioc = (
            any("indicator of compromise" in r for r in reasons_lower) or
            ioc_status_str in ("malicious", "hit", "true")
        )

        # 4. High CVSS: M3 threshold >= 7.0 (norm_vulnerability >= 70.0) or M3 explanation
        cvss_val = incident.cvss_score
        high_cvss = (
            any("high active vulnerability exposure" in r for r in reasons_lower) or
            (cvss_val is not None and float(cvss_val) >= 7.0)
        )

        # 5. Multiple related events: len(related_events) > 1
        multi_events = len(related_events) > 1

        # 6. Ransomware behavior detected: threat_type or explanation
        ransomware_detected = (
            "ransomware" in threat_type_str or
            any("ransomware" in r for r in reasons_lower)
        )

        incident.risk_factors = {
            "critical_asset": bool(crit_asset),
            "high_ml_confidence": bool(high_conf),
            "malicious_ioc": bool(mal_ioc),
            "high_cvss": bool(high_cvss),
            "multiple_related_events": bool(multi_events),
            "ransomware_behavior_detected": bool(ransomware_detected)
        }

        if not incident.severity:
            incident.severity = incident.risk_level or "Low"

        # Generate XAI reasons if missing
        if not incident.reasons:
            try:
                from backend.app.services.risk_engine import (
                    normalize_threat_severity, normalize_ml_confidence,
                    normalize_asset_criticality, normalize_vulnerability_risk,
                    normalize_threat_intel, RiskScoringEngine
                )
                norm_sev = normalize_threat_severity(incident.risk_level)
                norm_conf = normalize_ml_confidence(conf_val or 0.0)
                norm_crit = normalize_asset_criticality(asset_crit or "Low")
                norm_vuln = normalize_vulnerability_risk(incident.cvss_score or 0.0)
                norm_intel = normalize_threat_intel(incident.ioc_status or False)
                incident.reasons = RiskScoringEngine._generate_reasons(
                    norm_severity=norm_sev,
                    norm_confidence=norm_conf,
                    norm_criticality=norm_crit,
                    norm_vulnerability=norm_vuln,
                    norm_threat_intel=norm_intel,
                    severity_raw=incident.risk_level,
                    confidence_raw=conf_val,
                    criticality_raw=asset_crit,
                    cvss_raw=incident.cvss_score,
                    asset_name=incident.affected_asset,
                    anomaly_score=None,
                    existing_reasons=[]
                )
            except Exception:
                pass

        return incident

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
                    return self._enrich_incident_m4(Incident(**doc))
            except PyMongoError as e:
                logger.error(f"Failed to query MongoDB for incident {clean_id}: {e}")

        raw_mem = self._in_memory_store.get(clean_id)
        if raw_mem:
            return self._enrich_incident_m4(Incident(**raw_mem))

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
                    incidents.append(self._enrich_incident_m4(Incident(**doc)))
                return incidents
            except PyMongoError as e:
                logger.error(f"Failed to list incidents from MongoDB: {e}")

        # In-memory fallback
        for doc in self._in_memory_store.values():
            if not status or doc.get("status") == str(status).strip():
                incidents.append(self._enrich_incident_m4(Incident(**doc)))

        return incidents[offset:offset + limit]
