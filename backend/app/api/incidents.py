"""
backend/app/api/incidents.py

Milestone 3 — Step 5: Incident Management & Recommendations REST API Router

Provides REST API endpoints for querying, creating, updating lifecycle status,
and retrieving prescriptive analyst recommendations for security incidents.
"""

import math
from datetime import datetime
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

from backend.app.schemas.incident import (
    Incident,
    IncidentStatusUpdate,
    IncidentFeedbackRequest,
    IncidentRecommendationResponse,
    RecommendationItem
)
from backend.app.services.incident_service import IncidentService
from backend.app.services.recommendation_service import RecommendationService

# Router with empty prefix when mounted directly or prefix="/incidents"
router = APIRouter(tags=["Incidents"])

incident_service = IncidentService()


@router.get("/incidents/summary", status_code=status.HTTP_200_OK)
def get_incidents_summary() -> dict:
    """
    Computes macro aggregate statistics and lifecycle status distributions for M3 incidents directly from MongoDB.
    Powers the SOC Overview Dashboard KPI cards (Active Incidents, High Risk Incidents) and Threat Status distribution.
    """
    try:
        all_incidents = incident_service.list_incidents(limit=10000, offset=0)
        
        by_status = {"Open": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}
        by_risk_level = {"Critical": 0, "High": 0, "Moderate": 0, "Medium": 0, "Low": 0}
        by_priority = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
        affected_assets_set = set()

        for inc in all_incidents:
            st = str(inc.status).strip()
            if st in by_status:
                by_status[st] += 1
            else:
                by_status[st] = 1

            rl = str(inc.risk_level).strip().capitalize() if inc.risk_level else "Low"
            if rl in by_risk_level:
                by_risk_level[rl] += 1
            else:
                by_risk_level[rl] = 1

            pr = str(inc.priority).strip().upper() if inc.priority else None
            if pr in by_priority:
                by_priority[pr] += 1

            if inc.affected_asset and str(inc.affected_asset).strip():
                affected_assets_set.add(str(inc.affected_asset).strip())

        active_incidents = by_status.get("Open", 0) + by_status.get("Investigating", 0)
        high_risk_incidents = by_risk_level.get("Critical", 0) + by_risk_level.get("High", 0)

        return {
            "total_incidents": len(all_incidents),
            "active_incidents": active_incidents,
            "high_risk_incidents": high_risk_incidents,
            "affected_assets_count": len(affected_assets_set),
            "by_status": by_status,
            "by_risk_level": by_risk_level,
            "by_priority": by_priority
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate incidents summary: {str(e)}"
        )


@router.get("/incidents/filters", status_code=status.HTTP_200_OK)
def get_incident_filter_options() -> dict:
    """
    Milestone 4 — Task 9: Distinct filter options dynamically derived from authoritative incident data.
    Provides options for:
    1. Severity
    2. Risk Level
    3. Threat Type
    4. Asset
    5. Department
    6. MITRE Technique
    7. CVE
    8. IOC Status
    9. Incident Status
    10. Date Range (min/max timestamps)
    """
    try:
        all_incidents = incident_service.list_incidents(limit=10000, offset=0)
        
        severities = sorted(list(set(str(i.severity or i.risk_level).strip() for i in all_incidents if i.severity or i.risk_level)))
        risk_levels = ["Critical", "High", "Moderate", "Medium", "Low"]
        threat_types = sorted(list(set(str(i.threat_type).strip() for i in all_incidents if i.threat_type)))
        assets = sorted(list(set(str(i.affected_asset).strip() for i in all_incidents if i.affected_asset)))
        auth_departments = set()
        has_unknown_dept = False
        for i in all_incidents:
            d_val = str(i.department).strip() if i.department else ""
            if d_val and d_val.lower() not in ("none", "n/a", "unknown"):
                auth_departments.add(d_val)
            else:
                has_unknown_dept = True

        departments = sorted(list(auth_departments))
        if has_unknown_dept:
            departments.append("Unknown")

        mitre_techs = sorted(list(set(t for i in all_incidents for t in (i.mitre_techniques or []))))
        cves = sorted(list(set(str(i.cve_id).strip() for i in all_incidents if i.cve_id)))
        ioc_statuses = sorted(list(set(str(i.ioc_status).strip() for i in all_incidents if i.ioc_status)))
        statuses = ["Open", "Investigating", "Resolved", "False Positive"]

        timestamps = [i.created_at for i in all_incidents if i.created_at]
        min_date = min(timestamps)[:10] if timestamps else "2025-01-01"
        max_date = max(timestamps)[:10] if timestamps else "2026-12-31"

        return {
            "severities": severities or ["Critical", "High", "Medium", "Low"],
            "risk_levels": risk_levels,
            "threat_types": threat_types,
            "assets": assets,
            "departments": departments,
            "mitre_techniques": mitre_techs,
            "cves": cves,
            "ioc_statuses": ioc_statuses or ["Malicious", "Suspicious", "Clean"],
            "incident_statuses": statuses,
            "statuses": statuses,
            "date_range": {
                "min": min_date,
                "max": max_date
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load filter options: {str(e)}"
        )


@router.get("/incidents", status_code=status.HTTP_200_OK)
def list_incidents(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    # Milestone 4 — Task 9: EXACT 10 FILTERS
    severity: Optional[str] = Query(default=None, description="1. Filter by severity ('Critical', 'High', 'Medium', 'Low')"),
    risk_level: Optional[str] = Query(default=None, description="2. Filter by risk level ('Critical', 'High', 'Moderate', 'Medium', 'Low')"),
    threat_type: Optional[str] = Query(default=None, description="3. Filter by threat type category"),
    asset: Optional[str] = Query(default=None, description="4. Filter by affected asset name"),
    department: Optional[str] = Query(default=None, description="5. Filter by affected asset department"),
    mitre_technique: Optional[str] = Query(default=None, description="6. Filter by MITRE technique ID"),
    cve: Optional[str] = Query(default=None, description="7. Filter by CVE identifier"),
    ioc_status: Optional[str] = Query(default=None, description="8. Filter by IOC status ('Malicious', 'Clean', etc.)"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="9. Filter by incident status ('Open', 'Investigating', 'Resolved', 'False Positive')"),
    start_date: Optional[str] = Query(default=None, description="10a. Date range filter start (YYYY-MM-DD)"),
    end_date: Optional[str] = Query(default=None, description="10b. Date range filter end (YYYY-MM-DD)")
) -> dict:
    """
    Retrieves a paginated list of security incidents with Milestone 4 Task 9 10-field multi-filtering.
    """
    try:
        all_incidents = incident_service.list_incidents(status=status_filter, limit=1000, offset=0)

        filtered = all_incidents

        # 1. Severity filter
        if severity and str(severity).strip() and str(severity).lower() != "all":
            s_target = str(severity).strip().lower()
            filtered = [i for i in filtered if (i.severity and i.severity.lower() == s_target) or (i.risk_level and i.risk_level.lower() == s_target)]

        # 2. Risk Level filter
        if risk_level and str(risk_level).strip() and str(risk_level).lower() != "all":
            r_target = str(risk_level).strip().lower()
            filtered = [i for i in filtered if i.risk_level and i.risk_level.lower() == r_target]

        # 3. Threat Type filter
        if threat_type and str(threat_type).strip() and str(threat_type).lower() != "all":
            t_target = str(threat_type).strip().lower()
            filtered = [i for i in filtered if i.threat_type and i.threat_type.lower() == t_target]

        # 4. Asset filter
        if asset and str(asset).strip() and str(asset).lower() != "all":
            a_target = str(asset).strip().lower()
            filtered = [i for i in filtered if i.affected_asset and a_target in i.affected_asset.lower()]

        # 5. Department filter
        if department and str(department).strip() and str(department).lower() != "all":
            d_target = str(department).strip().lower()
            if d_target in ("unknown", "n/a", "none"):
                filtered = [i for i in filtered if not i.department or str(i.department).strip().lower() in ("unknown", "n/a", "none")]
            else:
                filtered = [i for i in filtered if i.department and d_target in str(i.department).strip().lower()]

        # 6. MITRE Technique filter
        if mitre_technique and str(mitre_technique).strip() and str(mitre_technique).lower() != "all":
            m_target = str(mitre_technique).strip().lower()
            filtered = [i for i in filtered if any(m_target in t.lower() for t in (i.mitre_techniques or []))]

        # 7. CVE filter
        if cve and str(cve).strip() and str(cve).lower() != "all":
            c_target = str(cve).strip().lower()
            filtered = [i for i in filtered if i.cve_id and c_target in i.cve_id.lower()]

        # 8. IOC Status filter
        if ioc_status and str(ioc_status).strip() and str(ioc_status).lower() != "all":
            ioc_target = str(ioc_status).strip().lower()
            filtered = [i for i in filtered if i.ioc_status and ioc_target in i.ioc_status.lower()]

        # 9. Incident Status filter (already checked in list_incidents, but double check if passed via alias)
        if status_filter and str(status_filter).strip() and str(status_filter).lower() != "all":
            st_target = str(status_filter).strip().lower()
            filtered = [i for i in filtered if i.status and i.status.lower() == st_target]

        # 10. Date Range filter (start_date, end_date)
        if start_date and str(start_date).strip():
            s_d = str(start_date).strip()[:10]
            filtered = [i for i in filtered if (i.created_at and i.created_at[:10] >= s_d)]

        if end_date and str(end_date).strip():
            e_d = str(end_date).strip()[:10]
            filtered = [i for i in filtered if (i.created_at and i.created_at[:10] <= e_d)]

        total = len(filtered)
        total_pages = max(1, math.ceil(total / limit)) if total > 0 else 1
        offset = (page - 1) * limit
        
        formatted_data = []
        for item in filtered[offset:offset + limit]:
            idict = item.model_dump() if hasattr(item, "model_dump") else item
            idict["asset_id"] = idict.get("affected_asset") or idict.get("asset_id")
            idict["affected_asset"] = idict.get("asset_id") or idict.get("affected_asset")
            idict["username"] = idict.get("affected_user") or idict.get("username")
            idict["affected_user"] = idict.get("username") or idict.get("affected_user")
            idict["confidence_score"] = idict.get("ml_confidence") if idict.get("ml_confidence") is not None else idict.get("confidence_score")
            idict["ml_confidence"] = idict.get("confidence_score") if idict.get("confidence_score") is not None else idict.get("ml_confidence")
            idict["event_ids"] = idict.get("related_events") or idict.get("event_ids") or []
            idict["related_events"] = idict.get("event_ids") or idict.get("related_events") or []
            idict["mitre_technique"] = idict.get("mitre_techniques") or idict.get("mitre_technique") or []
            idict["mitre_techniques"] = idict.get("mitre_technique") or idict.get("mitre_techniques") or []
            idict["assignee"] = idict.get("assignee") or idict.get("assigned_to")
            idict["assigned_to"] = idict.get("assigned_to") or idict.get("assignee")
            idict["notes"] = idict.get("notes") or idict.get("investigation_notes")
            idict["investigation_notes"] = idict.get("investigation_notes") or idict.get("notes")
            formatted_data.append(idict)

        return {
            "data": formatted_data,
            "total": total,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query incidents: {str(e)}"
        )


@router.get("/incidents/{incident_id}", response_model=Incident, status_code=status.HTTP_200_OK)
def get_incident(incident_id: str) -> Incident:
    """
    Retrieves a single security incident document by its unique ID.
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )
    return incident


@router.patch("/incidents/{incident_id}/status", response_model=Incident, status_code=status.HTTP_200_OK)
def update_incident_status(incident_id: str, update: IncidentStatusUpdate) -> Incident:
    """
    Updates an incident's lifecycle status, enforcing strict state machine transitions.
    Allowed transitions:
        - Open -> Investigating
        - Investigating -> Resolved
        - Open or Investigating -> False Positive
    """
    try:
        return incident_service.update_incident_status(
            incident_id=incident_id,
            new_status=update.status,
            assigned_to=update.assigned_to,
            notes=update.notes
        )
    except KeyError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update incident status: {str(e)}"
        )


@router.post("/incidents/{incident_id}/feedback", response_model=Incident, status_code=status.HTTP_200_OK)
def submit_incident_feedback(incident_id: str, request: IncidentFeedbackRequest) -> Incident:
    """
    Submits dedicated analyst feedback (True Positive / False Positive) for a specific incident.
    Associates feedback strictly with the incident without modifying M2 model predictions or forcing lifecycle changes.
    """
    try:
        return incident_service.submit_feedback(
            incident_id=incident_id,
            label=request.label,
            comment=request.comment,
            analyst=request.analyst
        )
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to submit feedback: {str(e)}")


@router.get("/incidents/{incident_id}/recommendations", response_model=IncidentRecommendationResponse, status_code=status.HTTP_200_OK)
@router.get("/recommendations/{incident_id}", response_model=IncidentRecommendationResponse, status_code=status.HTTP_200_OK)
def get_incident_recommendations(incident_id: str) -> IncidentRecommendationResponse:
    """
    Milestone 4 — Task 11: Retrieves prescriptive M3 mitigation guidance for a specific incident.
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )

    structured_recs = RecommendationService.get_structured_recommendations(
        threat_type=incident.threat_type,
        asset_criticality=None,
        ioc_status=incident.ioc_status,
        attack_chain_id=incident.attack_chain_id
    )

    return IncidentRecommendationResponse(
        incident_id=incident.incident_id,
        threat_type=incident.threat_type,
        risk_level=incident.risk_level,
        priority=incident.priority,
        recommendations=incident.recommendations,
        structured_recommendations=structured_recs
    )


@router.get("/incidents/{incident_id}/attack-chain", status_code=status.HTTP_200_OK)
def get_incident_attack_chain(incident_id: str) -> dict:
    """
    Milestone 4 — Task 5: Dynamic Attack Chain for Threat Investigation.
    Exposes chronological attack stages derived authoritatively from incident related events,
    security events telemetry, and MITRE kill-chain mappings.
    Each stage exposes:
        - Event ID
        - Timestamp
        - Source
        - Destination
        - User
        - MITRE Technique
        - Risk
    """
    incident = incident_service.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found."
        )

    db = get_database()
    events_coll = db["security_events"]
    preds_coll = db["threat_predictions"]

    from backend.app.services.correlation_engine import TECHNIQUE_STAGE_MAP, EventCorrelationEngine

    # Retrieve authoritative related events from incident
    raw_event_ids = list(incident.related_events or incident.event_ids or [])
    
    # If incident has an attack_chain_id and no direct matching events, check correlated chains
    matching_events = list(events_coll.find({"event_id": {"$in": raw_event_ids}}, {"_id": 0}))
    
    # Fallback to attack_chain correlation if event IDs were synthetic or empty but attack_chain_id exists
    if not matching_events and incident.attack_chain_id:
        engine = EventCorrelationEngine(correlation_window_minutes=30)
        # Find events matching this chain or source/asset
        query_filter = {}
        if incident.affected_asset:
            query_filter["asset_name"] = incident.affected_asset
        elif incident.source_ip:
            query_filter["source_ip"] = incident.source_ip
            
        candidate_events = list(events_coll.find(query_filter, {"_id": 0}).limit(100))
        if candidate_events:
            corr_res = engine.correlate(candidate_events)
            for chain in corr_res.attack_chains:
                if chain.attack_chain_id == incident.attack_chain_id:
                    raw_event_ids = chain.events
                    matching_events = list(events_coll.find({"event_id": {"$in": raw_event_ids}}, {"_id": 0}))
                    break

    # Build event lookup map
    event_map = {e.get("event_id"): e for e in matching_events if e.get("event_id")}

    # Get ML predictions for additional confidence / threat details
    pred_map = {}
    if raw_event_ids:
        pred_cursor = preds_coll.find({"event_id": {"$in": raw_event_ids}}, {"_id": 0})
        pred_map = {p.get("event_id"): p for p in pred_cursor if p.get("event_id")}

    # Determine chronological order
    def get_event_timestamp(e_id: str):
        evt_doc = event_map.get(e_id)
        if evt_doc and evt_doc.get("timestamp"):
            ts = evt_doc.get("timestamp")
            if isinstance(ts, datetime):
                return ts
            try:
                return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except Exception:
                return datetime.min
        return datetime.min

    sorted_event_ids = sorted(raw_event_ids, key=get_event_timestamp)

    stages = []
    for idx, e_id in enumerate(sorted_event_ids, start=1):
        evt_doc = event_map.get(e_id)
        p_doc = pred_map.get(e_id, {})

        if evt_doc:
            # Authoritative event telemetry present in database
            ts_val = evt_doc.get("timestamp")
            if isinstance(ts_val, datetime):
                formatted_ts = ts_val.strftime("%Y-%m-%d %H:%M:%S")
            elif ts_val:
                formatted_ts = str(ts_val).replace("T", " ").replace("Z", "")[:19]
            else:
                formatted_ts = "N/A"

            source = evt_doc.get("source_ip") or "N/A"
            dest = evt_doc.get("destination_ip") or "N/A"
            user = evt_doc.get("username") or "N/A"
            
            # MITRE Technique
            mitre_id = evt_doc.get("mitre_id")
            tech_name = evt_doc.get("technique_name")
            if mitre_id and tech_name:
                mitre_tech = f"{mitre_id} ({tech_name})"
            elif mitre_id:
                mitre_tech = mitre_id
            elif tech_name:
                mitre_tech = tech_name
            else:
                mitre_tech = "N/A"

            # Risk calculation: severity or prediction confidence or incident risk
            risk_val = evt_doc.get("event_severity") or p_doc.get("confidence_score") or incident.risk_level or "N/A"
            if isinstance(risk_val, (int, float)):
                risk_str = f"{risk_val}%"
            else:
                risk_str = str(risk_val)

            # Stage classification via canonical TECHNIQUE_STAGE_MAP
            stage_name = (
                TECHNIQUE_STAGE_MAP.get(mitre_id) or
                TECHNIQUE_STAGE_MAP.get(tech_name) or
                TECHNIQUE_STAGE_MAP.get(evt_doc.get("tactic")) or
                TECHNIQUE_STAGE_MAP.get(evt_doc.get("event_type")) or
                evt_doc.get("tactic") or
                evt_doc.get("event_type") or
                f"Stage {idx}"
            )
        else:
            # Event ID referenced by incident, but raw event not present in telemetry (display N/A honestly)
            formatted_ts = "N/A"
            source = incident.source_ip or "N/A"
            dest = incident.destination_ip or "N/A"
            user = incident.affected_user or "N/A"
            mitre_tech = (incident.mitre_techniques[0] if incident.mitre_techniques else "N/A")
            risk_str = str(incident.risk_level or "N/A")
            stage_name = incident.threat_type or f"Stage {idx}"

        stages.append({
            "stage_number": idx,
            "stage_name": stage_name,
            "event_id": e_id if e_id else "N/A",
            "timestamp": formatted_ts,
            "source": source,
            "destination": dest,
            "user": user,
            "mitre_technique": mitre_tech,
            "risk": risk_str
        })

    return {
        "incident_id": incident_id,
        "attack_chain_id": incident.attack_chain_id or (f"AC-{incident_id[:8]}" if stages else None),
        "total_stages": len(stages),
        "stages": stages
    }

