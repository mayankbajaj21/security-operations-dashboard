"""
backend/app/api/incidents.py

Milestone 3 — Step 5: Incident Management & Recommendations REST API Router

Provides REST API endpoints for querying, creating, updating lifecycle status,
and retrieving prescriptive analyst recommendations for security incidents.
"""

import math
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError

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


@router.get("/incidents", status_code=status.HTTP_200_OK)
def list_incidents(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=20, ge=1, le=100, description="Items per page"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by status ('Open', 'Investigating', 'Resolved', 'False Positive')"),
    risk_level: Optional[str] = Query(default=None, description="Filter by risk level ('Critical', 'High', 'Moderate', 'Medium', 'Low')"),
    threat_type: Optional[str] = Query(default=None, description="Filter by threat category"),
    asset: Optional[str] = Query(default=None, description="Filter by affected asset name"),
    mitre_technique: Optional[str] = Query(default=None, description="Filter by MITRE technique ID")
) -> dict:
    """
    Retrieves a paginated list of security incidents with multi-field filtering.
    """
    try:
        all_incidents = incident_service.list_incidents(status=status_filter, limit=1000, offset=0)

        filtered = all_incidents
        if risk_level and str(risk_level).strip():
            r_target = str(risk_level).strip().lower()
            filtered = [i for i in filtered if i.risk_level and i.risk_level.lower() == r_target]

        if threat_type and str(threat_type).strip():
            t_target = str(threat_type).strip().lower()
            filtered = [i for i in filtered if i.threat_type and i.threat_type.lower() == t_target]

        if asset and str(asset).strip():
            a_target = str(asset).strip().lower()
            filtered = [i for i in filtered if i.affected_asset and a_target in i.affected_asset.lower()]

        if mitre_technique and str(mitre_technique).strip():
            m_target = str(mitre_technique).strip().lower()
            filtered = [i for i in filtered if any(m_target in t.lower() for t in i.mitre_techniques)]

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


@router.get("/recommendations/{incident_id}", response_model=IncidentRecommendationResponse, status_code=status.HTTP_200_OK)
def get_incident_recommendations(incident_id: str) -> IncidentRecommendationResponse:
    """
    Retrieves prescriptive mitigation guidance for a specific incident.
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
