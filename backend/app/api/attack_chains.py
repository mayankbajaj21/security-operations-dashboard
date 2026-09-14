"""
backend/app/api/attack_chains.py

Milestone 3 — Step 5: Correlated Attack Chains REST API Router

Provides REST API endpoints for querying detected multi-stage cyber attack chains
correlated from security events and threat predictions.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database, check_database_connection
from backend.app.schemas.correlation import AttackChain, CorrelationResult
from backend.app.services.correlation_engine import EventCorrelationEngine

router = APIRouter(prefix="/attack-chains", tags=["Attack Chains"])

correlation_engine = EventCorrelationEngine(correlation_window_minutes=15)


@router.get("", status_code=status.HTTP_200_OK)
def list_attack_chains(
    window_minutes: Optional[float] = Query(default=15.0, ge=1.0, le=120.0, description="Correlation sliding time window in minutes")
) -> dict:
    """
    Retrieves all detected multi-stage attack chains correlated across security telemetry.
    """
    try:
        is_healthy, _ = check_database_connection()
        if not is_healthy:
            return {
                "data": [],
                "total": 0,
                "metrics": {
                    "total_events_analyzed": 0,
                    "suspicious_events_count": 0,
                    "attack_chains_count": 0
                }
            }

        db = get_database()
        events_coll = db["security_events"]
        pred_coll = db["threat_predictions"]

        pred_cursor = pred_coll.find({}, {"_id": 0})
        pred_map = {p["event_id"]: p for p in pred_cursor if "event_id" in p}

        events_cursor = events_coll.find({}, {"_id": 0})
        combined_events = []

        for evt in events_cursor:
            e_id = evt.get("event_id")
            pred_data = pred_map.get(e_id, {})

            combined_events.append({
                "event_id": e_id,
                "timestamp": evt.get("timestamp"),
                "event_type": evt.get("event_type"),
                "threat_type": pred_data.get("threat_type", evt.get("event_type")),
                "severity": evt.get("event_severity", "Low"),
                "username": evt.get("username"),
                "source_ip": evt.get("source_ip"),
                "destination_ip": evt.get("destination_ip"),
                "asset_name": evt.get("asset_name"),
                "mitre_id": evt.get("mitre_id"),
                "prediction": pred_data.get("prediction", "Normal"),
                "confidence_score": pred_data.get("confidence_score", 0),
                "threat_intel_match": evt.get("threat_intel_match", False),
                "failed_login_attempts": evt.get("failed_login_attempts", 0)
            })

        # Run Correlation Engine
        engine = EventCorrelationEngine(correlation_window_minutes=window_minutes or 15.0)
        corr_result: CorrelationResult = engine.correlate(combined_events)

        formatted_chains = []
        for chain in corr_result.attack_chains:
            cdict = chain.model_dump(by_alias=True)
            # Ensure aliases and entity accessors are populated
            cdict["events"] = chain.events
            cdict["related_events"] = chain.events
            cdict["techniques"] = chain.techniques
            cdict["stages"] = chain.stages
            cdict["stage"] = chain.stage
            cdict["risk_score"] = chain.risk_score
            cdict["confidence"] = chain.confidence
            cdict["ml_confidence"] = chain.confidence
            cdict["affected_asset"] = chain.affected_asset
            cdict["target_user"] = chain.target_user
            cdict["source_ip"] = chain.source_ip
            cdict["participating_entities"] = {
                "username": chain.target_user,
                "asset_name": chain.affected_asset,
                "source_ip": chain.source_ip,
                "destination_ip": chain.event_details[0].destination_ip if chain.event_details else None
            }
            formatted_chains.append(cdict)

        return {
            "data": formatted_chains,
            "total": corr_result.attack_chains_count,
            "metrics": {
                "total_events_analyzed": corr_result.total_events_analyzed,
                "suspicious_events_count": corr_result.suspicious_events_count,
                "attack_chains_count": corr_result.attack_chains_count
            }
        }
    except PyMongoError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error during correlation: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute attack chain correlation: {str(e)}"
        )

