"""
Threat Intelligence & Indicators of Compromise (IoC) REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /threat-intel endpoint returning threat intelligence indicators,
event match counts, and dynamic matching summary metrics from MongoDB.
"""

from fastapi import APIRouter, HTTPException, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["Threat Intelligence"])


@router.get("/threat-intel", status_code=status.HTTP_200_OK)
def get_threat_intelligence() -> dict:
    """
    Retrieves Threat Intelligence indicators (IoCs) and evaluates real-time event match counts.
    Uses MongoDB aggregation pipelines to match source_ip or destination_ip against indicator_value.
    """
    try:
        db = get_database()
        threat_coll = db["threat_intelligence"]
        events_coll = db["security_events"]
        
        # MongoDB aggregation pipeline joining threat_intelligence -> security_events
        pipeline = [
            {
                "$lookup": {
                    "from": "security_events",
                    "let": {
                        "val": "$indicator_value",
                        "itype": "$indicator_type"
                    },
                    "pipeline": [
                        {
                            "$match": {
                                "$expr": {
                                    "$and": [
                                        {"$eq": ["$$itype", "IP Address"]},
                                        {
                                            "$or": [
                                                {"$eq": ["$source_ip", "$$val"]},
                                                {"$eq": ["$destination_ip", "$$val"]}
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    ],
                    "as": "matched_events"
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "indicator_id": 1,
                    "indicator_type": 1,
                    "indicator_value": 1,
                    "threat_name": 1,
                    "threat_actor": 1,
                    "confidence": 1,
                    "severity": 1,
                    "event_match_count": {"$size": "$matched_events"}
                }
            }
        ]
        
        indicators = list(threat_coll.aggregate(pipeline))
        
        total_indicators = len(indicators)
        matched_indicators = sum(1 for i in indicators if i.get("event_match_count", 0) > 0)
        unmatched_indicators = total_indicators - matched_indicators
        match_percentage = round((matched_indicators / total_indicators * 100), 2) if total_indicators > 0 else 0.0
        
        total_matched_events = events_coll.count_documents({"threat_intel_match": True})
        
        return {
            "summary": {
                "total_indicators": total_indicators,
                "matched_indicators": matched_indicators,
                "unmatched_indicators": unmatched_indicators,
                "match_percentage": match_percentage,
                "total_matched_events": total_matched_events
            },
            "indicators": indicators
        }
        
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving threat intelligence"
        )
