"""
MITRE ATT&CK Mapping REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /mitre endpoint for returning MITRE ATT&CK framework coverage summary and technique mappings.
"""

from fastapi import APIRouter, HTTPException, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["MITRE"])


@router.get("/mitre", status_code=status.HTTP_200_OK)
def get_mitre_mappings() -> dict:
    """
    Retrieves MITRE ATT&CK mapping coverage statistics and reference technique mappings.
    Computes total mapped/unmapped event counts dynamically from MongoDB.
    """
    try:
        db = get_database()
        events_coll = db["security_events"]
        mitre_coll = db["mitre_attack_mapping"]
        
        # Calculate summary statistics from security_events
        total_events = events_coll.count_documents({})
        mapped_events = events_coll.count_documents({"mitre_mapping_status": "Mapped"})
        unmapped_events = total_events - mapped_events
        
        mapping_percentage = round((mapped_events / total_events * 100), 2) if total_events > 0 else 0.0
        
        # Aggregate event counts per event_type from security_events
        event_counts_cursor = events_coll.aggregate([
            {"$group": {"_id": "$event_type", "event_count": {"$sum": 1}}}
        ])
        event_counts_map = {item["_id"]: item["event_count"] for item in event_counts_cursor if item.get("_id")}
        
        # Fetch reference MITRE mappings from mitre_attack_mapping collection
        mitre_records = list(mitre_coll.find({}, {"_id": 0}))
        
        mappings = []
        for record in mitre_records:
            e_type = record.get("event_type")
            mappings.append({
                "event_type": e_type,
                "mitre_id": record.get("mitre_id"),
                "technique_name": record.get("technique_name"),
                "tactic": record.get("tactic"),
                "event_count": event_counts_map.get(e_type, 0)
            })
            
        return {
            "summary": {
                "total_events": total_events,
                "mapped_events": mapped_events,
                "unmapped_events": unmapped_events,
                "mapping_percentage": mapping_percentage
            },
            "mappings": mappings
        }
        
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving MITRE mappings"
        )
