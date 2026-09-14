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

        # Milestone 4 — Task 6: Authoritative MITRE Technique Analysis
        # Derive technique analysis by joining:
        #   security_events (grouped by event_type, aggregated severity)
        #      ↓ event_type key
        #   mitre_attack_mapping (event_type → mitre_id, technique_name, tactic)
        #
        # This is the correct join because security_events.mitre_id is not populated;
        # the authoritative MITRE mapping lives in the mitre_attack_mapping collection.

        # Aggregate dominant severity per event_type in a single pipeline pass
        severity_rank = {"Critical": 4, "High": 3, "Moderate": 2, "Medium": 2, "Low": 1}
        severity_agg = events_coll.aggregate([
            {"$group": {
                "_id": "$event_type",
                "critical_count": {"$sum": {"$cond": [{"$eq": ["$event_severity", "Critical"]}, 1, 0]}},
                "high_count":     {"$sum": {"$cond": [{"$eq": ["$event_severity", "High"]},     1, 0]}},
                "moderate_count": {"$sum": {"$cond": [{"$eq": ["$event_severity", "Moderate"]}, 1, 0]}},
                "medium_count":   {"$sum": {"$cond": [{"$eq": ["$event_severity", "Medium"]},   1, 0]}},
                "low_count":      {"$sum": {"$cond": [{"$eq": ["$event_severity", "Low"]},      1, 0]}}
            }}
        ])
        # Build a map: event_type -> dominant risk level
        severity_by_etype: dict = {}
        for row in severity_agg:
            etype = row.get("_id")
            if not etype:
                continue
            candidates = [
                ("Critical", row.get("critical_count", 0)),
                ("High",     row.get("high_count", 0)),
                ("Moderate", row.get("moderate_count", 0)),
                ("Medium",   row.get("medium_count", 0)),
                ("Low",      row.get("low_count", 0)),
            ]
            best_sev = "Low"
            best_rank = 0
            for sev_name, cnt in candidates:
                r = severity_rank.get(sev_name, 0)
                if r > best_rank and cnt > 0:
                    best_rank = r
                    best_sev = sev_name
            severity_by_etype[etype] = best_sev

        # Build technique list: one entry per authoritative mitre_attack_mapping record
        # that has at least one matching event_type in the security_events collection.
        techniques = []
        for record in mitre_records:
            e_type = record.get("event_type")
            mitre_id = record.get("mitre_id")
            t_name = record.get("technique_name") or mitre_id or e_type
            if not mitre_id or not e_type:
                continue
            evt_count = event_counts_map.get(e_type, 0)
            risk_level = severity_by_etype.get(e_type, "Low")
            techniques.append({
                "technique": mitre_id,
                "name": t_name,
                "events": evt_count,
                "risk": risk_level
            })

        # Sort descending by event count
        techniques.sort(key=lambda x: x["events"], reverse=True)
            
        return {
            "summary": {
                "total_events": total_events,
                "mapped_events": mapped_events,
                "unmapped_events": unmapped_events,
                "mapping_percentage": mapping_percentage
            },
            "mappings": mappings,
            "techniques": techniques,
            "distribution": techniques
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


@router.get("/mitre/techniques", status_code=status.HTTP_200_OK)
def get_mitre_techniques() -> dict:
    """
    Milestone 4 — Task 6: Dedicated endpoint returning MITRE technique analysis table & chart data.
    Columns: Technique, Name, Events, Risk
    """
    res = get_mitre_mappings()
    techs = res.get("techniques", [])
    return {
        "data": techs,
        "techniques": techs,
        "distribution": techs,
        "total": len(techs)
    }

