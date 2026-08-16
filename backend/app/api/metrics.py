"""
Metrics & Telemetry Aggregation REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /metrics endpoint calculating real-time dashboard summary metrics from MongoDB.
"""

from fastapi import APIRouter, HTTPException, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["Metrics"])


@router.get("/metrics", status_code=status.HTTP_200_OK)
def get_metrics() -> dict:
    """
    Computes and returns aggregate metrics for the security operations dashboard.
    Uses a single-pass MongoDB $facet aggregation pipeline for maximum efficiency.
    """
    try:
        db = get_database()
        collection = db["security_events"]
        
        # Single-pass MongoDB $facet aggregation pipeline
        pipeline = [
            {
                "$facet": {
                    "total": [{"$count": "count"}],
                    "by_severity": [{"$group": {"_id": "$event_severity", "count": {"$sum": 1}}}],
                    "by_status": [{"$group": {"_id": "$event_status", "count": {"$sum": 1}}}],
                    "malware": [{"$match": {"malware_detected": "Yes"}}, {"$count": "count"}],
                    "events_with_vuln_id": [{"$match": {"vulnerability_id": {"$ne": None}}}, {"$count": "count"}],
                    "vuln_enriched": [{"$match": {"vulnerability_record_id": {"$ne": None}}}, {"$count": "count"}],
                    "threat_matches": [{"$match": {"threat_intel_match": True}}, {"$count": "count"}],
                    "mitre_mapped": [{"$match": {"mitre_mapping_status": "Mapped"}}, {"$count": "count"}],
                    "incident_matches": [{"$match": {"incident_id": {"$ne": None}}}, {"$count": "count"}],
                    "asset_matched": [{"$match": {"asset_id": {"$ne": None}}}, {"$count": "count"}],
                    "asset_unmatched": [{"$match": {"asset_id": None}}, {"$count": "count"}]
                }
            }
        ]
        
        agg_result = list(collection.aggregate(pipeline))
        if not agg_result:
            results = {}
        else:
            results = agg_result[0]
            
        def extract_count(facet_key: str) -> int:
            facet_data = results.get(facet_key, [])
            return facet_data[0]["count"] if facet_data else 0
            
        total_events = extract_count("total")
        
        # Build severity mapping
        severity_items = results.get("by_severity", [])
        severity_counts = {item["_id"]: item["count"] for item in severity_items if item.get("_id")}
        
        # Build status mapping
        status_items = results.get("by_status", [])
        status_counts = {str(item["_id"]).lower(): item["count"] for item in status_items if item.get("_id")}
        
        return {
            "overview": {
                "total_events": total_events,
                "critical_events": severity_counts.get("Critical", 0),
                "high_events": severity_counts.get("High", 0),
                "medium_events": severity_counts.get("Medium", 0),
                "low_events": severity_counts.get("Low", 0)
            },
            "event_status": {
                "success": status_counts.get("success", 0),
                "failed": status_counts.get("failed", 0),
                "blocked": status_counts.get("blocked", 0),
                "detected": status_counts.get("detected", 0)
            },
            "security_indicators": {
                "malware_detected": extract_count("malware"),
                "events_with_vulnerability_id": extract_count("events_with_vuln_id"),
                "vulnerability_enriched_events": extract_count("vuln_enriched"),
                "threat_intel_matches": extract_count("threat_matches"),
                "mitre_mapped_events": extract_count("mitre_mapped"),
                "incident_matches": extract_count("incident_matches")
            },
            "asset_coverage": {
                "asset_matched_events": extract_count("asset_matched"),
                "asset_unmatched_events": extract_count("asset_unmatched")
            }
        }
        
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while calculating metrics"
        )
