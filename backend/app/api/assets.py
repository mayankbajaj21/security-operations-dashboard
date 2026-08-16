"""
Asset Inventory & Vulnerability Context REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /assets endpoint returning enriched IT asset inventory metrics,
event analytics, and associated CVE vulnerability context from MongoDB.
"""

from fastapi import APIRouter, HTTPException, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["Assets"])


@router.get("/assets", status_code=status.HTTP_200_OK)
def get_assets() -> dict:
    """
    Retrieves IT asset inventory enriched with event counts, vulnerability counts,
    critical severity counts, and associated CVE vulnerability catalog details.
    
    Uses MongoDB aggregation pipeline for efficient server-side processing.
    """
    try:
        db = get_database()
        assets_coll = db["assets"]
        
        # MongoDB Aggregation Pipeline joining assets -> security_events -> vulnerabilities
        pipeline = [
            {
                "$lookup": {
                    "from": "security_events",
                    "localField": "asset_name",
                    "foreignField": "asset_name",
                    "as": "matched_events"
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "asset_id": 1,
                    "asset_name": 1,
                    "asset_type": 1,
                    "owner": 1,
                    "department": 1,
                    "criticality": 1,
                    "operating_system": 1,
                    "event_count": {"$size": "$matched_events"},
                    "vulnerability_event_count": {
                        "$size": {
                            "$filter": {
                                "input": "$matched_events",
                                "as": "evt",
                                "cond": {"$ne": ["$$evt.vulnerability_id", None]}
                            }
                        }
                    },
                    "critical_event_count": {
                        "$size": {
                            "$filter": {
                                "input": "$matched_events",
                                "as": "evt",
                                "cond": {"$eq": ["$$evt.event_severity", "Critical"]}
                            }
                        }
                    },
                    "asset_cve_ids": {
                        "$setUnion": [
                            {
                                "$map": {
                                    "input": {
                                        "$filter": {
                                            "input": "$matched_events",
                                            "as": "evt",
                                            "cond": {"$ne": ["$$evt.vulnerability_id", None]}
                                        }
                                    },
                                    "as": "vevt",
                                    "in": "$$vevt.vulnerability_id"
                                }
                            },
                            []
                        ]
                    }
                }
            },
            {
                "$lookup": {
                    "from": "vulnerabilities",
                    "localField": "asset_cve_ids",
                    "foreignField": "cve_id",
                    "as": "matched_vulns"
                }
            },
            {
                "$project": {
                    "asset_id": 1,
                    "asset_name": 1,
                    "asset_type": 1,
                    "owner": 1,
                    "department": 1,
                    "criticality": 1,
                    "operating_system": 1,
                    "event_count": 1,
                    "vulnerability_event_count": 1,
                    "critical_event_count": 1,
                    "vulnerabilities": {
                        "$map": {
                            "input": "$matched_vulns",
                            "as": "v",
                            "in": {
                                "cve_id": "$$v.cve_id",
                                "vulnerability_record_id": "$$v.vulnerability_id",
                                "vulnerability_name": "$$v.vulnerability_name",
                                "vulnerability_severity": "$$v.severity",
                                "vulnerability_cvss_score": "$$v.cvss_score",
                                "patch_available": "$$v.patch_available",
                                "vulnerability_status": "$$v.status"
                            }
                        }
                    }
                }
            }
        ]
        
        asset_records = list(assets_coll.aggregate(pipeline))
        
        total_assets = len(asset_records)
        assets_with_events = sum(1 for asset in asset_records if asset.get("event_count", 0) > 0)
        assets_without_events = total_assets - assets_with_events
        
        return {
            "summary": {
                "total_assets": total_assets,
                "assets_with_events": assets_with_events,
                "assets_without_events": assets_without_events
            },
            "assets": asset_records
        }
        
    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while retrieving asset inventory"
        )
