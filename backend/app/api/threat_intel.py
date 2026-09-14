"""
Threat Intelligence & Indicators of Compromise (IoC) REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /threat-intel endpoint returning threat intelligence indicators,
event match counts, and dynamic matching summary metrics from MongoDB.
"""

from typing import Optional, List, Dict, Any
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
        
        # Query indicators and match against security events telemetry
        raw_indicators = list(threat_coll.find({}, {"_id": 0}))

        def map_ioc_type(raw_type: str) -> str:
            t = str(raw_type or "").strip().lower()
            if "ip" in t:
                return "IP"
            elif "domain" in t:
                return "Domain"
            elif "url" in t:
                return "URL"
            elif "hash" in t:
                return "File Hash"
            elif "email" in t or "mail" in t:
                return "Email"
            return raw_type or "IP"

        enriched_indicators = []
        for ind in raw_indicators:
            val = ind.get("indicator_value")
            itype = ind.get("indicator_type", "IP Address")
            canonical_type = map_ioc_type(itype)

            # Build query filter based on IOC type
            matched_events = []
            if val:
                if canonical_type == "IP":
                    matched_events = list(events_coll.find(
                        {"$or": [{"source_ip": val}, {"destination_ip": val}]},
                        {"_id": 0, "timestamp": 1, "asset_name": 1, "event_severity": 1}
                    ))
                elif canonical_type == "Email":
                    matched_events = list(events_coll.find(
                        {"username": val},
                        {"_id": 0, "timestamp": 1, "asset_name": 1, "event_severity": 1}
                    ))
                # For domain/url/hash if future fields exist
                if not matched_events:
                    # Also check if any event matched threat_intel_indicator_id
                    ind_id = ind.get("indicator_id")
                    if ind_id:
                        matched_events = list(events_coll.find(
                            {"threat_intel_indicator_id": ind_id},
                            {"_id": 0, "timestamp": 1, "asset_name": 1, "event_severity": 1}
                        ))

            threat_count = len(matched_events)
            
            # Derive affected assets
            assets_found = sorted(list(set(e.get("asset_name") for e in matched_events if e.get("asset_name"))))
            affected_assets_str = ", ".join(assets_found) if assets_found else "N/A"

            # Derive first seen / last seen
            timestamps = []
            for e in matched_events:
                ts = e.get("timestamp")
                if ts:
                    if isinstance(ts, str):
                        try:
                            from datetime import datetime
                            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        except Exception:
                            pass
                    timestamps.append(ts)

            if timestamps:
                first_seen = min(timestamps)
                last_seen = max(timestamps)
                first_seen_str = first_seen.strftime("%Y-%m-%d %H:%M:%S") if hasattr(first_seen, "strftime") else str(first_seen)[:19]
                last_seen_str = last_seen.strftime("%Y-%m-%d %H:%M:%S") if hasattr(last_seen, "strftime") else str(last_seen)[:19]
            else:
                first_seen_str = "N/A"
                last_seen_str = "N/A"

            # Status
            status_val = ind.get("severity") or "Active"

            enriched_indicators.append({
                # Canonical Milestone 4 Task 8 fields
                "ioc": val or "N/A",
                "type": canonical_type,
                "status": status_val,
                "threat_count": threat_count,
                "affected_assets": affected_assets_str,
                "first_seen": first_seen_str,
                "last_seen": last_seen_str,

                # Backward compatibility M1 fields
                "indicator_id": ind.get("indicator_id"),
                "indicator_type": itype,
                "indicator_value": val,
                "threat_name": ind.get("threat_name"),
                "threat_actor": ind.get("threat_actor"),
                "confidence": ind.get("confidence"),
                "severity": ind.get("severity"),
                "event_match_count": threat_count
            })

        total_indicators = len(enriched_indicators)
        matched_indicators = sum(1 for i in enriched_indicators if i["threat_count"] > 0)
        unmatched_indicators = total_indicators - matched_indicators
        match_percentage = round((matched_indicators / total_indicators * 100), 2) if total_indicators > 0 else 0.0
        
        total_matched_events = events_coll.count_documents({"threat_intel_match": True})
        
        return {
            "summary": {
                "total_indicators": total_indicators,
                "total_iocs": total_indicators,
                "matched_indicators": matched_indicators,
                "unmatched_indicators": unmatched_indicators,
                "match_percentage": match_percentage,
                "total_matched_events": total_matched_events
            },
            "indicators": enriched_indicators,
            "iocs": enriched_indicators,
            "data": enriched_indicators
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


@router.get("/threat-intel/iocs", status_code=status.HTTP_200_OK)
def get_threat_intel_iocs(
    ioc_type: Optional[str] = None
) -> dict:
    """
    Milestone 4 — Task 8: Dedicated IOC Intelligence panel endpoint.
    Returns:
    - IOC
    - Type (IP, Domain, URL, File Hash, Email)
    - Status
    - Threat Count
    - Affected Assets
    - First Seen
    - Last Seen
    """
    res = get_threat_intelligence()
    indicators = res.get("indicators", [])

    if ioc_type and isinstance(ioc_type, str) and ioc_type.strip() and ioc_type.lower() != "all":
        t_target = ioc_type.strip().lower()
        indicators = [i for i in indicators if i.get("type", "").lower() == t_target]

    return {
        "data": indicators,
        "iocs": indicators,
        "summary": res.get("summary", {}),
        "total": len(indicators)
    }

