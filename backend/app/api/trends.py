"""
Security Event Trend REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /events/trend endpoint performing server-side MongoDB aggregations
to group security telemetry into hourly timestamp buckets broken down by severity.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database
from backend.app.services.risk_engine import RiskScoringEngine

router = APIRouter(tags=["Trends"])


@router.get("/events/trend", status_code=status.HTTP_200_OK)
def get_event_trend(
    range: Optional[str] = Query(
        default="7d",
        description="Time window for trend analytics ('24h', '7d', '30d')"
    )
) -> dict:
    """
    Computes hourly security event trend and authoritative Milestone 3 risk analytics from MongoDB.
    Groups events into hourly buckets, computing severity counts (critical, high, medium, low)
    and authoritative multi-factor average/max risk scores derived directly from RiskScoringEngine.
    """
    try:
        db = get_database()
        events_coll = db["security_events"]
        pred_coll = db["threat_predictions"]

        range_clean = str(range or "7d").strip().lower()
        if range_clean not in ("24h", "7d", "30d"):
            range_clean = "7d"

        # Determine dataset telemetry boundary from actual data
        latest_doc = events_coll.find_one(sort=[("timestamp", -1)])
        if not latest_doc or "timestamp" not in latest_doc:
            return {
                "range": range_clean,
                "telemetry_window": {
                    "requested_start": None,
                    "requested_end": None,
                    "actual_start": None,
                    "actual_end": None,
                    "hours_covered": 0.0,
                    "days_covered": 0.0,
                    "is_partial": False
                },
                "data_points_count": 0,
                "trend": []
            }

        max_dt = latest_doc["timestamp"]
        if isinstance(max_dt, str):
            max_dt = datetime.fromisoformat(max_dt.replace("Z", "+00:00"))

        if range_clean == "24h":
            req_start = max_dt - timedelta(hours=24)
        elif range_clean == "7d":
            req_start = max_dt - timedelta(days=7)
        else:  # "30d"
            req_start = max_dt - timedelta(days=30)

        # Query only real telemetry within boundary - never fabricate synthetic events
        query = {"timestamp": {"$gte": req_start, "$lte": max_dt}}
        matching_events = list(events_coll.find(query, {"_id": 0}))

        if not matching_events:
            return {
                "range": range_clean,
                "telemetry_window": {
                    "requested_start": req_start.isoformat(),
                    "requested_end": max_dt.isoformat(),
                    "actual_start": None,
                    "actual_end": None,
                    "hours_covered": 0.0,
                    "days_covered": 0.0,
                    "is_partial": True
                },
                "data_points_count": 0,
                "trend": []
            }

        # Build predictions lookup map for authoritative M3 risk evaluation
        pred_cursor = pred_coll.find({}, {"_id": 0})
        pred_map = {p["event_id"]: p for p in pred_cursor if "event_id" in p}

        # Group by actual hourly bucket timestamps
        buckets = defaultdict(lambda: {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "risk_scores": []
        })

        for evt in matching_events:
            ts = evt["timestamp"]
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hour_key = ts.strftime("%Y-%m-%dT%H:00:00")

            sev = evt.get("event_severity", "Low")
            sev_str = str(sev).strip().lower()

            b = buckets[hour_key]
            b["total"] += 1
            if sev_str == "critical":
                b["critical"] += 1
            elif sev_str == "high":
                b["high"] += 1
            elif sev_str == "medium":
                b["medium"] += 1
            elif sev_str == "low":
                b["low"] += 1

            # Authoritative M3 Multi-Factor Risk Evaluation
            p = pred_map.get(evt.get("event_id"), {})
            risk_payload = {
                "event_id": evt.get("event_id"),
                "severity": sev,
                "ml_prediction": p.get("prediction", "Normal"),
                "confidence_score": p.get("confidence_score", 0.0),
                "anomaly_score": p.get("anomaly_score", 0.0),
                "cvss_score": evt.get("raw_cvss_score", 0.0),
                "asset_criticality": evt.get("asset_criticality", "Low"),
                "threat_intel_match": evt.get("threat_intel_match", False),
                "threat_type": p.get("threat_type", evt.get("event_type", "Unknown")),
                "asset_name": evt.get("asset_name"),
                "username": evt.get("username")
            }
            risk_res = RiskScoringEngine.calculate(risk_payload)
            b["risk_scores"].append(risk_res.risk_score)

        trend_data = []
        for k in sorted(buckets.keys()):
            b_data = buckets[k]
            scores = b_data["risk_scores"]
            avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
            max_score = max(scores) if scores else 0
            trend_data.append({
                "timestamp": k,
                "total": b_data["total"],
                "critical": b_data["critical"],
                "high": b_data["high"],
                "medium": b_data["medium"],
                "low": b_data["low"],
                "avg_risk_score": avg_score,
                "max_risk_score": max_score
            })

        # Calculate actual telemetry window
        actual_min_ts = min(
            (e["timestamp"] if isinstance(e["timestamp"], datetime) else datetime.fromisoformat(str(e["timestamp"]).replace("Z", "+00:00")))
            for e in matching_events
        )
        actual_max_ts = max(
            (e["timestamp"] if isinstance(e["timestamp"], datetime) else datetime.fromisoformat(str(e["timestamp"]).replace("Z", "+00:00")))
            for e in matching_events
        )
        hours_covered = round((actual_max_ts - actual_min_ts).total_seconds() / 3600.0, 2)
        days_covered = round(hours_covered / 24.0, 2)

        return {
            "range": range_clean,
            "telemetry_window": {
                "requested_start": req_start.isoformat(),
                "requested_end": max_dt.isoformat(),
                "actual_start": actual_min_ts.isoformat(),
                "actual_end": actual_max_ts.isoformat(),
                "hours_covered": hours_covered,
                "days_covered": days_covered,
                "is_partial": (actual_min_ts > req_start)
            },
            "data_points_count": len(trend_data),
            "trend": trend_data
        }

    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while computing event trends: {str(e)}"
        )
