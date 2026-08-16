"""
Security Event Trend REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /events/trend endpoint performing server-side MongoDB aggregations
to group security telemetry into hourly timestamp buckets broken down by severity.
"""

from fastapi import APIRouter, HTTPException, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["Trends"])


@router.get("/events/trend", status_code=status.HTTP_200_OK)
def get_event_trend() -> dict:
    """
    Computes hourly security event trend analytics directly from MongoDB.
    Groups events into hourly buckets and counts total, critical, high, medium, and low severity events.
    """
    try:
        db = get_database()
        events_coll = db["security_events"]

        # Server-side MongoDB Aggregation Pipeline for hourly time buckets
        pipeline = [
            {
                "$project": {
                    "hour_bucket": {
                        "$dateToString": {
                            "format": "%Y-%m-%dT%H:00:00",
                            "date": {
                                "$cond": [
                                    {"$eq": [{"$type": "$timestamp"}, "date"]},
                                    "$timestamp",
                                    {"$dateFromString": {"dateString": "$timestamp"}}
                                ]
                            }
                        }
                    },
                    "event_severity": 1
                }
            },
            {
                "$group": {
                    "_id": "$hour_bucket",
                    "total": {"$sum": 1},
                    "critical": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_severity", "Critical"]}, 1, 0]
                        }
                    },
                    "high": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_severity", "High"]}, 1, 0]
                        }
                    },
                    "medium": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_severity", "Medium"]}, 1, 0]
                        }
                    },
                    "low": {
                        "$sum": {
                            "$cond": [{"$eq": ["$event_severity", "Low"]}, 1, 0]
                        }
                    }
                }
            },
            {"$sort": {"_id": 1}},
            {
                "$project": {
                    "_id": 0,
                    "timestamp": "$_id",
                    "total": 1,
                    "critical": 1,
                    "high": 1,
                    "medium": 1,
                    "low": 1
                }
            }
        ]

        trend_data = list(events_coll.aggregate(pipeline))

        return {"trend": trend_data}

    except PyMongoError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while computing event trends"
        )
