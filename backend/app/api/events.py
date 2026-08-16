"""
Security Events REST API Router
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides GET /events endpoint for querying, filtering, and paginating canonical security events from MongoDB.
"""

from datetime import datetime
import math
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

router = APIRouter(tags=["Events"])


def serialize_doc(doc: dict) -> dict:
    """
    Serializes a MongoDB document for JSON response:
    - Removes internal _id field
    - Converts datetime objects to ISO 8601 string representation
    """
    doc.pop("_id", None)
    for key, val in doc.items():
        if isinstance(val, datetime):
            doc[key] = val.isoformat()
    return doc


@router.get("/events", status_code=status.HTTP_200_OK)
def get_events(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    severity: Optional[str] = Query(default=None, description="Filter by event severity (Critical, High, Medium, Low)"),
    event_type: Optional[str] = Query(default=None, description="Filter by event type"),
    status_filter: Optional[str] = Query(default=None, alias="status", description="Filter by event status (Success, Blocked, Failed, Detected)")
) -> dict:
    """
    Retrieves paginated security event documents with optional multi-field filtering.
    
    Query Parameters:
    - page: Page number (default: 1)
    - limit: Results per page (default: 50, max: 100)
    - severity: Maps to event_severity
    - event_type: Maps to event_type
    - status: Maps to event_status
    
    Returns:
    - Paginated list of security events sorted by timestamp descending.
    """
    try:
        db = get_database()
        collection = db["security_events"]
        
        # Build query filter
        query_filter = {}
        if severity:
            query_filter["event_severity"] = severity
        if event_type:
            query_filter["event_type"] = event_type
        if status_filter:
            query_filter["event_status"] = status_filter
            
        # Total count for pagination metadata
        total = collection.count_documents(query_filter)
        total_pages = math.ceil(total / limit) if total > 0 else 0
        
        skip_count = (page - 1) * limit
        
        # Execute paginated, sorted query
        cursor = collection.find(
            query_filter,
            {"_id": 0}  # Exclude BSON ObjectId from projection
        ).sort("timestamp", -1).skip(skip_count).limit(limit)
        
        events = [serialize_doc(doc) for doc in cursor]
        
        return {
            "data": events,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages
            }
        }
        
    except PyMongoError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request"
        )
