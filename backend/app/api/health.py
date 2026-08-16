"""
Health Check API Route
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides a health status endpoint verifying application operation and MongoDB connection status.
"""

from fastapi import APIRouter, Response, status
from backend.app.core.database import check_database_connection

router = APIRouter(tags=["Health"])


@router.get("/health", status_code=status.HTTP_200_OK)
def get_health(response: Response) -> dict:
    """
    Health check endpoint.
    Verifies that the FastAPI web service is operational and checks MongoDB connectivity.
    
    Returns:
        HTTP 200 OK: {"status": "healthy", "database": "connected"}
        HTTP 503 Service Unavailable: {"status": "unhealthy", "database": "disconnected"}
    """
    is_healthy, _ = check_database_connection()
    
    if is_healthy:
        return {
            "status": "healthy",
            "database": "connected"
        }
    
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "unhealthy",
        "database": "disconnected"
    }
