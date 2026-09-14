"""
backend/app/api/posture.py

Milestone 4 — Task 15: Security Posture Score REST Router.

Provides GET /posture and GET /api/v1/posture returning overall security-health metric (0-100),
status band (Good/Warning/Critical), and contributing factor breakdowns.
"""

from fastapi import APIRouter, HTTPException, status
from backend.app.services.posture_service import SecurityPostureService
from backend.app.core.database import get_database

router = APIRouter(tags=["Security Posture"])

@router.get("/posture", status_code=status.HTTP_200_OK)
@router.get("/api/v1/posture", status_code=status.HTTP_200_OK)
def get_security_posture() -> dict:
    """
    Milestone 4 — Task 15: Retrieves the overall Security Posture Score.
    Dynamically derived from authoritative project data across:
    1. Critical vulnerabilities
    2. Active incidents
    3. High-risk assets
    4. Unresolved threats
    5. Threat volume
    """
    try:
        db = get_database()
        return SecurityPostureService.calculate_posture(db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate security posture score: {str(e)}"
        )
