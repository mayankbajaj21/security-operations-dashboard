"""
backend/app/api/reports.py

Milestone 4 — Task 17: Security Report Generation REST Router.

Provides downloadable executive reports in PDF and CSV formats:
- GET /reports/executive?format=pdf|csv
- GET /api/v1/reports/executive?format=pdf|csv
- GET /reports/executive/data (JSON summary of authoritative report data)
- GET /api/v1/reports/executive/data
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Response, status
from backend.app.services.report_service import SecurityReportService
from backend.app.core.database import get_database

router = APIRouter(tags=["Security Reports"])


@router.get("/reports/executive/data", status_code=status.HTTP_200_OK)

def get_executive_report_data() -> dict:
    """
    Returns authoritative data payload used to assemble the executive security report.
    Enables frontend executive summary dashboard to load unified live metrics.
    """
    try:
        db = get_database()
        return SecurityReportService.get_report_data(db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile report data: {str(e)}"
        )


@router.get("/reports/executive", status_code=status.HTTP_200_OK)
@router.get("/api/v1/reports/executive", status_code=status.HTTP_200_OK)
def generate_executive_report(
    format: Optional[str] = Query("pdf", pattern="^(pdf|csv)$", description="Report output format: 'pdf' or 'csv'")
):
    """
    Milestone 4 — Task 17: Generates downloadable authoritative executive security report.
    Supports downloadable PDF and CSV.
    """
    try:
        db = get_database()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        if format.lower() == "csv":
            csv_content = SecurityReportService.generate_csv(db)
            filename = f"security_operations_executive_report_{timestamp}.csv"
            return Response(
                content=csv_content,
                media_type="text/csv",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "text/csv; charset=utf-8",
                    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                }
            )
        else:
            pdf_bytes = SecurityReportService.generate_pdf(db)
            filename = f"security_operations_executive_report_{timestamp}.pdf"
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Content-Type": "application/pdf",
                    "Cache-Control": "no-cache, no-store, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                }
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate executive report: {str(e)}"
        )
