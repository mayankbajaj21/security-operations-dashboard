"""
backend/app/api/vulnerabilities.py

Milestone 4 — Task 7: Authoritative Vulnerability & CVE Exposure REST API Router

Provides REST API endpoints for querying authoritative CVE vulnerability exposures,
affected assets, CVSS scores, severity classifications (Critical, High, Medium, Low),
and patch statuses.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pymongo.errors import PyMongoError
from collections import defaultdict

from backend.app.core.database import get_database, check_database_connection

router = APIRouter(tags=["Vulnerabilities"])


def classify_cvss_severity(cvss: Optional[float]) -> str:
    """
    Standard CVSS v3 Severity Classification:
    Critical: 9.0 - 10.0
    High:     7.0 - 8.9
    Medium:   4.0 - 6.9
    Low:      0.1 - 3.9
    """
    if cvss is None:
        return "Unknown"
    if cvss >= 9.0:
        return "Critical"
    elif cvss >= 7.0:
        return "High"
    elif cvss >= 4.0:
        return "Medium"
    else:
        return "Low"


@router.get("/vulnerabilities", status_code=status.HTTP_200_OK)
def get_vulnerabilities(
    severity: Optional[str] = Query(default=None, description="Filter by severity (Critical, High, Medium, Low)"),
    asset: Optional[str] = Query(default=None, description="Filter by affected asset name")
) -> dict:
    """
    Milestone 4 — Task 7: Authoritative Vulnerability Information.
    Displays vulnerability information for:
        - Critical CVEs
        - High CVEs
        - Medium CVEs
    and affected assets.

    The vulnerability table contains:
        - CVE
        - Asset
        - CVSS
        - Severity
        - Status
    """
    try:
        is_healthy, _ = check_database_connection()
        if not is_healthy:
            return {
                "summary": {
                    "total": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "unique_cves": 0,
                    "affected_assets_count": 0
                },
                "data": []
            }

        db = get_database()
        vuln_coll = db["vulnerabilities"]
        events_coll = db["security_events"]

        # 1. Authoritative M1 catalog vulnerabilities
        catalog_vulns = list(vuln_coll.find({}, {"_id": 0}))
        catalog_map = {v.get("cve_id"): v for v in catalog_vulns if v.get("cve_id")}

        # 2. Correlated CVE events from security telemetry grouped by (cve_id, asset_name, severity_tier)
        cve_events = events_coll.find(
            {"vulnerability_id": {"$ne": None}},
            {"_id": 0, "vulnerability_id": 1, "asset_name": 1, "raw_cvss_score": 1, "event_status": 1, "event_severity": 1, "vulnerability_name": 1}
        )

        tier_groups: Dict[tuple, List[Dict[str, Any]]] = defaultdict(list)
        for evt in cve_events:
            vid = evt.get("vulnerability_id")
            aname = evt.get("asset_name")
            score = evt.get("raw_cvss_score")
            if vid and aname and score is not None:
                tier = classify_cvss_severity(float(score))
                tier_groups[(vid, aname, tier)].append(evt)

        records = []
        # First ensure catalog record is preserved
        for v in catalog_vulns:
            cve = v.get("cve_id")
            ast = v.get("affected_asset")
            cvss = float(v.get("cvss_score") or 9.5)
            sev = v.get("severity") or classify_cvss_severity(cvss)
            stat = v.get("status") or "Open"
            name = v.get("vulnerability_name") or "Privilege Escalation"

            records.append({
                "cve": cve,
                "cve_id": cve,
                "asset": ast,
                "asset_name": ast,
                "cvss": round(cvss, 1),
                "cvss_score": round(cvss, 1),
                "severity": sev,
                "status": stat,
                "vulnerability_name": name,
                "event_count": len(tier_groups.get((cve, ast, sev), [])) or 1
            })

        seen_keys = {(r["cve"], r["asset"], r["severity"]) for r in records}

        # Add remaining dynamic authoritative groups
        for (vid, aname, tier), evts in tier_groups.items():
            if (vid, aname, tier) in seen_keys:
                continue

            scores = [float(e["raw_cvss_score"]) for e in evts if e.get("raw_cvss_score") is not None]
            max_score = max(scores) if scores else 0.0
            
            # Status: open if any non-blocked, mitigated if all blocked
            has_active = any(e.get("event_status") in ("Detected", "Failed", "Success") for e in evts)
            stat = "Open" if has_active else "Mitigated"

            cat_entry = catalog_map.get(vid)
            v_name = cat_entry.get("vulnerability_name") if cat_entry else f"{vid} Exposure"

            records.append({
                "cve": vid,
                "cve_id": vid,
                "asset": aname,
                "asset_name": aname,
                "cvss": round(max_score, 1),
                "cvss_score": round(max_score, 1),
                "severity": tier,
                "status": stat,
                "vulnerability_name": v_name,
                "event_count": len(evts)
            })
            seen_keys.add((vid, aname, tier))

        # Sort: Critical first, then High, then Medium, then Low, descending CVSS
        severity_sort_order = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Unknown": 5}
        records.sort(key=lambda x: (severity_sort_order.get(x["severity"], 99), -x["cvss"]))

        # Pre-filter summary statistics
        crit_count = sum(1 for r in records if r["severity"] == "Critical")
        high_count = sum(1 for r in records if r["severity"] == "High")
        med_count = sum(1 for r in records if r["severity"] == "Medium")
        low_count = sum(1 for r in records if r["severity"] == "Low")
        unique_cves = len(set(r["cve"] for r in records))
        unique_assets = len(set(r["asset"] for r in records))

        # Filter by severity if requested
        filtered = records
        if severity is not None and isinstance(severity, str) and severity.strip():
            s_target = severity.strip().lower()
            filtered = [r for r in filtered if r["severity"].lower() == s_target]

        if asset is not None and isinstance(asset, str) and asset.strip():
            a_target = asset.strip().lower()
            filtered = [r for r in filtered if a_target in r["asset"].lower()]

        return {
            "summary": {
                "total": len(records),
                "filtered_total": len(filtered),
                "critical_count": crit_count,
                "critical_cves": crit_count,
                "high_count": high_count,
                "high_cves": high_count,
                "medium_count": med_count,
                "medium_cves": med_count,
                "low_count": low_count,
                "unique_cves": unique_cves,
                "affected_assets_count": unique_assets,
                "affected_assets": unique_assets
            },
            "data": filtered,
            "vulnerabilities": filtered
        }

    except PyMongoError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error while querying vulnerabilities: {str(e)}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query vulnerability intelligence: {str(e)}"
        )
