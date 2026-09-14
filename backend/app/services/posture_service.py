"""
backend/app/services/posture_service.py

Milestone 4 — Task 15: Overall Security Posture Score Service.

Calculates an overall security-health metric (0–100, higher = better) dynamically
grounded in authoritative project data across the five required M4 conditions:
1. Critical vulnerabilities (from vulnerabilities catalog & security_events telemetry)
2. Active incidents (Open / Investigating incidents from incidents collection)
3. High-risk assets (criticality = Critical or affected by Critical threats)
4. Unresolved threats (detected events awaiting resolution)
5. Threat volume (Isolation Forest anomalies & suspicious events)

Scoring Methodology (Deterministic & Normalized 0–100):
- Perfect Baseline: 100 points
- Deductions:
  - Critical Vulnerabilities: 1.5 pts per critical CVE (cap: 25 pts)
  - Active Incidents: 2.0 pts per open/investigating incident (cap: 25 pts)
  - High-Risk Assets: 5.0 pts per high-risk asset (cap: 20 pts)
  - Unresolved Threats: 0.5 pts per detected threat event (cap: 15 pts)
  - Threat Volume: 0.15 pts per anomaly/suspicious event (cap: 15 pts)
- Status Bands:
  - Good:     score >= 75
  - Warning:  50 <= score < 75
  - Critical: score < 50
"""

from datetime import datetime, timezone
import math
from typing import Dict, Any, List
from pymongo.database import Database
from backend.app.core.database import get_database

class SecurityPostureService:
    @staticmethod
    def calculate_posture(db: Database = None) -> Dict[str, Any]:
        if db is None:
            db = get_database()

        # Total denominators for authoritative ratio calculations
        total_events = max(1, db["security_events"].count_documents({}))
        total_incidents = max(1, db["incidents"].count_documents({}))
        total_assets = max(1, db["assets"].count_documents({}))

        # 1. Critical Vulnerabilities (Cap: 25 pts, 1.5 pts per CVE)
        crit_vuln_cves = set()
        for v in db["vulnerabilities"].find({"severity": "Critical"}, {"cve_id": 1}):
            if v.get("cve_id"):
                crit_vuln_cves.add(v["cve_id"])
        for e in db["security_events"].find({"raw_cvss_score": {"$gte": 9.0}}, {"cve_id": 1}):
            if e.get("cve_id"):
                crit_vuln_cves.add(e["cve_id"])
        
        crit_vuln_count = len(crit_vuln_cves)
        # Apply 1.5 pts per critical CVE, cap at 25 pts
        vuln_penalty = min(25.0, crit_vuln_count * 1.5)

        # 2. Active Incidents (Cap: 25 pts, 2.0 pts per incident)
        active_inc_count = db["incidents"].count_documents({
            "status": {"$in": ["Open", "Investigating"]}
        })
        incident_penalty = min(25.0, active_inc_count * 2.0)

        # 3. High-Risk Assets (Cap: 20 pts, 5.0 pts per asset)
        high_risk_assets = set()
        for a in db["assets"].find({"criticality": "Critical"}, {"asset_name": 1, "asset_id": 1}):
            high_risk_assets.add(a.get("asset_name") or a.get("asset_id"))
        for inc in db["incidents"].find({"risk_level": "Critical"}, {"affected_asset": 1}):
            if inc.get("affected_asset"):
                high_risk_assets.add(inc["affected_asset"])
        high_risk_asset_count = len(high_risk_assets)
        asset_penalty = min(20.0, high_risk_asset_count * 5.0)

        # 4. Unresolved Threats (Cap: 15 pts, 0.5 pts per threat)
        unresolved_threats_count = db["security_events"].count_documents({
            "event_status": {"$in": ["Detected", "Open", "Investigating"]}
        })
        threat_penalty = min(15.0, unresolved_threats_count * 0.5)

        # 5. Threat Volume (Cap: 15 pts, 0.15 pts per anomaly/suspicious event)
        threat_volume_count = db["threat_predictions"].count_documents({
            "prediction": "Suspicious"
        })
        volume_penalty = min(15.0, threat_volume_count * 0.15)

        # Total Penalty & Posture Score Calculation
        total_penalty = vuln_penalty + incident_penalty + asset_penalty + threat_penalty + volume_penalty
        raw_score = 100.0 - total_penalty
        posture_score = max(0, min(100, int(round(raw_score))))

        # Status Band Determination
        if posture_score >= 75:
            posture_status = "Good"
        elif posture_score >= 50:
            posture_status = "Warning"
        else:
            posture_status = "Critical"

        # Explanations of contributing factors
        explanations = []
        if crit_vuln_count > 0:
            explanations.append(f"{crit_vuln_count} critical vulnerabilities identified requiring patch remediation (-{vuln_penalty:.1f} pts)")
        if active_inc_count > 0:
            explanations.append(f"{active_inc_count} active security incidents currently pending containment (-{incident_penalty:.1f} pts)")
        if high_risk_asset_count > 0:
            explanations.append(f"{high_risk_asset_count} high-risk enterprise assets exposed to critical threats (-{asset_penalty:.1f} pts)")
        if unresolved_threats_count > 0:
            explanations.append(f"{unresolved_threats_count} unresolved detected telemetry threats awaiting investigation (-{threat_penalty:.1f} pts)")
        if threat_volume_count > 0:
            explanations.append(f"{threat_volume_count} anomalous events flagged by ML Isolation Forest (-{volume_penalty:.1f} pts)")

        if not explanations:
            explanations.append("All enterprise systems operating within nominal baseline parameters.")

        return {
            "posture_score": posture_score,
            "status": posture_status,
            "scoring_methodology": "Normalized 0-100 deterministic risk-subtraction across 5 M4 conditions (baseline 100 minus bounded deductions).",
            "conditions": {
                "critical_vulnerabilities": {
                    "count": crit_vuln_count,
                    "penalty": round(vuln_penalty, 1),
                    "impact": "High active CVE exposure requiring remediation"
                },
                "active_incidents": {
                    "count": active_inc_count,
                    "penalty": round(incident_penalty, 1),
                    "impact": f"{active_inc_count} incidents in Open or Investigating status"
                },
                "high_risk_assets": {
                    "count": high_risk_asset_count,
                    "penalty": round(asset_penalty, 1),
                    "impact": f"{high_risk_asset_count} assets hosting critical threats or classified critical"
                },
                "unresolved_threats": {
                    "count": unresolved_threats_count,
                    "penalty": round(threat_penalty, 1),
                    "impact": f"{unresolved_threats_count} telemetry threat events awaiting resolution"
                },
                "threat_volume": {
                    "count": threat_volume_count,
                    "penalty": round(volume_penalty, 1),
                    "impact": f"{threat_volume_count} anomaly events detected by ML classifier"
                }
            },
            "explanations": explanations,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
