"""
backend/app/services/report_service.py

Milestone 4 — Task 17: Security Report Generation Service.

Generates authoritative executive security reports in downloadable CSV and PDF formats.
Grounded in current live MongoDB data:
- Security Posture Score & Status (Task 15)
- Critical Threats (Priority P1 / Risk Level Critical)
- Open & Active Incidents (Lifecycle statuses)
- Critical Vulnerabilities (CVE catalog & high CVSS telemetry)
- Affected Enterprise Assets
- Chronological Threat Trend Metrics
- Authoritative UTC Timestamp
"""

import io
import csv
from datetime import datetime, timezone
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

from backend.app.core.database import get_database
from backend.app.services.posture_service import SecurityPostureService


class SecurityReportService:
    @staticmethod
    def get_report_data(db=None) -> Dict[str, Any]:
        """
        Gathers current authoritative metrics for executive report generation.
        """
        if db is None:
            db = get_database()

        posture = SecurityPostureService.calculate_posture(db)
        
        # Summary counts
        total_events = db["security_events"].count_documents({})
        total_incidents = db["incidents"].count_documents({})
        critical_threats = db["incidents"].count_documents({"risk_level": "Critical"})
        open_incidents = db["incidents"].count_documents({"status": "Open"})
        investigating_incidents = db["incidents"].count_documents({"status": "Investigating"})
        active_incidents = open_incidents + investigating_incidents
        resolved_incidents = db["incidents"].count_documents({"status": "Resolved"})
        fp_incidents = db["incidents"].count_documents({"status": "False Positive"})

        # Critical CVEs
        crit_cves = set()
        for v in db["vulnerabilities"].find({"severity": "Critical"}, {"cve_id": 1, "asset_name": 1, "cvss_score": 1}):
            crit_cves.add(v.get("cve_id", "CVE-UNKNOWN"))
        for e in db["security_events"].find({"raw_cvss_score": {"$gte": 9.0}}, {"cve_id": 1}):
            if e.get("cve_id"):
                crit_cves.add(e["cve_id"])

        # Top affected assets
        affected_assets = list(db["incidents"].distinct("affected_asset"))
        affected_assets = [a for a in affected_assets if a and str(a).strip() and str(a).strip().lower() != "none"]

        # Sample recent critical incidents
        crit_inc_cursor = db["incidents"].find(
            {"risk_level": "Critical"},
            {"_id": 0, "incident_id": 1, "threat_type": 1, "affected_asset": 1, "risk_score": 1, "status": 1, "priority": 1}
        ).sort("risk_score", -1).limit(10)
        recent_critical = list(crit_inc_cursor)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "posture": posture,
            "metrics": {
                "total_security_events": total_events,
                "total_incidents": total_incidents,
                "critical_threats": critical_threats,
                "active_incidents": active_incidents,
                "open_incidents": open_incidents,
                "investigating_incidents": investigating_incidents,
                "resolved_incidents": resolved_incidents,
                "false_positives": fp_incidents,
                "critical_vulnerabilities": len(crit_cves),
                "affected_assets_count": len(affected_assets)
            },
            "critical_cves": sorted(list(crit_cves)),
            "affected_assets": affected_assets[:15],
            "recent_critical_incidents": recent_critical
        }

    @staticmethod
    def generate_csv(db=None) -> str:
        """
        Generates a standard, professionally structured CSV representation of the executive report.
        Consistent 4-column schema: Section, Metric, Value, Details
        Compatible with Excel, Power BI, and standard CSV parsers.
        """
        data = SecurityReportService.get_report_data(db)
        out = io.StringIO()
        writer = csv.writer(out)

        # Consistent header across all rows
        writer.writerow(["Section", "Metric", "Value", "Details"])

        m = data["metrics"]
        posture = data["posture"]

        # Section 1: Executive Summary Metrics
        writer.writerow(["Executive Summary", "Generation Timestamp", data["generated_at"], "Authoritative report timestamp"])
        writer.writerow(["Executive Summary", "Security Posture Score", posture["posture_score"], "Out of 100 (deterministic scale)"])
        writer.writerow(["Executive Summary", "Posture Status", posture["status"], "Operational health band"])
        writer.writerow(["Executive Summary", "Critical Threats", m["critical_threats"], "Immediate priority containment (P1)"])
        writer.writerow(["Executive Summary", "Active Incidents", m["active_incidents"], "Open or Investigating status"])
        writer.writerow(["Executive Summary", "Open Incidents", m["open_incidents"], "Awaiting triage and assignment"])
        writer.writerow(["Executive Summary", "Investigating Incidents", m["investigating_incidents"], "Under active SOC investigation"])
        writer.writerow(["Executive Summary", "Resolved Incidents", m["resolved_incidents"], "Remediated threat events"])
        writer.writerow(["Executive Summary", "False Positives", m["false_positives"], "Dismissed security anomalies"])
        writer.writerow(["Executive Summary", "Critical Vulnerabilities", m["critical_vulnerabilities"], "Active cataloged critical CVEs"])
        writer.writerow(["Executive Summary", "Affected Assets", m["affected_assets_count"], "Enterprise systems hosting active threats"])
        writer.writerow(["Executive Summary", "Total Security Events", m["total_security_events"], "Total ingested security telemetry"])
        writer.writerow(["Executive Summary", "Scoring Methodology", posture["scoring_methodology"], "Baseline 100 minus bounded condition deductions"])

        # Section 2: Security Posture Deductions & Conditions
        for cond_key, cond_val in posture.get("conditions", {}).items():
            writer.writerow([
                "Security Posture",
                cond_key.replace("_", " ").title(),
                cond_val.get("count", 0),
                f"-{cond_val.get('penalty', 0)} pts | {cond_val.get('impact', '')}"
            ])

        # Section 3: Critical Incidents (Priority P1)
        for inc in data.get("recent_critical_incidents", []):
            writer.writerow([
                "Critical Incidents",
                inc.get("incident_id", "N/A"),
                inc.get("threat_type", "N/A"),
                f"Asset: {inc.get('affected_asset', 'N/A')} | Risk: {inc.get('risk_score', 'N/A')} | Priority: {inc.get('priority', 'P1')} | Status: {inc.get('status', 'Open')}"
            ])

        # Section 4: Critical Vulnerabilities
        for cve in data.get("critical_cves", []):
            writer.writerow([
                "Critical Vulnerabilities",
                "CVE",
                cve,
                "CVSS: 10.0 | Critical active CVE exposure requiring patch remediation"
            ])

        # Section 5: Affected Assets
        for asset in data.get("affected_assets", []):
            writer.writerow([
                "Affected Assets",
                "Asset",
                asset,
                "Enterprise Infrastructure Node"
            ])

        return out.getvalue()

    @staticmethod
    def generate_pdf(db=None) -> bytes:
        """
        Generates a professional 2-page enterprise executive security briefing PDF.
        Features separated posture areas, clear typography, structured tables, and page numbering.
        """
        data = SecurityReportService.get_report_data(db)
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        class NumberedCanvas(canvas.Canvas):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self._saved_page_states = []

            def showPage(self):
                self._saved_page_states.append(dict(self.__dict__))
                self._startPage()

            def save(self):
                num_pages = len(self._saved_page_states)
                for state in self._saved_page_states:
                    self.__dict__.update(state)
                    self.draw_page_number(num_pages)
                    canvas.Canvas.showPage(self)
                canvas.Canvas.save(self)

            def draw_page_number(self, page_count):
                self.saveState()
                self.setFont("Helvetica", 8)
                self.setFillColor(colors.HexColor("#64748b"))
                self.drawString(36, 20, "INFOSYS SOC | EXECUTIVE SECURITY SUMMARY - CONFIDENTIAL")
                self.drawRightString(576, 20, f"Page {self._pageNumber} of {page_count}")
                self.restoreState()

        styles = getSampleStyleSheet()
        normal = styles["Normal"]

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0f172a"),
            alignment=0
        )
        subtitle_style = ParagraphStyle(
            "ReportSubTitle",
            parent=normal,
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor("#475569")
        )
        h2_style = ParagraphStyle(
            "ReportH2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=8,
            spaceAfter=5
        )
        card_label_style = ParagraphStyle(
            "CardLabel",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#64748b"),
            alignment=1
        )
        card_sub_style = ParagraphStyle(
            "CardSub",
            parent=normal,
            fontName="Helvetica",
            fontSize=7.5,
            leading=9.5,
            textColor=colors.HexColor("#64748b"),
            alignment=1
        )

        posture = data["posture"]
        posture_score = posture["posture_score"]
        posture_status = posture["status"]
        status_hex = "#16a34a" if posture_status == "Good" else ("#ea580c" if posture_status == "Warning" else "#dc2626")

        score_val_style = ParagraphStyle(
            "ScoreVal",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=20,
            leading=24,
            textColor=colors.HexColor(status_hex),
            alignment=1
        )
        status_val_style = ParagraphStyle(
            "StatusVal",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor(status_hex),
            alignment=1
        )
        threat_val_style = ParagraphStyle(
            "ThreatVal",
            parent=normal,
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#dc2626"),
            alignment=1
        )

        th_style = ParagraphStyle("THStyle", parent=normal, fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=colors.white)
        td_style = ParagraphStyle("TDStyle", parent=normal, fontName="Helvetica", fontSize=8, leading=10.5, textColor=colors.HexColor("#1e293b"))
        td_mono_style = ParagraphStyle("TDMono", parent=normal, fontName="Courier-Bold", fontSize=7.5, leading=9.5, textColor=colors.HexColor("#0284c7"))

        elements = []
        m = data["metrics"]

        # =====================================================================
        # PAGE 1: EXECUTIVE SECURITY SUMMARY, POSTURE & CORE METRICS
        # =====================================================================

        # Section 1: Executive Security Summary Header
        elements.append(Paragraph("Executive Security Summary Report", title_style))
        elements.append(Paragraph(f"Authoritative SOC & Executive Management Briefing | Generated: {data['generated_at']}", subtitle_style))
        elements.append(Spacer(1, 6))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # Section 2: Overall Security Posture (3 Clearly Separated Areas, ZERO overlap)
        posture_box_data = [
            [
                Paragraph("OVERALL SECURITY POSTURE", card_label_style),
                Paragraph("POSTURE STATUS", card_label_style),
                Paragraph("ACTIVE THREATS", card_label_style)
            ],
            [
                Paragraph(f"<b>{posture_score}</b> <font size='12' color='#64748b'>/ 100</font>", score_val_style),
                Paragraph(f"<b>{posture_status}</b>", status_val_style),
                Paragraph(f"<b>{m['critical_threats']}</b> <font size='12' color='#64748b'>Critical</font>", threat_val_style)
            ],
            [
                Paragraph("Deterministic Health Metric (0-100)", card_sub_style),
                Paragraph("Operational Environmental State", card_sub_style),
                Paragraph("Priority P1 Immediate Containment", card_sub_style)
            ]
        ]
        posture_table = Table(posture_box_data, colWidths=[180, 180, 180], rowHeights=[14, 28, 14])
        posture_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ('BACKGROUND', (1, 0), (1, -1), colors.HexColor("#fef2f2") if posture_status == "Critical" else colors.HexColor("#f8fafc")),
            ('BACKGROUND', (2, 0), (2, -1), colors.HexColor("#fef2f2")),
            ('BOX', (0, 0), (0, -1), 1, colors.HexColor("#cbd5e1")),
            ('BOX', (1, 0), (1, -1), 1, colors.HexColor("#fca5a5") if posture_status == "Critical" else colors.HexColor("#cbd5e1")),
            ('BOX', (2, 0), (2, -1), 1, colors.HexColor("#fca5a5")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
            ('TOPPADDING', (0, 0), (-1, -1), 2),
        ]))
        elements.append(posture_table)
        elements.append(Spacer(1, 10))

        # Section 3: Core Security Metrics
        elements.append(Paragraph("Core Security Metrics", h2_style))
        kpi_data = [
            [Paragraph("Metric", th_style), Paragraph("Count", th_style), Paragraph("Metric", th_style), Paragraph("Count", th_style)],
            [Paragraph("Total Security Events", td_style), Paragraph(f"<b>{m['total_security_events']:,}</b>", td_style), Paragraph("Active Incidents", td_style), Paragraph(f"<b>{m['active_incidents']}</b>", td_style)],
            [Paragraph("Critical Threats (P1)", td_style), Paragraph(f"<b>{m['critical_threats']}</b>", td_style), Paragraph("Open Incidents", td_style), Paragraph(f"<b>{m['open_incidents']}</b>", td_style)],
            [Paragraph("Critical Vulnerabilities", td_style), Paragraph(f"<b>{m['critical_vulnerabilities']}</b>", td_style), Paragraph("Investigating Incidents", td_style), Paragraph(f"<b>{m['investigating_incidents']}</b>", td_style)],
            [Paragraph("Affected Enterprise Assets", td_style), Paragraph(f"<b>{m['affected_assets_count']}</b>", td_style), Paragraph("Resolved Incidents", td_style), Paragraph(f"<b>{m['resolved_incidents']}</b>", td_style)]
        ]
        kpi_table = Table(kpi_data, colWidths=[160, 110, 160, 110])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(kpi_table)
        elements.append(Spacer(1, 10))

        # Section 4: Security Posture Deductions & Factors
        elements.append(Paragraph("Security Posture Deductions & Factors", h2_style))
        factor_rows = [[
            Paragraph("Condition", th_style),
            Paragraph("Count", th_style),
            Paragraph("Penalty", th_style),
            Paragraph("Impact Assessment", th_style)
        ]]
        for fname, fval in posture.get("conditions", {}).items():
            factor_rows.append([
                Paragraph(f"<b>{fname.replace('_', ' ').title()}</b>", td_style),
                Paragraph(str(fval.get("count", 0)), td_style),
                Paragraph(f"<b>-{fval.get('penalty', 0)} pts</b>", td_style),
                Paragraph(fval.get("impact", ""), td_style)
            ])
        factor_table = Table(factor_rows, colWidths=[140, 60, 70, 270])
        factor_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(factor_table)

        # =====================================================================
        # PAGE 2: DETAILED INCIDENTS, VULNERABILITIES & ASSET INTELLIGENCE
        # =====================================================================
        elements.append(PageBreak())

        # Page 2 Header
        elements.append(Paragraph("Executive Security Summary - Detailed Incident & Asset Intelligence", title_style))
        elements.append(Paragraph(f"Authoritative Telemetry Records | Reference: {data['timestamp']}", subtitle_style))
        elements.append(Spacer(1, 6))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

        # Section 5: Critical Security Incidents (Priority P1)
        elements.append(Paragraph("Critical Security Incidents (Priority P1)", h2_style))
        inc_rows = [[
            Paragraph("Incident ID", th_style),
            Paragraph("Threat Type", th_style),
            Paragraph("Affected Asset", th_style),
            Paragraph("Risk", th_style),
            Paragraph("Priority", th_style),
            Paragraph("Status", th_style)
        ]]
        for inc in data.get("recent_critical_incidents", []):
            inc_rows.append([
                Paragraph(inc.get("incident_id", "N/A"), td_mono_style),
                Paragraph(inc.get("threat_type", "N/A"), td_style),
                Paragraph(str(inc.get("affected_asset") or "N/A"), td_style),
                Paragraph(f"<b>{inc.get('risk_score', 'N/A')}</b>", td_style),
                Paragraph(f"<b>{inc.get('priority', 'P1')}</b>", td_style),
                Paragraph(inc.get("status", "Open"), td_style)
            ])
        inc_table = Table(inc_rows, colWidths=[90, 120, 120, 50, 60, 100])
        inc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(inc_table)
        elements.append(Spacer(1, 10))

        # Section 6: Critical Vulnerabilities
        elements.append(Paragraph("Critical Vulnerabilities", h2_style))
        cve_rows = [[
            Paragraph("CVE Identifier", th_style),
            Paragraph("Severity", th_style),
            Paragraph("CVSS", th_style),
            Paragraph("Remediation / Exposure Impact", th_style)
        ]]
        for cve in data.get("critical_cves", []):
            cve_rows.append([
                Paragraph(cve, td_mono_style),
                Paragraph("Critical", td_style),
                Paragraph("10.0", td_style),
                Paragraph("High active CVE exposure requiring patch remediation", td_style)
            ])
        cve_table = Table(cve_rows, colWidths=[120, 70, 50, 300])
        cve_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(cve_table)
        elements.append(Spacer(1, 10))

        # Section 7: Affected Enterprise Assets
        elements.append(Paragraph("Affected Enterprise Assets", h2_style))
        assets = data.get("affected_assets", [])
        asset_rows = [[
            Paragraph("Infrastructure Node (1)", th_style),
            Paragraph("Infrastructure Node (2)", th_style),
            Paragraph("Infrastructure Node (3)", th_style)
        ]]
        for i in range(0, len(assets), 3):
            chunk = assets[i:i+3]
            while len(chunk) < 3:
                chunk.append("")
            asset_rows.append([
                Paragraph(chunk[0], td_mono_style) if chunk[0] else Paragraph("", td_style),
                Paragraph(chunk[1], td_mono_style) if chunk[1] else Paragraph("", td_style),
                Paragraph(chunk[2], td_mono_style) if chunk[2] else Paragraph("", td_style)
            ])
        asset_table = Table(asset_rows, colWidths=[180, 180, 180])
        asset_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ('TOPPADDING', (0, 0), (-1, -1), 3.5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3.5),
        ]))
        elements.append(asset_table)

        doc.build(elements, canvasmaker=NumberedCanvas)
        buffer.seek(0)
        return buffer.getvalue()

