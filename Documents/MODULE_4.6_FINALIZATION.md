# Milestone 4 — Module 4.6: Final System Integration, Performance Optimization & Verification

## 1. Milestone 4 Objective

Milestone 4 (M4) delivers the end-to-end operationalization and visualization layer for the Security Operations Center (SOC) Dashboard. It synthesizes foundational telemetry ingestion from Milestone 1 (M1), machine learning anomaly detection and threat classification models from Milestone 2 (M2), and operational risk scoring, attack chain correlation, and incident prioritization from Milestone 3 (M3) into a cohesive, responsive, and authoritative SOC operations and executive reporting platform.

---

## 2. End-to-End Architecture

The system operates across a unidirectional, authoritative data processing and presentation pipeline:

```
[ Security Telemetry ] ──> [ ML Detection Engine ] ──> [ Risk & Correlation Engine ] ──> [ React SOC Dashboard ]
(M1: Ingestion & Feeds)     (M2: IsolationForest / RF)    (M3: Scorer / Chains / Lifecycle)    (M4: Interactive Web UI)
           │                             │                                 │                             │
           ▼                             ▼                                 ▼                             ▼
    MongoDB Collections:          MongoDB Telemetry:             MongoDB Collections:             FastAPI Endpoints:
  • security_events             • predictions                  • incidents                      • /metrics, /events
  • assets                      • anomaly_scores               • attack_chains                  • /predictions, /predict
  • threat_intel                • confidence_scores            • analyst_feedback               • /v1/risk/*, /api/v1/incidents
  • mitre_attack_mapping                                       • vulnerabilities                • /posture, /api/reports/*
```

### Data Pipeline Stages:
1. **Security Telemetry Layer (M1):** Raw events, asset registers, threat intelligence feeds (IOCs), and MITRE ATT&CK reference mapping stored in MongoDB.
2. **Machine Learning Layer (M2):** Preprocessing, Isolation Forest unsupervised anomaly detection, Random Forest supervised threat classification, confidence scoring (0–100%), and model version tracking (`v1.0.0`).
3. **Operational Risk & Incident Engine (M3):** Multi-factor risk calculation (0–100 score, Low/Medium/High/Critical risk levels), P1–P4 operational priority assignment, attack chain correlation, rule-based analyst recommendations, and incident state tracking.
4. **Interactive Dashboard & Executive Platform (M4):** React-based SPA (Vite + Tailwind/CSS) communicating with FastAPI REST backend endpoints with optimized response times (<350 ms), deterministic posture scoring, interactive drill-downs, and exportable executive reports.

---

## 3. Integrated Telemetry & Intelligence Components

The dashboard directly couples all prior project telemetry domains into unified views without client-side synthetic fallbacks:

- **M1 Telemetry:** Authoritative network and endpoint events (`event_id`, `timestamp`, `source_ip`, `destination_ip`, `event_type`, `event_severity`), asset inventory (`asset_name`, `criticality`, `department`), threat intel indicators, and reference MITRE mappings.
- **M2 Intelligence:** Machine learning prediction labels, anomaly probabilities, confidence scores (0–100%), and model metadata.
- **M3 Risk & Incident State:** Deterministic composite risk score, risk level, operational priority (`P1`–`P4`), correlated event chains, explainable risk reasons, recommendation lists, and lifecycle statuses (`Open`, `Investigating`, `Resolved`, `False Positive`).

---

## 4. Milestone 4 Tasks Implementation Summary (Tasks 1–17)

| Task | Exact Terminology | What Was Implemented | Authoritative Data Source / API |
|---|---|---|---|
| **Task 1** | End-to-End Integration Verification | Full pipeline health, DB connectivity, collection schemas, and cross-milestone API contract integrity verification. | MongoDB collections, `/events`, `/assets`, `/predictions`, `/v1/risk/summary`, `/v1/incidents` |
| **Task 2** | SOC Overview Dashboard | 6 authoritative KPI cards (Total Events, Active Incidents, Critical Threats, Security Posture, Threat Volume, High-Risk Assets), severity distribution, and temporal trend visualization. | `/metrics`, `/posture`, `/trends` |
| **Task 3** | Critical Threat Panel | Real-time critical incident table with 6 exact columns: Incident ID, Threat Type, Risk Score, Affected Asset, ML Confidence, Time. Direct investigation routing. | `GET /api/v1/incidents?risk_level=Critical` |
| **Task 4** | Threat Investigation View | Complete incident deep-dive displaying 12 authoritative fields (ID, Threat Type, Risk Score, Risk Level, Confidence, Asset, Source IP, User, IOC Status, MITRE Technique, CVE, CVSS) and 6 explainable boolean risk factors. | `GET /api/v1/incidents/{id}` |
| **Task 5** | Incident Attack Chain Visualization | Chronological multi-stage attack chain view with stage progression (Event ID, MITRE Technique, Risk Level, User, Asset). | `GET /api/v1/incidents/{id}/attack-chain` |
| **Task 6** | MITRE Technique Analysis | Technique analysis table and distribution chart (Technique, Name, Events, Risk) derived dynamically from event types joined with mapping reference. | `GET /mitre`, `GET /mitre/techniques` |
| **Task 7** | Vulnerabilities Catalog & Intelligence | CVE vulnerability ledger with summary KPI cards (Critical, High, Medium CVEs, Affected Assets) and filtering by severity. Columns: CVE, Asset, CVSS, Severity, Status. | `GET /vulnerabilities`, `GET /v1/vulnerabilities`, `GET /api/v1/vulnerabilities` |
| **Task 8** | IOC Intelligence | Threat intelligence feed viewer with indicator status, type filtering (IP, Domain, Hash), threat association count, and affected asset tracking. | `GET /threat-intel`, `GET /threat-intel/iocs` |
| **Task 9** | Advanced Filtering | 10 exact filter dimensions (Severity, Risk Level, Threat Type, Asset, Department, MITRE Technique, CVE, IOC Status, Incident Status, Date Range) with dynamic filter option metadata. | `GET /incidents/filters`, `GET /api/v1/incidents` |
| **Task 10** | Interactive Drill-Down Flow | Unbroken contextual navigation flow: Dashboard KPI → Incident Table → Attack Chain Visualizer → Event Investigation (`onInvestigateEvent`). | Frontend navigation state & route routing |
| **Task 11** | Analyst Recommendations | Contextual rule-based mitigation recommendations across Immediate Containment, Investigation, and Remediation categories. | `GET /api/v1/incidents/{id}/recommendations` |
| **Task 12** | Incident Management Lifecycle | Finite state machine enforcing valid status transitions (`Open` → `Investigating` → `Resolved` / `Open` → `False Positive`), rejecting invalid reversals with HTTP 400. | `PATCH /api/v1/incidents/{id}/status` |
| **Task 13** | Analyst Feedback Persistence | Analyst feedback capture (`Correct`, `False Positive`) with authenticated analyst identity, written to `analyst_feedback` collection. | `POST /predictions/{id}/feedback`, `GET /predictions/{id}/feedback` |
| **Task 14** | AI-Assisted Risk Explanation | Multi-factor risk factor breakdown with 6 explainable boolean indicators and specific contextual risk reasons. | `IncidentService` / `RiskEngine` |
| **Task 15** | Overall Security Posture Assessment | Deterministic security-health scoring engine (0–100 scale) evaluating 5 core environmental conditions. | `GET /posture`, `GET /api/v1/posture`, `GET /v1/posture` |
| **Task 16** | Executive Security Summary | High-level executive dashboard aggregating overall posture score, core metrics, critical CVE breakdown, affected assets, and recent critical incidents. | `GET /api/reports/executive/data` |
| **Task 17** | Generate Security Report | Dynamic, on-demand generation and download of formatted executive security reports in PDF (`%PDF` binary) and CSV (`text/csv`). | `GET /api/reports/executive?format=pdf|csv` |

---

## 5. Security Posture Scoring Methodology

The Security Posture Score is a normalized, deterministic value between 0 and 100 calculated by `SecurityPostureService`. A higher score represents a healthier, more secure posture.

### Scoring Formula & Deductions:
- **Starting Baseline:** 100 points
- **Condition Deductions:**
  1. **Critical Vulnerabilities:** 1.5 points deducted per critical CVE in the catalog or telemetry (Maximum penalty cap: 25.0 points).
  2. **Active Incidents:** 2.0 points deducted per incident currently in `Open` or `Investigating` status (Maximum penalty cap: 25.0 points).
  3. **High-Risk Assets:** 5.0 points deducted per asset with Critical criticality or compromised by critical threats (Maximum penalty cap: 20.0 points).
  4. **Unresolved Threats:** 0.5 points deducted per detected threat event awaiting mitigation (Maximum penalty cap: 15.0 points).
  5. **Threat Volume:** 0.15 points deducted per anomaly/suspicious event detected by ML models (Maximum penalty cap: 15.0 points).

### Status Classification:
- **Good:** Score $\ge 75$
- **Warning:** $50 \le \text{Score} < 75$
- **Critical:** Score $< 50$

*Current Verified State:* Score = **25 / 100** (`Critical`), reflecting 15 critical CVEs (22.5 pt deduction), 38 active incidents (capped at 25.0 pt deduction), 21 high-risk assets (capped at 20.0 pt deduction), and high threat volume.

---

## 6. Executive Security Summary & Report Generation

### Executive Summary Endpoint (`GET /api/reports/executive/data`):
Provides a unified JSON payload for executive decision-makers containing:
- Live posture score, status, and 5-condition penalty audit.
- Executive metrics: critical threats count, active incidents count, critical vulnerabilities count, affected assets count.
- Ranked list of critical CVEs with CVSS scores and remediation statuses.
- Top affected assets with risk levels and department ownership.
- Recent critical incident feed with timestamps, threat classifications, and analyst assignees.

### Dynamic Report Export (`GET /api/reports/executive?format=pdf|csv`):
`SecurityReportService` generates dynamic reports on request without caching or static file dependencies:
- **PDF Report (`format=pdf`):** Produced with standard `%PDF` header, ReportLab PDF generation, metadata headers (`Content-Disposition: attachment; filename="executive_security_report_YYYYMMDD_HHMMSS.pdf"`), executive summary tables, and posture audit.
- **CSV Report (`format=csv`):** Standard CSV structure with `Metric,Value` headers, posture breakdown, and incident details for import into spreadsheet and BI tooling.

---

## 7. MITRE ATT&CK Mapping Implementation

### Authoritative Derivation:
In the authoritative MongoDB dataset, raw records in `security_events` do not contain populated `mitre_id` fields. Rather than modifying or corrupting raw telemetry records, the MITRE Technique Analysis (`GET /mitre` and `GET /mitre/techniques`) derives technique mappings dynamically:
1. `security_events` records are grouped by `event_type`.
2. Event types are joined against the authoritative reference collection `mitre_attack_mapping` (`event_type` → `mitre_id`, `technique_name`, `tactic`).
3. Dominant risk level is derived from aggregated event severities for that event type.
4. Technique `T1110` (Brute Force) maps to 179 authoritative events of type `Failed Login` with dominant severity `High`.

> **Verification Note:** Raw `security_events` were strictly preserved in their original state. No synthetic `mitre_id` values were backfilled into raw records.

---

## 8. Verification Results & Quality Gate

### Contract Verification Suites:
- **M4 Task 4 Contract Suite (`scripts/verify_m4_task4_contracts.py`):** **PASS**
  - Verified 12 exact incident details fields, 6 boolean risk factors, multi-event correlation, clean N/A handling, and list endpoints.
- **M4 Batch A Contract Suite (`scripts/verify_m4_batch_a_contracts.py`):** **PASS**
  - Verified Task 5 attack chains, Task 6 MITRE techniques & distribution, Task 7 vulnerability catalog & filters, Task 8 IOC intelligence & type filters, and frontend service wiring.
- **M4 Batch B Contract Suite (`scripts/verify_m4_batch_b_contracts.py`):** **PASS**
  - Verified Task 9 advanced filtering (10 filters), Task 10 drill-down flow, Task 11 analyst recommendations, Task 12 incident lifecycle FSM, Task 13 feedback persistence, and Task 14 AI risk explanations.
- **M4 Batch C Contract Suite (`scripts/verify_m4_batch_c_contracts.py`):** **PASS**
  - Verified Task 15 security posture calculation, Task 16 executive summary data contract, and Task 17 PDF/CSV downloads.

### Production Build:
- **Command:** `npm run build` (in `frontend/`)
- **Status:** **PASS** (Exit code 0, 2728 modules transformed, built in 29.00s, production assets generated cleanly in `dist/`).

### Test Suite Execution:
- **Command:** `python -m pytest`
- **Result:** **150 passed, 0 failed, 4 warnings** in 19.78s (**100% Pass Rate**).
- **Test Alignment:** The 3 legacy M3 unit test assertions that previously expected `incident.priority` to be `None` (`test_incident_creation_and_field_preservation`, `test_get_incident_by_id_and_404`, `test_priority_preserved_as_none`) have been aligned with the active M4 priority derivation contract (`Critical` $\rightarrow$ `P1`). All field preservation and regression coverage remain intact.

---

## 9. Runtime Performance Benchmarks

Direct API latency benchmarks measured via FastAPI TestClient on the integrated environment:

| Endpoint | Target Component | HTTP Status | Response Time | Result Count / Payload |
|---|---|:---:|:---:|---|
| `/v1/risk/summary` | Risk Summary | `200 OK` | **303.9 ms** | 4 summary metric categories |
| `/v1/risk/high?page=1&limit=10` | High-Risk Incidents | `200 OK` | **172.4 ms** | 10 paginated incident records |
| `/v1/attack-chains?window_minutes=15` | Attack Chains | `200 OK` | **246.4 ms** | 245 correlation chains |
| `/v1/vulnerabilities` | Vulnerabilities Catalog | `200 OK` | **91.2 ms** | 60 CVE vulnerability records |
| `/mitre` | MITRE ATT&CK Analysis | `200 OK` | **56.4 ms** | 1 technique (`T1110`), coverage summary |
| `/api/reports/executive/data` | Executive Security Data | `200 OK` | **283.5 ms** | Posture score, metrics, top CVEs & assets |

All core endpoints respond well within standard SLA thresholds (<350 ms).

---

## 10. Final Route Architecture & Registration

The FastAPI routing table enforces clear namespace separation without route collision or ambiguous overrides:

- **Executive & Reports Router:**
  - `GET /api/reports/executive/data` (Canonical Executive JSON)
  - `GET /api/reports/executive?format=pdf|csv` (Report Download)
- **Vulnerabilities Router:**
  - `GET /vulnerabilities`, `GET /v1/vulnerabilities`, `GET /api/v1/vulnerabilities`
- **Attack Chains Router:**
  - `GET /v1/attack-chains` (windowed aggregate)
  - `GET /api/v1/attack-chains`
  - `GET /api/v1/incidents/{incident_id}/attack-chain` (incident-specific stages)
- **Risk & Incidents Router:**
  - `GET /v1/risk/summary`, `GET /v1/risk/high`, `POST /v1/risk/calculate`
  - `GET /api/v1/incidents`, `GET /api/v1/incidents/{id}`, `PATCH /api/v1/incidents/{id}/status`
- **MITRE Router:**
  - `GET /mitre` (coverage summary, techniques, and synchronized distribution)
  - `GET /mitre/techniques` (dedicated technique analysis table endpoint)

---

## 11. Known Limitations & Baseline Failures

1. **M4 Priority Contract Alignment:**
   Incident priority is derived dynamically based on `risk_level` (`Critical` $\rightarrow$ `P1`, `High` $\rightarrow$ `P2`, `Moderate` $\rightarrow$ `P3`, `Medium/Low` $\rightarrow$ `P4`) per SOC operational guidelines. The 3 legacy M3 unit tests expecting `None` have been formally aligned with this contract, achieving a clean 150/150 test pass rate.
2. **Dynamic Retraining:**
   Analyst feedback (`POST /predictions/{id}/feedback`) is persisted to MongoDB for auditability and future retraining pipelines; the dashboard does not trigger automatic online machine learning model retraining.
3. **Large Frontend Bundle Warning:**
   Vite build reports chunk size warnings (>500 kB) for minified vendor bundles (`html2canvas`, `jspdf`, and Lucide icon sets). This does not impede production execution.

---

## 12. Deployment & Execution Guide

### Prerequisites:
- Python 3.10+ (tested on Python 3.13)
- Node.js 18+ and npm
- MongoDB 6.0+ instance (local or MongoDB Atlas connection)

### Configuration (`.env` in repository root):
```env
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
DATABASE_NAME=security_operations_db
JWT_SECRET_KEY=soc-dashboard-secret-key-m4
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

### Backend Startup:
```bash
# Navigate to project root
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation available at `http://127.0.0.1:8000/docs`.

### Frontend Startup:
```bash
cd frontend
npm install
npm run dev
```
Interactive dashboard available at `http://localhost:5173`.

### Production Build:
```bash
cd frontend
npm run build
```
Compiled production assets are output to `frontend/dist/`.

---

## 13. Final Module 4.6 Sign-Off

- **Module 4.1 to 4.5 Implementation:** Complete
- **Module 4.6 Verification & Audit:** Complete
- **All 4 Milestone 4 Contract Suites:** 100% Passed
- **Frontend Production Build:** Succeeded
- **Application Code Status:** Frozen
