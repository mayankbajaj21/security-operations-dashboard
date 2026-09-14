# Project Context: Security Operations Dashboard (M1 & M2 Complete State)

> **Document Status**: Complete Project State Preservation (End of Milestone 2)  
> **Workspace**: `c:\Infosys Internship\security-operations-dashboard`  
> **Target Role**: Definitive technical reference and baseline for subsequent Milestone 3 implementation.

---

## 1. Project Overview

The **Security Operations Dashboard** is an enterprise-grade, AI-assisted security analytics platform developed as an internship project. It aggregates, cleans, normalizes, and enriches heterogeneous security telemetry, performs unsupervised machine learning anomaly detection and hybrid threat classification, and presents real-time Security Operations Center (SOC) analytics through a reactive web dashboard.

The system combines:
1. **Milestone 1**: Security Data Aggregation, Multi-Dataset Enrichment, MongoDB Storage Engine, and Telemetry REST APIs.
2. **Milestone 2**: Unsupervised Isolation Forest Anomaly Detection, Feature Engineering & ML Preprocessing, Calibrated Hybrid Threat Classification (5-tier SOC Hierarchy), Bounded 0–100 Threat Confidence Scoring, XAI Explanations, Prediction Storage in MongoDB (`threat_predictions`), and 6 Prediction REST APIs.
3. **Milestone 3 (Pending)**: Composite Risk Scoring, Automated Threat Prioritization, Attack-Chain Detection, CVE/IOC/MITRE Risk Enrichment, Incident Lifecycle Management, and Actionable Mitigation Recommendations.

---

## 2. Current Milestone

* **Current State**: **END OF MILESTONE 2 (100% COMPLETE & VERIFIED)**.
* **Milestone 3 Status**: **NOT STARTED (STRICTLY FROZEN)**.
* All Milestone 1 and Milestone 2 data pipelines, ML models, database collections, backend endpoints, and frontend dashboards are implemented, tested, and operational.

---

## 3. Milestone 1 Summary

### Objective
Establish a reliable security data engineering foundation by aggregating raw security event logs, enriching them with contextual asset, vulnerability, threat intelligence, MITRE ATT&CK taxonomy, and incident telemetry, storing them in MongoDB, and exposing real-time queries via FastAPI.

### Implementation Summary
* **Raw Datasets Processed (6 CSVs in `data/raw/`)**:
  * `security_events.csv`: 1,800 event logs (timestamps, source/destination IPs, usernames, event types, protocol, device name, OS, status, severity, failed logins, malware flag, vulnerability ID, raw CVSS score, asset name, department).
  * `assets.csv`: IT asset catalog (asset ID, name, type, owner, department, criticality, OS).
  * `vulnerabilities.csv`: CVE vulnerability catalog (vulnerability ID, CVE ID, name, severity, CVSS score, affected asset, patch status, lifecycle status).
  * `threat_intelligence.csv`: IoC feed (indicator ID, type, IP value, threat name, threat actor, confidence, severity).
  * `mitre_attack_mapping.csv`: MITRE ATT&CK taxonomy (`event_type` $\rightarrow$ `mitre_id`, `technique_name`, `tactic`).
  * `incident_history.csv`: Historical incident tickets (incident ID, event ID, type, assignee, status, response time, resolution).
* **Data Cleaning (`scripts/clean_data.py`)**:
  * Validates column schemas, enforces primary key constraints, removes duplicate records, normalizes string casing/whitespace, standardizes booleans (`malware_detected` $\rightarrow$ `Yes`/`No`), parses timestamps to datetime, and exports cleaned CSVs to `data/processed/cleaned_*.csv`.
* **Relational Normalization & Enrichment (`scripts/enrich_data.py`)**:
  * Executes Left Outer Joins on cleaned datasets:
    1. Events to Assets on `asset_name`.
    2. Events to Vulnerabilities on `vulnerability_id` == `cve_id`.
    3. Events to Threat Intel matching `source_ip` or `destination_ip` against `indicator_value`.
    4. Events to MITRE ATT&CK on `event_type`.
    5. Events to Incidents on `event_id`.
  * Outputs canonical dataset: `data/processed/enriched_security_events.csv` (1,800 rows, 35 columns, zero data loss, zero row multiplication).
* **Database Seeding (`scripts/seed_mongodb.py`)**:
  * Idempotently seeds `security_operations` database across 5 collections (`security_events`, `assets`, `vulnerabilities`, `threat_intelligence`, `mitre_attack_mapping`).
  * Creates unique indexes on primary keys and query indexes on `timestamp`, `event_severity`, `event_status`, `threat_intel_match`, `mitre_id`, and `asset_name`.
* **Backend REST APIs (`backend/app/api/`)**:
  * `GET /health`: Health check verifying FastAPI and MongoDB connectivity.
  * `GET /events`: Paginated query & multi-field filtering/search on security events.
  * `GET /metrics`: Single-pass MongoDB `$facet` aggregation of overview KPIs, severities, and status counts.
  * `GET /events/trend`: Server-side hourly timestamp bucketing of security event trends.
  * `GET /mitre`: MITRE ATT&CK coverage statistics and technique mappings.
  * `GET /assets`: IT asset inventory enriched with CVE catalog details and event counts.
  * `GET /threat-intel`: IoC catalog with real-time matched event counters.

---

## 4. Milestone 2 Summary

### Objective
Implement an unsupervised Machine Learning threat detection engine and hybrid SOC classification rules to detect anomalies, categorize threat types and severity evidence, calculate bounded confidence scores with XAI reasons, persist predictions in MongoDB, and expose prediction APIs for SOC investigation.

### Implementation Summary
* **Feature Selection & Engineering (`documentation/Feature_selection.md`)**:
  * Selected 13 core domain features (10 numerical/binary + 3 categorical).
  * Derived temporal and behavioral features with strict backward-rolling windows $[t - \text{window}, t]$ to eliminate future data leakage:
    * `login_hour` (0–23)
    * `after_hours_activity` (1 if hour $<8$ or $\ge 18$, else 0)
    * `events_per_user_1h` (rolling 1-hour event volume per user)
    * `login_frequency_1h` (rolling 1-hour authentication event frequency per user)
    * `unique_destinations_24h` (rolling 24-hour distinct destination IPs per user)
    * `severity_score` (ordinal 1–4: Low=1, Medium=2, High=3, Critical=4)
    * `vulnerability_present` (1 if `vulnerability_id` non-null, else 0)
* **ML Preprocessing (`backend/ml/preprocessing.py`)**:
  * Standardizes numerical features using `StandardScaler`.
  * One-hot encodes categoricals (`protocol`, `event_type`, `event_status`) using `OneHotEncoder(handle_unknown='ignore')`.
  * Generates 29-feature numerical matrix: `data/processed/m2_feature_matrix.csv`.
  * Serializes fitted preprocessor artifact: `backend/models/preprocessor.pkl`.
* **Isolation Forest Anomaly Detection (`backend/ml/anomaly_detection.py`)**:
  * Trains unsupervised `IsolationForest(n_estimators=100, contamination=0.05, random_state=42)`.
  * Generates decision function anomaly score ($S_{raw} = -\text{decision\_function}(X)$) and discrete predictions (`Normal` / `Suspicious`).
  * Serializes model artifact: `backend/models/isolation_forest.pkl`.
  * Persists development predictions: `data/processed/m2_anomaly_predictions.csv` (1,710 Normal [95.0%], 90 Suspicious [5.0%]).
* **Model Evaluation Diagnostics (`documentation/Model_performance.md`)**:
  * Documented unsupervised evaluation diagnostics (score min: -0.100174, max: +0.061516, mean: -0.039102, median: -0.041507).
  * Verified absence of ground-truth attack labels; justified omission of fabricated supervised metrics (F1/Precision/Recall).
* **Calibrated Threat Classification Engine (`backend/ml/threat_classifier.py`)**:
  * Categorizes events into **Threat Type** (WHAT happened: `Brute Force`, `Malware`, `Phishing`, `SQL Injection`, `Privilege Escalation`, `Port Scan`, `Unauthorized File Access`, `USB / Removable Media`, `Authentication Anomaly`, `Normal Activity`).
  * Assigns **Threat Level** (EVIDENCE STRENGTH: `Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat`).
  * Generates machine-readable JSON array of human-readable explainable AI (XAI) `reasons`.
  * Calibrated to treat passive CVSS vulnerability scores as asset context rather than active attacks, preventing alert inflation.
  * Persists dataset: `data/processed/m2_threat_classification.csv`.
* **Threat Confidence Scoring Engine (`backend/ml/confidence_scorer.py`)**:
  * Calculates bounded 0–100 evidence score across 4 weighted components:
    1. ML Anomaly Evidence Score (Weight: 35%)
    2. Active Malicious Behavior Score (Weight: 30%)
    3. Asset Risk & Context Score (Weight: 20%)
    4. Threat Level Alignment Score (Weight: 15%)
  * Soft-caps Normal events at 45 without active attack indicators; floors Suspicious anomalies at 50.
  * Persists dataset: `data/processed/m2_confidence_scores.csv` (Mean: 27.07, Range: 3–83).
* **Prediction Storage in MongoDB (`backend/app/services/threat_prediction_service.py`, `scripts/seed_threat_predictions.py`)**:
  * Collection: `threat_predictions` in `security_operations` database.
  * Stores 1,800 documents linked 1:1 via `event_id` to `security_events`. Zero raw telemetry duplication.
  * Indexed with unique constraint `uniq_event_id` and query indexes on `threat_level`, `prediction`, `confidence_score`, `threat_type`, `created_at`.
* **Prediction REST APIs (`backend/app/api/predictions.py`)**:
  * `POST /predict`: Live on-the-fly ML inference and hybrid classification.
  * `GET /predictions`: Paginated query & filtering of stored predictions in MongoDB.
  * `GET /predictions/{event_id}`: Single event prediction joined with telemetry from `security_events` (404 on missing).
  * `GET /anomalies`: Filtered query returning only `Suspicious` predictions.
  * `GET /model-performance`: Model diagnostics, score distribution, and contamination parameters.
  * `GET /threat-summary`: Database-derived aggregated threat KPIs, threat level/type breakdowns, and average confidence.

---

## 5. Current Architecture

```
                                +-------------------------------------------+
                                |               React Frontend              |
                                |       (Vite, React 18, Recharts, Lucide)  |
                                +-------------------------------------------+
                                                      │
                                                      │ HTTP / JSON (Axios via /api proxy)
                                                      ▼
                                +-------------------------------------------+
                                |              FastAPI Backend              |
                                |            (Port 8000 / ASGI)             |
                                +-------------------------------------------+
                                        │                           │
                   Inference Pipeline   │                           │ Database Queries
                   (ModelLoader)        ▼                           ▼ (PyMongo)
                     ┌───────────────────────────────┐     ┌────────────────────────────────┐
                     │ Preprocessor: preprocessor.pkl│     │ MongoDB Atlas / Local Instance │
                     │ Model: isolation_forest.pkl   │     │ Database: security_operations  │
                     │ Classifier: threat_classifier │     │ Collections:                   │
                     │ Scorer: confidence_scorer     │     │  - security_events (1,800)     │
                     └───────────────────────────────┘     │  - threat_predictions (1,800) │
                                                           │  - assets (1)                  │
                                                           │  - vulnerabilities (1)         │
                                                           │  - threat_intelligence (1)     │
                                                           │  - mitre_attack_mapping (1)    │
                                                           └────────────────────────────────┘
```

### Communication Flow:
1. **Frontend $\leftrightarrow$ Backend**: React application runs on `http://localhost:3000`. Vite dev server proxies `/api/*` requests to the FastAPI backend at `http://127.0.0.1:8000`.
2. **Backend $\leftrightarrow$ Database**: FastAPI connects to MongoDB via PyMongo using the `MONGODB_URI` environment variable loaded from `.env`.
3. **Backend $\leftrightarrow$ ML Pipeline**: On-the-fly inference (`POST /predict`) loads cached singleton instances of `ModelLoader`, `SecurityThreatClassifier`, and `ThreatConfidenceScorer` in memory. Stored prediction routes (`GET /predictions`, `GET /threat-summary`, etc.) query the indexed `threat_predictions` MongoDB collection directly for sub-millisecond response latency.

---

## 6. Complete Folder Structure

```
c:\Infosys Internship\security-operations-dashboard\
├── .env                                       # MongoDB Atlas connection string URI
├── .gitignore                                 # Git ignore rules for Python, Node, artifacts
├── README.md                                  # High-level project summary
├── backend/
│   ├── requirements.txt                       # Backend Python dependencies
│   ├── app/
│   │   ├── __init__.py                        # Package init
│   │   ├── main.py                            # FastAPI entry point & CORS configuration
│   │   ├── api/
│   │   │   ├── __init__.py                    # API package init
│   │   │   ├── assets.py                      # GET /assets route (M1)
│   │   │   ├── events.py                      # GET /events route (M1)
│   │   │   ├── health.py                      # GET /health route (M1)
│   │   │   ├── metrics.py                     # GET /metrics route (M1)
│   │   │   ├── mitre.py                       # GET /mitre route (M1)
│   │   │   ├── predictions.py                 # 6 Prediction REST endpoints (M2)
│   │   │   ├── threat_intel.py                # GET /threat-intel route (M1)
│   │   │   └── trends.py                      # GET /events/trend route (M1)
│   │   ├── core/
│   │   │   ├── __init__.py                    # Core package init
│   │   │   └── database.py                    # PyMongo client singleton & health check
│   │   ├── schemas/
│   │   │   └── prediction.py                  # Pydantic request/response validation models (M2)
│   │   └── services/
│   │       ├── __init__.py                    # Services package init
│   │       └── threat_prediction_service.py   # CRUD & referential integrity service for threat_predictions (M2)
│   ├── ml/
│   │   ├── __init__.py                        # ML package init
│   │   ├── anomaly_detection.py               # IsolationForestDetector training & prediction (M2)
│   │   ├── confidence_scorer.py               # ThreatConfidenceScorer 0–100 evidence engine (M2)
│   │   ├── model_loader.py                    # ModelLoader inference infrastructure & smoke test (M2)
│   │   ├── preprocessing.py                   # SecurityEventPreprocessor feature engineering & scaling (M2)
│   │   └── threat_classifier.py               # SecurityThreatClassifier hybrid SOC rules engine (M2)
│   └── models/
│       ├── isolation_forest.pkl               # Serialized Isolation Forest model artifact (M2)
│       └── preprocessor.pkl                   # Serialized ColumnTransformer preprocessor artifact (M2)
├── data/
│   ├── raw/                                   # Immutable raw source CSVs
│   │   ├── assets.csv                         # Raw asset catalog
│   │   ├── incident_history.csv               # Raw incident catalog
│   │   ├── mitre_attack_mapping.csv           # Raw MITRE mapping
│   │   ├── security_events.csv                # Raw security events (1,800 rows)
│   │   ├── threat_intelligence.csv            # Raw IoC feed
│   │   └── vulnerabilities.csv                # Raw CVE catalog
│   └── processed/                             # Processed, enriched & ML feature CSVs
│       ├── cleaned_assets.csv                 # Deduplicated & cleaned assets (M1)
│       ├── cleaned_incident_history.csv       # Deduplicated & cleaned incidents (M1)
│       ├── cleaned_mitre_attack_mapping.csv   # Deduplicated & cleaned MITRE (M1)
│       ├── cleaned_security_events.csv        # Deduplicated & cleaned events (M1)
│       ├── cleaned_threat_intelligence.csv    # Deduplicated & cleaned threat intel (M1)
│       ├── cleaned_vulnerabilities.csv        # Deduplicated & cleaned vulnerabilities (M1)
│       ├── enriched_security_events.csv       # Canonical enriched event dataset (1,800 rows) (M1)
│       ├── m2_anomaly_predictions.csv         # Isolation Forest anomaly predictions (M2)
│       ├── m2_confidence_scores.csv           # Threat confidence score dataset (M2)
│       ├── m2_feature_matrix.csv              # 29-feature encoded ML matrix (M2)
│       └── m2_threat_classification.csv       # Threat classifications & XAI reasons (M2)
├── documentation/                             # Architectural design & implementation documentation
│   ├── Anomaly_detection.md                   # Isolation Forest training documentation (M2)
│   ├── Confidence_scoring.md                  # Threat confidence scoring design & formulation (M2)
│   ├── data_dictionary.md                     # Canonical data dictionary & schemas (M1)
│   ├── database_schema.md                     # MongoDB database schema specification (M1/M2)
│   ├── Feature_selection.md                   # M2 ML feature selection specification (M2)
│   ├── ML_preprocessing.md                    # ML preprocessing pipeline documentation (M2)
│   ├── Model_loading.md                       # Model loading infrastructure documentation (M2)
│   ├── Model_performance.md                   # Model evaluation diagnostics & score distribution (M2)
│   ├── Prediction_APIs.md                     # Prediction REST APIs specification (M2)
│   ├── Threat_classification.md               # Calibrated threat classification documentation (M2)
│   └── Threat_predictions_schema.md           # MongoDB threat_predictions collection schema (M2)
├── frontend/
│   ├── dist/                                  # Compiled production build
│   ├── index.html                             # Single-page app HTML template
│   ├── package.json                           # Node dependencies & npm scripts
│   ├── package-lock.json                      # Locked npm package tree
│   ├── vite.config.js                         # Vite dev server configuration & backend proxy
│   └── src/
│       ├── main.jsx                           # React root mount
│       ├── App.jsx                            # Primary application shell & navigation router
│       ├── assets/
│       │   ├── infosys-logo.png               # Infosys branding logo asset
│       │   └── styles/
│       │       └── index.css                  # Core CSS design system & styling rules
│       ├── charts/
│       │   ├── SeverityPieChart.jsx           # Severity breakdown donut chart (M1)
│       │   ├── ThreatTrendChart.jsx           # Hourly time-series trend line chart (M1)
│       │   ├── TopAffectedAssetsChart.jsx     # Affected assets horizontal bar chart (M1)
│       │   └── TopAttackTypesChart.jsx        # Top attack categories bar chart (M1)
│       ├── components/
│       │   ├── AssetRiskOverviewCard.jsx      # Asset risk overview widget (M1)
│       │   ├── AttackHeatmap.jsx              # Temporal attack intensity heatmap (M1)
│       │   ├── AutoRefreshControl.jsx         # 60s auto-refresh & manual reload control (M1)
│       │   ├── Badge.jsx                      # Severity/status color-coded badge component
│       │   ├── Header.jsx                     # Top navigation bar with theme toggle & user profile
│       │   ├── IncidentTable.jsx              # Incident response telemetry table (M1)
│       │   ├── InfosysLogo.jsx                # Responsive logo wrapper
│       │   ├── MetricCard.jsx                 # Standardized KPI summary metric card
│       │   ├── Sidebar.jsx                    # Primary SOC navigation sidebar
│       │   └── ThreatTimeline.jsx             # Chronological event telemetry feed (M1)
│       ├── pages/
│       │   ├── AdminProfilePage.jsx           # Authenticated user session & profile
│       │   ├── AiThreatDetectionPage.jsx      # M2 AI detection overview & model diagnostics
│       │   ├── AnalyticsPage.jsx              # Analytics sub-navigation hub
│       │   ├── AssetRiskPage.jsx              # Master asset exposure & risk table (M1)
│       │   ├── EventInvestigationPage.jsx     # M2 Single event lookup & stored predictions table
│       │   ├── IncidentResponsePage.jsx       # Historical incident response tracking (M1)
│       │   ├── LandingPage.jsx                # Particle canvas landing & sign-in modal
│       │   ├── LoginPage.jsx                  # Login wrapper delegating to LandingPage
│       │   ├── MitreCoveragePage.jsx          # MITRE ATT&CK coverage matrix & techniques (M1)
│       │   ├── RiskPrioritizationPage.jsx     # M1 rule-based event risk ranking
│       │   ├── SecurityEventsPage.jsx         # Primary paginated security telemetry table (M1)
│       │   ├── ThreatIntelPage.jsx            # IoC indicators & threat feed view (M1)
│       │   └── VulnerabilitiesPage.jsx        # CVE vulnerability management center (M1)
│       ├── services/
│       │   └── api.js                         # Centralized Axios API service with TTL caching
│       └── utils/
│           ├── assetRiskAggregator.js         # Client-side asset exposure aggregation helper
│           └── pdfExport.js                   # Client-side PDF investigation report generator
├── scripts/
│   ├── clean_data.py                          # M1 Data validation & deduplication pipeline
│   ├── enrich_data.py                         # M1 Multi-dataset relational normalization pipeline
│   ├── seed_mongodb.py                        # M1 MongoDB database seeder for core collections
│   └── seed_threat_predictions.py             # M2 MongoDB seeder for threat_predictions collection
└── tests/
    ├── test_prediction_api.py                 # M2 Prediction REST API unit & integration tests
    └── test_threat_prediction_service.py      # M2 ThreatPredictionService & MongoDB tests
```

---

## 7. Frontend State

* **Framework**: React 18.2.0 with Vite 5.1.0 (ESM).
* **Navigation Architecture**: Controlled in `frontend/src/App.jsx` with persistent sidebar navigation across 6 primary tabs + Admin Profile:
  1. `overview`: Dashboard overview (5 KPI cards, M2 AI detection banner, severity donut chart, top attack types chart, asset risk card, threat timeline).
  2. `events`: Security Events Page (paginated, debounced multi-field search, severity/type/status/IP/date filtering, CSV export).
  3. `threat-intel`: Threat Intelligence Page (hourly event trend line chart, threat type breakdown, attack heatmap).
  4. `investigation`: Event Investigation Page (M2 Single-event lookup via `GET /predictions/{event_id}`, telemetry display, XAI reasons list, PDF export, paginated stored predictions table with 1-click investigation).
  5. `vulnerabilities`: Vulnerabilities Page (monitored assets, CVE catalog details, patch statuses, CVSS distribution).
  6. `analytics`: Analytics Hub with sub-tabs:
     - *Risk Prioritization* (`RiskPrioritizationPage.jsx`)
     - *Incident Response* (`IncidentResponsePage.jsx`)
     - *MITRE ATT&CK* (`MitreCoveragePage.jsx`)
     - *AI Threat Detection* (`AiThreatDetectionPage.jsx` consuming `GET /threat-summary` and `GET /model-performance`)
     - *Asset Risk* (`AssetRiskPage.jsx`)
  7. `admin`: Admin Profile Page (`AdminProfilePage.jsx` showing active session details).
* **State Management**: React Hooks (`useState`, `useEffect`, `useCallback`, `useMemo`, `useRef`) with centralized Axios client and in-memory TTL caching (30s) in `frontend/src/services/api.js`.
* **Styling**: Vanilla CSS in `frontend/src/assets/styles/index.css` supporting light and dark themes via `data-theme` attribute on root document.

---

## 8. Backend State

* **Framework**: FastAPI (Python $\ge 3.10$, tested on Python 3.13) running via Uvicorn.
* **Database Driver**: PyMongo 4.6+ connecting to MongoDB Atlas / Local instance via `backend/app/core/database.py`.
* **Routing**: Fully registered in `backend/app/main.py`:
  * `health_router` (`/health`)
  * `events_router` (`/events`)
  * `metrics_router` (`/metrics`)
  * `mitre_router` (`/mitre`)
  * `assets_router` (`/assets`)
  * `threat_intel_router` (`/threat-intel`)
  * `trends_router` (`/events/trend`)
  * `predictions_router` (`/predict`, `/predictions`, `/predictions/{event_id}`, `/anomalies`, `/model-performance`, `/threat-summary`)

---

## 9. Database State

* **Database Name**: `security_operations`
* **Collections**:
  1. `security_events`: 1,800 canonical enriched security events (M1).
  2. `threat_predictions`: 1,800 ML anomaly predictions, classifications, confidence scores, and XAI reasons (M2).
  3. `assets`: Reference IT asset inventory (1 record: `AST001` / `HR-PC-01`) (M1).
  4. `vulnerabilities`: Reference CVE catalog (1 record: `VULN001` / `CVE-2024-1045`) (M1).
  5. `threat_intelligence`: Reference IoC feed (1 record: `IOC001` / `185.91.22.14`) (M1).
  6. `mitre_attack_mapping`: Reference MITRE taxonomy (1 record: `Failed Login` $\rightarrow$ `T1110`) (M1).

---

## 10. ML / Data Pipeline

```
Raw Telemetry CSVs (data/raw/)
       │
       ▼ scripts/clean_data.py
Cleaned CSVs (data/processed/cleaned_*.csv)
       │
       ▼ scripts/enrich_data.py
Canonical Enriched Events (data/processed/enriched_security_events.csv)
       │
       ├──► scripts/seed_mongodb.py ──► MongoDB: security_events collection
       │
       ▼ backend/ml/preprocessing.py
Fitted Preprocessor (backend/models/preprocessor.pkl) + Feature Matrix (data/processed/m2_feature_matrix.csv)
       │
       ▼ backend/ml/anomaly_detection.py
Fitted Isolation Forest (backend/models/isolation_forest.pkl) + Anomaly Predictions (data/processed/m2_anomaly_predictions.csv)
       │
       ▼ backend/ml/threat_classifier.py
Threat Classifications & XAI Reasons (data/processed/m2_threat_classification.csv)
       │
       ▼ backend/ml/confidence_scorer.py
Threat Confidence Scores (data/processed/m2_confidence_scores.csv)
       │
       ▼ scripts/seed_threat_predictions.py
MongoDB: threat_predictions collection
       │
       ▼ backend/app/api/predictions.py
FastAPI Endpoints ──► React SOC Dashboard
```

---

## 11. Milestone 2 Output Contract (To be Consumed by Milestone 3)

The exact output contract produced by Milestone 2 that **Milestone 3 will consume** consists of the following fields in the `threat_predictions` MongoDB collection (and `data/processed/m2_confidence_scores.csv`):

| Output Field Name | Data Type | Permitted / Observed Values | Description |
| :--- | :--- | :--- | :--- |
| `event_id` | `string` | `EVT00001` – `EVT01800` | Primary key linking directly to `security_events.event_id`. |
| `prediction` | `string` | `'Normal'`, `'Suspicious'` | Discrete Isolation Forest anomaly detection verdict. |
| `anomaly_score` | `float` | $[-0.100174, +0.061516]$ | Continuous decision function score (higher = more anomalous). |
| `threat_type` | `string` | `'Brute Force'`, `'Malware'`, `'Phishing'`, `'SQL Injection'`, `'Privilege Escalation'`, `'Port Scan'`, `'Unauthorized File Access'`, `'File Access'`, `'USB / Removable Media'`, `'Authentication Anomaly'`, `'Other Suspicious Activity'`, `'Normal Activity'` | Categorical security activity classification. |
| `threat_level` | `string` | `'Normal'`, `'Low Threat'`, `'Medium Threat'`, `'High Threat'`, `'Critical Threat'` | Calibrated 5-tier SOC threat evidence hierarchy. |
| `confidence_score`| `integer` | $0 \le \text{score} \le 100$ | Bounded 0–100 threat evidence confidence score. |
| `reasons` | `list[string]` | Array of explanation strings | Machine-readable explainable AI (XAI) security detection reasons. |
| `model_version` | `string` | `'isolation_forest_v1'` | Tracked machine learning model version. |
| `created_at` | `datetime` / `string`| ISO 8601 UTC Timestamp | Timestamp of prediction record persistence. |

### Context Telemetry Available via `security_events` (Joined by `event_id`):
* `timestamp`: Event generation timestamp.
* `source_ip`: Source IPv4 address.
* `destination_ip`: Destination IPv4 address.
* `username`: Target user account.
* `event_type`: Raw log event classification.
* `protocol`: Network protocol (`SSH`, `HTTP`, `HTTPS`, `SMB`, `TCP`).
* `event_status`: Execution outcome (`Success`, `Failed`, `Blocked`, `Detected`).
* `event_severity`: Log severity (`Critical`, `High`, `Medium`, `Low`).
* `failed_login_attempts`: Count of failed authentication attempts.
* `malware_detected`: Binary malware indicator (`Yes` / `No`).
* `raw_cvss_score`: CVSS base score from log telemetry.
* `vulnerability_id`: Associated CVE ID (nullable).
* `asset_name`: Name of targeted host/workstation.
* `department`: Organizational department.
* `asset_id`, `asset_type`, `asset_owner`, `asset_criticality`, `asset_operating_system`: Enriched asset metadata.
* `vulnerability_record_id`, `vulnerability_name`, `vulnerability_severity`, `vulnerability_cvss_score`, `patch_available`, `vulnerability_status`: Enriched CVE catalog metadata.
* `threat_intel_match`, `threat_name`, `threat_actor`, `threat_confidence`, `threat_intel_severity`: Enriched IoC metadata.
* `mitre_id`, `technique_name`, `tactic`, `mitre_mapping_status`: Enriched MITRE ATT&CK taxonomy.
* `incident_id`, `incident_type`, `assigned_to`, `incident_status`, `response_time_minutes`, `resolution`: Enriched historical incident tracking.

---

## 12. API Inventory

| Method | Endpoint | Purpose | Request Parameters / Body | Response Schema | Status |
| :--- | :--- | :--- | :--- | :--- | :---: |
| `GET` | `/health` | Application & MongoDB health check | None | `{"status": "healthy", "database": "connected"}` | **DONE** |
| `GET` | `/events` | Paginated security telemetry query | `page`, `limit`, `severity`, `event_type`, `status`, `start_date`, `end_date`, `ip_address`, `search` | `{"data": [...], "pagination": {...}}` | **DONE** |
| `GET` | `/metrics` | Overview KPI dashboard metrics | None | `{"overview": {...}, "event_status": {...}, "security_indicators": {...}, "asset_coverage": {...}}` | **DONE** |
| `GET` | `/events/trend` | Hourly time-series telemetry buckets | None | `{"trend": [{"timestamp": "...", "total": N, "critical": N, ...}]}` | **DONE** |
| `GET` | `/mitre` | MITRE ATT&CK coverage statistics | None | `{"summary": {...}, "mappings": [...]}` | **DONE** |
| `GET` | `/assets` | Enriched IT asset inventory & CVEs | None | `{"summary": {...}, "assets": [...]}` | **DONE** |
| `GET` | `/threat-intel` | Threat intelligence IoCs & match counts | None | `{"summary": {...}, "indicators": [...]}` | **DONE** |
| `POST` | `/predict` | Live on-the-fly ML model inference | `PredictRequest` (JSON body) | `PredictResponse` (`event_id`, `prediction`, `anomaly_score`, `threat_type`, `threat_level`, `confidence_score`, `reasons`, `model_version`) | **DONE** |
| `GET` | `/predictions` | Paginated stored predictions from DB | `page`, `limit`, `prediction`, `threat_level`, `threat_type`, `min_confidence`, `search` | `PaginatedPredictionsResponse` | **DONE** |
| `GET` | `/predictions/{event_id}` | Single prediction joined with telemetry | `event_id` (Path param) | `PredictionWithEventDetailsResponse` (404 on missing) | **DONE** |
| `GET` | `/anomalies` | Stored predictions filtered for `Suspicious` | `page`, `limit`, `min_confidence` | `PaginatedPredictionsResponse` | **DONE** |
| `GET` | `/model-performance` | Isolation Forest evaluation diagnostics | None | `ModelPerformanceResponse` (contamination, distribution, feature count) | **DONE** |
| `GET` | `/threat-summary` | Aggregated threat KPIs & score statistics | None | `ThreatSummaryResponse` (threat levels/types breakdown, avg confidence) | **DONE** |

---

## 13. Frontend Routes / Pages

| View / Tab ID | Page Component | File Path | Purpose |
| :--- | :--- | :--- | :--- |
| `landing` | Landing Page | `frontend/src/pages/LandingPage.jsx` | Animated cyber particle hero landing and modal authentication entry. |
| `login` | Login Wrapper | `frontend/src/pages/LoginPage.jsx` | Delegates to LandingPage in `'signin'` mode. |
| `overview` | Dashboard Overview | Inline in `frontend/src/App.jsx` | Overview KPIs, M2 AI Detection Banner, Severity Donut, Attack Types, Asset Risk, Timeline. |
| `events` | Security Events | `frontend/src/pages/SecurityEventsPage.jsx` | Paginated canonical event table with multi-field filtering, search, and CSV export. |
| `threat-intel` | Threat Intelligence | `frontend/src/pages/ThreatIntelPage.jsx` | Hourly event trends line chart, horizontal threat bar chart, and attack heatmap. |
| `investigation` | Event Investigation | `frontend/src/pages/EventInvestigationPage.jsx` | Single event investigation via `GET /predictions/{event_id}`, XAI reasons, PDF export, and stored predictions table. |
| `vulnerabilities` | Vulnerabilities Page | `frontend/src/pages/VulnerabilitiesPage.jsx` | Asset exposure catalog, CVE vulnerabilities, patch status, and CVSS distributions. |
| `analytics` | Analytics Hub | `frontend/src/pages/AnalyticsPage.jsx` | Sub-navigation hub hosting Risk Prioritization, Incident Response, MITRE Coverage, AI Threat Detection, and Asset Risk. |
| `admin` | Admin Profile | `frontend/src/pages/AdminProfilePage.jsx` | Authenticated analyst user profile, role, session metadata, and logout. |

---

## 14. Current Data Flow

1. **Ingestion & ETL (Offline)**: Raw CSVs $\rightarrow$ `scripts/clean_data.py` $\rightarrow$ `scripts/enrich_data.py` $\rightarrow$ `scripts/seed_mongodb.py` $\rightarrow$ `security_events`.
2. **ML Training & Offline Prediction (Offline)**: `enriched_security_events.csv` $\rightarrow$ `backend/ml/preprocessing.py` $\rightarrow$ `backend/ml/anomaly_detection.py` $\rightarrow$ `backend/ml/threat_classifier.py` $\rightarrow$ `backend/ml/confidence_scorer.py` $\rightarrow$ `scripts/seed_threat_predictions.py` $\rightarrow$ `threat_predictions`.
3. **Live Inference (Online)**: Client $\rightarrow$ `POST /predict` $\rightarrow$ `ModelLoader.predict_events()` $\rightarrow$ `SecurityThreatClassifier.classify_event()` $\rightarrow$ `ThreatConfidenceScorer.compute_event_confidence()` $\rightarrow$ JSON Response.
4. **Dashboard Telemetry Queries (Online)**: Client $\rightarrow$ `GET /metrics`, `GET /events`, `GET /threat-summary`, etc. $\rightarrow$ FastAPI REST Router $\rightarrow$ PyMongo aggregation queries $\rightarrow$ JSON Response $\rightarrow$ React UI components.

---

## 15. Dependencies & Technology Stack

### Backend Stack
* **Python**: 3.10+ (tested on Python 3.13)
* **Web Framework**: `fastapi>=0.100.0`
* **ASGI Server**: `uvicorn>=0.20.0`
* **Database Driver**: `pymongo>=4.6.0`
* **Environment Configuration**: `python-dotenv>=1.0.0`
* **Data Processing & ML**: `pandas>=2.0.0`, `numpy>=1.24.0`, `scikit-learn>=1.3.0`, `joblib>=1.3.0`
* **Testing**: `unittest` (standard library), `fastapi.testclient.TestClient` / `httpx`

### Frontend Stack
* **Runtime / Bundler**: Node.js, `vite^5.1.0`, `@vitejs/plugin-react^4.2.1`
* **UI Library**: `react^18.2.0`, `react-dom^18.2.0`
* **HTTP Client**: `axios^1.6.7`
* **Charts**: `recharts^2.12.0`
* **Icons**: `lucide-react^0.330.0`
* **Document Export**: `jspdf^4.2.1`
* **Styling**: Vanilla CSS with custom properties / tokens

---

## 16. Run Instructions

### 1. Environment Configuration
Ensure `.env` exists in the project root with the valid MongoDB connection URI:
```env
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?appName=security-operations
```

### 2. Run Backend Server
```powershell
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
Backend API will be available at: `http://127.0.0.1:8000` (OpenAPI Docs: `http://127.0.0.1:8000/docs`).

### 3. Run Frontend Application
```powershell
cd frontend
npm run dev
```
Frontend application will be available at: `http://localhost:3000`.

### 4. Run Test Suite
```powershell
python -m unittest discover tests
```
Executes all 16 unit and integration tests across prediction APIs and MongoDB services.

---

## 17. Current Working Status

### DONE:
* Complete Milestone 1 data cleaning, normalization, enrichment, and MongoDB storage.
* Complete Milestone 1 REST API routers (`/health`, `/events`, `/metrics`, `/mitre`, `/assets`, `/threat-intel`, `/trends`).
* Complete Milestone 2 Feature Selection (13 domain features) and ML Preprocessing pipeline generating `m2_feature_matrix.csv` (29 features) and `preprocessor.pkl`.
* Complete Milestone 2 Isolation Forest training generating `isolation_forest.pkl` and `m2_anomaly_predictions.csv` (5% anomaly rate).
* Complete Milestone 2 Model Evaluation Diagnostics and documentation.
* Complete Milestone 2 Calibrated Threat Classification engine generating 5-tier threat levels, 12 threat types, and XAI reasons (`m2_threat_classification.csv`).
* Complete Milestone 2 Threat Confidence Scoring engine calculating bounded 0–100 evidence scores (`m2_confidence_scores.csv`).
* Complete Milestone 2 MongoDB storage layer (`threat_predictions` collection) with unique and query indexes and referential integrity verification.
* Complete Milestone 2 Prediction REST APIs (`POST /predict`, `GET /predictions`, `GET /predictions/{event_id}`, `GET /anomalies`, `GET /model-performance`, `GET /threat-summary`).
* Complete Frontend Event Investigation page, AI Threat Detection page, and Overview banner.
* Full test suite verification: 16 / 16 tests passing.

### PARTIALLY DONE:
* *None within Milestone 1 or Milestone 2 scope.*

### NOT WORKING:
* *None. All existing M1 and M2 components are fully functional.*

### KNOWN ISSUES:
* `source_country` and `destination_country` are static (`"India"`) in the raw dataset, so geographic impossible-travel rules cannot be evaluated with spatial variance. This was deliberately documented and omitted from ML feature matrices to preserve data integrity.
* Reference CSVs (`assets.csv`, `vulnerabilities.csv`, `threat_intelligence.csv`, `mitre_attack_mapping.csv`, `incident_history.csv`) contain single representative catalog records. Denormalization in `enriched_security_events.csv` appropriately preserves nulls for unmapped records.

---

## 18. M1 Requirement Status

| Milestone 1 Requirement | Status | Evidence / Implementation File |
| :--- | :---: | :--- |
| Security Data Ingestion & Schema Validation | **DONE** | `scripts/clean_data.py`, `documentation/data_dictionary.md` |
| Data Deduplication & Casing Normalization | **DONE** | `data/processed/cleaned_*.csv` |
| Multi-Dataset Relational Joins & Normalization | **DONE** | `scripts/enrich_data.py`, `data/processed/enriched_security_events.csv` |
| MongoDB Database Setup (`security_operations`) | **DONE** | `backend/app/core/database.py`, `scripts/seed_mongodb.py` |
| Database Index Strategy (Unique & Performance) | **DONE** | `documentation/database_schema.md`, `scripts/seed_mongodb.py` |
| Backend Core APIs (`/health`, `/events`, `/metrics`) | **DONE** | `backend/app/api/health.py`, `events.py`, `metrics.py` |
| Context APIs (`/mitre`, `/assets`, `/threat-intel`, `/trends`) | **DONE** | `backend/app/api/mitre.py`, `assets.py`, `threat_intel.py`, `trends.py` |
| React Overview Dashboard & KPI Cards | **DONE** | `frontend/src/App.jsx`, `MetricCard.jsx`, `SeverityPieChart.jsx` |
| Security Events Filter & Search Table | **DONE** | `frontend/src/pages/SecurityEventsPage.jsx` |
| Threat Intelligence Visualizations & Heatmap | **DONE** | `frontend/src/pages/ThreatIntelPage.jsx`, `AttackHeatmap.jsx` |

---

## 19. M2 Requirement Status

| Milestone 2 Requirement | Status | Evidence / Implementation File |
| :--- | :---: | :--- |
| Feature Selection & Engineering Specification | **DONE** | `documentation/Feature_selection.md` |
| Reusable Preprocessing Pipeline & Scaling | **DONE** | `backend/ml/preprocessing.py`, `backend/models/preprocessor.pkl` |
| Unsupervised Anomaly Detection Model | **DONE** | `backend/ml/anomaly_detection.py`, `backend/models/isolation_forest.pkl` |
| Reusable Model Loader & Smoke Test | **DONE** | `backend/ml/model_loader.py` |
| Model Performance Diagnostics & Evaluation | **DONE** | `documentation/Model_performance.md` |
| Calibrated Hybrid Threat Classification Rules | **DONE** | `backend/ml/threat_classifier.py`, `documentation/Threat_classification.md` |
| Threat Confidence Scoring Engine (0–100 Bounded) | **DONE** | `backend/ml/confidence_scorer.py`, `documentation/Confidence_scoring.md` |
| Explainable AI (XAI) Reasons Generation | **DONE** | `backend/ml/threat_classifier.py` (`reasons` field) |
| MongoDB Storage Layer (`threat_predictions`) | **DONE** | `backend/app/services/threat_prediction_service.py`, `scripts/seed_threat_predictions.py` |
| Prediction REST APIs (All 6 Endpoints) | **DONE** | `backend/app/api/predictions.py`, `documentation/Prediction_APIs.md` |
| Unit & Integration Test Suite | **DONE** | `tests/test_prediction_api.py`, `tests/test_threat_prediction_service.py` |
| Frontend AI Threat Detection & Diagnostics | **DONE** | `frontend/src/pages/AiThreatDetectionPage.jsx` |
| Frontend Event Investigation & PDF Export | **DONE** | `frontend/src/pages/EventInvestigationPage.jsx`, `utils/pdfExport.js` |

---

## 20. Important Existing Terminology

* **`event_id`**: Canonical alphanumeric identifier for security event records (`EVT00001` – `EVT01800`).
* **`prediction`**: Discrete output of the Isolation Forest ML model (`Normal` vs `Suspicious`).
* **`anomaly_score`**: Continuous numerical decision function score ($-\text{decision\_function}(X)$) where higher values indicate statistical isolation.
* **`threat_type`**: Categorical classification describing WHAT security action occurred (`Brute Force`, `Malware`, `Phishing`, `SQL Injection`, `Privilege Escalation`, `Port Scan`, `Unauthorized File Access`, `File Access`, `USB / Removable Media`, `Authentication Anomaly`, `Other Suspicious Activity`, `Normal Activity`).
* **`threat_level`**: 5-tier SOC hierarchy describing EVIDENCE STRENGTH (`Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat`).
* **`confidence_score`**: Bounded 0–100 evidence score representing indicator strength and consistency.
* **`reasons`**: Array of human-readable explanation strings generated for SOC analysts.
* **`model_version`**: Tracked ML model version string (`isolation_forest_v1`).
* **`raw_cvss_score`**: Continuous CVSS rating from base event telemetry (100% complete across all 1,800 events).
* **`security_events`**: Authoritative MongoDB collection containing raw/enriched telemetry.
* **`threat_predictions`**: Dedicated MongoDB collection storing ML predictions linked strictly by `event_id`.

---

## 21. Important Files and Their Roles

| File Path | Role / Purpose | Milestone |
| :--- | :--- | :---: |
| `backend/app/main.py` | Primary FastAPI application entry point; registers all 8 routers. | M1 / M2 |
| `backend/app/core/database.py` | PyMongo singleton connection provider and database health check. | M1 |
| `backend/app/schemas/prediction.py` | Pydantic validation schemas for prediction requests and responses. | M2 |
| `backend/app/services/threat_prediction_service.py` | CRUD operations, index creation, and referential integrity validation for `threat_predictions`. | M2 |
| `backend/app/api/predictions.py` | REST API router exposing the 6 prediction endpoints. | M2 |
| `backend/ml/preprocessing.py` | Deterministic feature extraction, categorical encoding, and feature scaling. | M2 |
| `backend/ml/anomaly_detection.py` | Unsupervised Isolation Forest model definition, fitting, and prediction. | M2 |
| `backend/ml/threat_classifier.py` | Calibrated SOC detection rules engine assigning threat types, levels, and XAI reasons. | M2 |
| `backend/ml/confidence_scorer.py` | 4-component weighted evidence confidence scoring engine. | M2 |
| `backend/ml/model_loader.py` | Reusable model and preprocessor deserializer with inference routines and smoke testing. | M2 |
| `backend/models/isolation_forest.pkl` | Trained Isolation Forest model artifact. | M2 |
| `backend/models/preprocessor.pkl` | Fitted ColumnTransformer preprocessor artifact. | M2 |
| `frontend/src/App.jsx` | Main React application shell, session management, and tab routing. | M1 / M2 |
| `frontend/src/services/api.js` | Centralized Axios service client with in-memory TTL caching. | M1 / M2 |
| `frontend/src/pages/EventInvestigationPage.jsx` | SOC analyst event investigation hub with single-event lookup and predictions table. | M2 |
| `frontend/src/pages/AiThreatDetectionPage.jsx` | Model evaluation diagnostics and threat overview visualization dashboard. | M2 |
| `tests/test_prediction_api.py` | Comprehensive test suite for prediction REST APIs. | M2 |
| `tests/test_threat_prediction_service.py` | Test suite for MongoDB prediction service and data formatting. | M2 |

---

## 22. Things That MUST NOT Be Changed Without Checking Context

1. **Do NOT modify existing dataset CSVs**: `data/raw/*.csv`, `data/processed/*.csv`, and `data/processed/m2_*.csv` are verified baseline artifacts.
2. **Do NOT modify the 1:1 `event_id` relationship**: The relationship between `security_events` and `threat_predictions` must remain strictly linked on `event_id` with zero raw data duplication.
3. **Do NOT alter existing M1 API response structures**: Endpoints `/health`, `/events`, `/metrics`, `/mitre`, `/assets`, `/threat-intel`, and `/events/trend` must retain their established schema contracts.
4. **Do NOT alter existing M2 API response structures**: Endpoints `/predict`, `/predictions`, `/predictions/{event_id}`, `/anomalies`, `/model-performance`, and `/threat-summary` must retain their established schema contracts.
5. **Do NOT change the 5-tier Threat Level hierarchy**: `Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat`.
6. **Do NOT change the Threat Confidence Score bounds**: Must remain bounded integers between 0 and 100.
7. **Do NOT delete or rename model artifacts**: `backend/models/isolation_forest.pkl` and `backend/models/preprocessor.pkl`.

---

## 23. Boundary Before Milestone 3

```
================================================================================
                    PROJECT STATE FREEZED AT END OF MILESTONE 2
================================================================================
```

* **Milestone 3 has NOT been implemented.**
* **Milestone 3 scope strictly includes**:
  1. Composite Multi-Factor Risk Scoring (`risk_score = f(threat_confidence, asset_criticality, vuln_severity, incident_history)`).
  2. Automated Threat & Incident Prioritization algorithms.
  3. Attack-Chain & Lateral Movement Detection.
  4. Dynamic Threat Intelligence & CVE Correlation.
  5. SOC Incident Lifecycle Management & Mitigation Playbook Recommendations.
  6. Dedicated Milestone 3 Risk Prioritization & Incident Response Dashboard Screens.
* **Future Milestone 3 work MUST EXTEND the existing Milestone 2 implementation.**
* **Do NOT rebuild Milestone 2.**
* **Do NOT replace the existing dataset.**
* **Do NOT create a separate application.**
* **Do NOT assume a new architecture.**
* **Do NOT invent terminology when the existing project/documentation already defines terminology.**
* **Future M3 implementation will happen STEP-BY-STEP in separate prompts.**

---
