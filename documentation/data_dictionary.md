# Canonical Security Event Data Dictionary

**Project:** Creation of Security Operations Dashboard for Threat Detection with Risk Mitigation Analytics  
**Milestone:** Milestone 1 – Security Data Aggregation & Threat Intelligence Layer  
**Document Status:** Approved Data Dictionary Specification  

---

## 1. Purpose

The objective of Milestone 1 is to aggregate raw security logs and enrich them with context from five reference datasets (asset inventory, CVE vulnerability catalog, IoC threat intelligence, MITRE ATT&CK framework mapping, and historical SOC incidents).

In raw form, the six datasets exhibit schema fragmentation, ambiguous field naming (e.g., three separate `severity` fields, two `department` fields, two `status` fields), and an key identifier mismatch (`security_events.vulnerability_id` actually stores CVE format strings rather than vulnerability table IDs).

A **Canonical Security Event Schema** is required to:
1. **Establish a Single Source of Truth:** Unify raw event logs and 5 reference datasets into a standardized, self-contained document format suitable for MongoDB storage.
2. **Eliminate Field Name Ambiguity:** Provide explicit, namespaced field identifiers to prevent collisions across joined datasets.
3. **Ensure Deterministic & Non-Destructive Enrichment:** Preserve original raw event attributes completely while attaching enrichment context via Left Outer Joins.
4. **Prepare Machine Learning Features:** Standardize data types, null representation, and field structures required for downstream anomaly detection (Milestone 2) and risk scoring (Milestone 3).

---

## 2. Raw Dataset Overview

| Dataset | Purpose | Primary / Identifier Key | Main Join Key(s) | Role in Milestone 1 |
| :--- | :--- | :--- | :--- | :--- |
| `security_events.csv` | Core log stream recording security activity across network hosts | `event_id` | N/A (Central Fact Log) | Base log entity to be cleaned, normalized, and enriched |
| `assets.csv` | Host asset inventory, ownership, and business criticality | `asset_id` | `asset_name` | Enriches events with asset type, owner, department, and criticality tier |
| `vulnerabilities.csv` | Active CVE vulnerability descriptions and patch status | `vulnerability_id` | `cve_id` (matches `security_events.vulnerability_id`) | Enriches events with CVE titles, patch availability, and vulnerability status |
| `threat_intelligence.csv` | External IoC threat feed and actor attribution | `indicator_id` | `indicator_value` (matches `source_ip` or `destination_ip`) | Enriches events with threat actor attribution, confidence, and IoC severity |
| `mitre_attack_mapping.csv` | Cyber threat taxonomy mapping events to ATT&CK tactics & techniques | Composite `(event_type, mitre_id)` | `event_type` | Enriches events with MITRE ID, technique name, and tactic phase |
| `incident_history.csv` | SOC analyst incident remediation and SLA tracking history | `incident_id` | `event_id` | Enriches events with historical incident ID, status, assigned analyst, and resolution |

---

## 3. Canonical Security Event Schema

Every enriched security event document in the canonical schema consists of 44 standardized fields grouped into 11 logical categories:

### A. Event Identity
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_id` | String | Required | `security_events.csv` | Trim whitespace; enforce format `EVT\d{5}` | Unique identifier for the security log record |
| `raw_event_hash` | String | Required | Derived | MD5/SHA256 hash of raw record line | Hash identifier ensuring raw record immutability & deduplication |

### B. Temporal Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `timestamp` | String (ISO 8601) | Required | `security_events.csv` | Parse to standardized ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`) | Exact date and time when the security event occurred |
| `event_year` | Integer | Required | Derived | Extract year from `timestamp` | Calendar year for temporal partitioning |
| `event_month` | Integer | Required | Derived | Extract month (1-12) from `timestamp` | Calendar month for temporal partitioning |
| `event_day` | Integer | Required | Derived | Extract day of month (1-31) from `timestamp` | Day of month for temporal aggregation |
| `event_hour` | Integer | Required | Derived | Extract hour (0-23) from `timestamp` | Hour of day for off-hours detection |

### C. Network Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `source_ip` | String | Required | `security_events.csv` | Validate IPv4 string format | Originating IP address of network traffic |
| `destination_ip` | String | Required | `security_events.csv` | Validate IPv4 string format | Destination IP address of network traffic |
| `protocol` | String | Required | `security_events.csv` | Uppercase standardization (`SSH`, `HTTPS`, `SMB`, `HTTP`, `TCP`) | Network protocol used during event |
| `source_country` | String | Required | `security_events.csv` | Standardize string | Country of traffic origin (Default: `India`) |
| `destination_country` | String | Required | `security_events.csv` | Standardize string | Country of traffic destination (Default: `India`) |

### D. User and Device Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `username` | String | Required | `security_events.csv` | Lowercase standardization | User account name associated with event |
| `device_name` | String | Required | `security_events.csv` | Trim whitespace | Endpoint hardware hostname reporting log |
| `os` | String | Required | `security_events.csv` | Standardize string (`Windows 10`, `Windows 11`, `Linux`) | Host operating system reported in raw event |

### E. Event Classification
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `event_type` | String | Required | `security_events.csv` | Title Case standardization | Categorical security event classification |
| `event_status` | String | Required | `security_events.csv` | Title Case (`Success`, `Blocked`, `Failed`, `Detected`) | Execution result of the event action |
| `event_severity` | String | Required | `security_events.csv` | Standardize casing (`Critical`, `High`, `Medium`, `Low`) | Severity assigned in raw event log |

### F. Security Indicators
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `failed_login_attempts` | Integer | Required | `security_events.csv` | Cast to integer; default `0` | Count of consecutive failed authentication attempts |
| `malware_detected` | Boolean | Required | `security_events.csv` | Convert string (`"Yes"` -> `true`, `"No"` -> `false`) | Binary flag indicating malware presence |
| `raw_cvss_score` | Float | Required | `security_events.csv` | Cast to float (0.0 to 10.0 scale) | Initial CVSS score present in raw event log |

### G. Vulnerability Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `cve_id` | String | Optional | `security_events.csv` | Standardize CVE format or `null` if missing | CVE identifier referenced in event log |
| `vulnerability_enrichment_status` | String | Required | Derived | `"Enriched"` if CVE matches `vulnerabilities.csv`, else `"Unmatched"` | Status of vulnerability join lookup |
| `vulnerability_id` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Primary key of vulnerability catalog record (`VUL001`) |
| `vulnerability_name` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Descriptive title of vulnerability |
| `vulnerability_severity` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Catalog severity rating of vulnerability |
| `vulnerability_cvss_score` | Float | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Formal CVSS score from vulnerability catalog |
| `vulnerability_affected_asset` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Target asset listed in vulnerability record |
| `patch_available` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Availability of vendor security patch (`Yes`/`No`) |
| `vulnerability_status` | String | Optional | `vulnerabilities.csv` | Left Join on `cve_id`; `null` if unmatched | Current lifecycle status of vulnerability (`Open`/`Closed`) |

### H. Asset Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `asset_name` | String | Required | `security_events.csv` | Trim whitespace | Target network asset name in event |
| `event_department` | String | Required | `security_events.csv` | Standardize string | Department recorded in event log |
| `asset_enrichment_status` | String | Required | Derived | `"Enriched"` if asset matches `assets.csv`, else `"Unmatched"` | Status of asset inventory join lookup |
| `asset_id` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Unique infrastructure inventory key (`AST001`) |
| `asset_type` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Hardware classification (`Workstation`, `Server`, `Firewall`) |
| `asset_owner` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Designated owner of asset |
| `asset_department` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Business unit owning the asset |
| `asset_criticality` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Business impact criticality rating (`Critical`, `High`, `Medium`, `Low`) |
| `asset_operating_system` | String | Optional | `assets.csv` | Left Join on `asset_name`; `null` if unmatched | Operating system registered in asset inventory |

### I. Threat Intelligence
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `threat_intel_match` | Boolean | Required | Derived | `true` if `source_ip` or `destination_ip` matches `threat_intelligence.indicator_value`, else `false` | IoC indicator match indicator |
| `threat_intel_indicator_id` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Unique IoC threat indicator ID (`IOC001`) |
| `threat_intel_indicator_type` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Indicator category (`IP Address`, `Domain`, `Hash`) |
| `threat_name` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Name of identified threat campaign |
| `threat_actor` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Attributed threat actor / group |
| `threat_confidence` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Threat feed confidence rating (`High`, `Medium`, `Low`) |
| `threat_intel_severity` | String | Optional | `threat_intelligence.csv` | Left Join on IP match; `null` if unmatched | Threat feed severity rating |

### J. MITRE ATT&CK
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `mitre_mapping_status` | String | Required | Derived | `"Mapped"` if `event_type` matches `mitre_attack_mapping.csv`, else `"Unmapped"` | Status of MITRE ATT&CK mapping lookup |
| `mitre_id` | String | Optional | `mitre_attack_mapping.csv` | Left Join on `event_type`; `null` if unmatched | Official MITRE ATT&CK Technique ID (`T1110`) |
| `technique_name` | String | Optional | `mitre_attack_mapping.csv` | Left Join on `event_type`; `null` if unmatched | Official MITRE ATT&CK Technique Name |
| `tactic` | String | Optional | `mitre_attack_mapping.csv` | Left Join on `event_type`; `null` if unmatched | High-level MITRE ATT&CK Tactic category |

### K. Incident / Response Information
| Field Name | Data Type | Required / Optional | Source Dataset | Transformation / Enrichment Rule | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `incident_enrichment_status` | String | Required | Derived | `"Enriched"` if `event_id` matches `incident_history.csv`, else `"Unmatched"` | Status of incident history lookup |
| `incident_id` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | SOC ticketing incident identifier (`INC001`) |
| `incident_type` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | Incident classification in SOC ticketing system |
| `assigned_to` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | SOC team or analyst handling incident |
| `incident_status` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | Resolution lifecycle status (`Open`, `In Progress`, `Closed`) |
| `response_time_str` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | Original response time string (`"15 min"`) |
| `response_time_minutes` | Integer | Optional | `incident_history.csv` | Parse numeric minutes from string; `null` if unmatched | Extracted numeric response duration in minutes (`15`) |
| `resolution` | String | Optional | `incident_history.csv` | Left Join on `event_id`; `null` if unmatched | Action taken to resolve incident (`Blocked`, `Mitigated`) |

---

## 4. Naming Conventions

To eliminate schema collisions across joined datasets, all ambiguous fields are explicitly disambiguated using prefix namespaces:

- **Severity Disambiguation:**
  - `security_events.severity` → `event_severity` (Severity rating from raw log)
  - `threat_intelligence.severity` → `threat_intel_severity` (Severity rating from IoC threat feed)
  - `vulnerabilities.severity` → `vulnerability_severity` (Severity rating from CVE catalog)
- **Status Disambiguation:**
  - `security_events.event_status` → `event_status` (Execution result: `Success`, `Blocked`, `Failed`, `Detected`)
  - `vulnerabilities.status` → `vulnerability_status` (CVE status: `Open`, `Closed`)
  - `incident_history.status` → `incident_status` (SOC incident status: `Open`, `In Progress`, `Closed`)
- **Department & Environment Disambiguation:**
  - `security_events.department` → `event_department` (Department context recorded during log generation)
  - `assets.department` → `asset_department` (Department registered in official asset inventory)
  - `security_events.os` → `os` (Operating system reported in raw log)
  - `assets.operating_system` → `asset_operating_system` (Operating system recorded in asset inventory)
- **CVSS Score Disambiguation:**
  - `security_events.cvss_score` → `raw_cvss_score` (CVSS value present in event log)
  - `vulnerabilities.cvss_score` → `vulnerability_cvss_score` (CVSS value in vulnerability catalog)

---

## 5. Missing Value Policy

1. **No Synthetic Data Generation:** Under no circumstances will missing attributes be populated with invented, synthetic, or dummy strings (e.g., do NOT use `'Unknown'`, `'N/A'`, or `'0'`).
2. **Representation of Optional Attributes:** Optional enrichment fields that do not have a matching record in reference tables MUST be represented as explicit `null` (JSON `null` / Python `None`).
3. **Missing `vulnerability_id` Handling:**
   - In `security_events.csv`, 427 rows have a missing `vulnerability_id`.
   - For these records, `cve_id` is set to `null`, and all joined vulnerability fields (`vulnerability_id`, `vulnerability_name`, `vulnerability_severity`, `vulnerability_cvss_score`, `vulnerability_affected_asset`, `patch_available`, `vulnerability_status`) MUST be `null`.
   - `vulnerability_enrichment_status` is explicitly set to `"Unmatched"`.
4. **Boolean Indicators:** `threat_intel_match` is a non-null boolean (`true` when an IP match exists, `false` otherwise).

---

## 6. Join and Enrichment Rules

All enrichment joins execute as **Left Outer Joins** anchored on `security_events.csv`, preserving 100% of raw security event logs regardless of whether a match exists in reference datasets.

```
┌──────────────────────────────┐
│     security_events.csv      │  (Base Fact Table - 1,800 Rows)
└──────────────┬───────────────┘
               │
               ├────── Left Join (security_events.vulnerability_id == vulnerabilities.cve_id)
               │
               ├────── Left Join (security_events.asset_name == assets.asset_name)
               │
               ├────── Left Join (source_ip / destination_ip == threat_intelligence.indicator_value)
               │
               ├────── Left Join (security_events.event_type == mitre_attack_mapping.event_type)
               │
               └────── Left Join (security_events.event_id == incident_history.event_id)
```

| Reference Dataset | Join Key | Join Direction | Expected Cardinality | Enriched Fields Added |
| :--- | :--- | :--- | :--- | :--- |
| `vulnerabilities.csv` | `security_events.vulnerability_id == vulnerabilities.cve_id` | Left Outer Join | Many-to-1 | `vulnerability_id`, `vulnerability_name`, `vulnerability_severity`, `vulnerability_cvss_score`, `vulnerability_affected_asset`, `patch_available`, `vulnerability_status`, `vulnerability_enrichment_status` |
| `assets.csv` | `security_events.asset_name == assets.asset_name` | Left Outer Join | Many-to-1 | `asset_id`, `asset_type`, `asset_owner`, `asset_department`, `asset_criticality`, `asset_operating_system`, `asset_enrichment_status` |
| `threat_intelligence.csv` | `source_ip` or `destination_ip == threat_intelligence.indicator_value` | Left Outer Join | Many-to-1 | `threat_intel_match`, `threat_intel_indicator_id`, `threat_intel_indicator_type`, `threat_name`, `threat_actor`, `threat_confidence`, `threat_intel_severity` |
| `mitre_attack_mapping.csv` | `security_events.event_type == mitre_attack_mapping.event_type` | Left Outer Join | Many-to-1 | `mitre_id`, `technique_name`, `tactic`, `mitre_mapping_status` |
| `incident_history.csv` | `security_events.event_id == incident_history.event_id` | Left Outer Join | 1-to-1 (or 1-to-0) | `incident_id`, `incident_type`, `assigned_to`, `incident_status`, `response_time_str`, `response_time_minutes`, `resolution`, `incident_enrichment_status` |

---

## 7. MITRE Mapping Policy

The provided `mitre_attack_mapping.csv` dataset contains exactly **one reference mapping record**:
- `event_type`: `"Failed Login"` → `mitre_id`: `"T1110"` → `technique_name`: `"Brute Force"` → `tactic`: `"Credential Access"`

### Strict Policy Rules:
1. **Zero Assumption / Invented Mappings:** Do NOT invent, assume, or hardcode ATT&CK mappings for the remaining 9 event types (`Brute Force`, `Phishing Email`, `File Access`, `Port Scan`, `Malware Detection`, `USB Device Connected`, `Privilege Escalation`, `Login Success`, `SQL Injection Attempt`).
2. **Explicit Mapping Status:**
   - When `security_events.event_type == "Failed Login"`:
     - `mitre_mapping_status` = `"Mapped"`
     - `mitre_id` = `"T1110"`
     - `technique_name` = `"Brute Force"`
     - `tactic` = `"Credential Access"`
   - For all other event types:
     - `mitre_mapping_status` = `"Unmapped"`
     - `mitre_id` = `null`
     - `technique_name` = `null`
     - `tactic` = `null`

---

## 8. Threat Intelligence Matching Policy

An event is evaluated against `threat_intelligence.csv` by matching IP fields (`source_ip` or `destination_ip`) against `indicator_value` when `indicator_type == "IP Address"`.

### Strict Policy Rules:
1. **Verified Match Condition:** An event is flagged as a threat intelligence match ONLY if `source_ip == indicator_value` OR `destination_ip == indicator_value`.
2. **Matched Event State:**
   - `threat_intel_match` = `true`
   - `threat_intel_indicator_id` = `"IOC001"`
   - `threat_intel_indicator_type` = `"IP Address"`
   - `threat_name` = `"Brute Force"`
   - `threat_actor` = `"Unknown"`
   - `threat_confidence` = `"High"`
   - `threat_intel_severity` = `"High"`
3. **Unmatched Event State:**
   - `threat_intel_match` = `false`
   - `threat_intel_indicator_id` = `null`
   - `threat_intel_indicator_type` = `null`
   - `threat_name` = `null`
   - `threat_actor` = `null`
   - `threat_confidence` = `null`
   - `threat_intel_severity` = `null`

---

## 9. Vulnerability Enrichment Policy

### Key Mapping Rule:
`security_events.vulnerability_id` stores values matching `vulnerabilities.cve_id` (e.g., `"CVE-2024-1045"`).

### Strict Policy Rules:
1. **Correct Join Target:** The join MUST be executed on `security_events.vulnerability_id == vulnerabilities.cve_id`. Under no circumstances should `security_events.vulnerability_id` be joined against `vulnerabilities.vulnerability_id` (`VUL001`).
2. **Missing / Unmatched State:**
   - If `security_events.vulnerability_id` is missing (`NaN` / 427 rows in raw data) OR does not exist in `vulnerabilities.csv`:
     - `cve_id` = `null`
     - `vulnerability_enrichment_status` = `"Unmatched"`
     - All 7 vulnerability catalog fields (`vulnerability_id`, `vulnerability_name`, `vulnerability_severity`, `vulnerability_cvss_score`, `vulnerability_affected_asset`, `patch_available`, `vulnerability_status`) remain `null`.

---

## 10. Incident Enrichment Policy

### Key Mapping Rule:
`security_events.event_id` matches `incident_history.event_id`.

### Strict Policy Rules:
1. **Matched Event State (e.g., `EVT00001`):**
   - `incident_enrichment_status` = `"Enriched"`
   - `incident_id` = `"INC001"`
   - `incident_type` = `"Brute Force"`
   - `assigned_to` = `"SOC"`
   - `incident_status` = `"Closed"`
   - `response_time_str` = `"15 min"`
   - `response_time_minutes` = `15`
   - `resolution` = `"Blocked"`
2. **Unmatched Event State:**
   - `incident_enrichment_status` = `"Unmatched"`
   - `incident_id` = `null`, `incident_type` = `null`, `assigned_to` = `null`, `incident_status` = `null`, `response_time_str` = `null`, `response_time_minutes` = `null`, `resolution` = `null`.

---

## 11. Feature-Ready Fields

To support future analytics without implementing calculation logic prematurely in Milestone 1, the canonical schema exposes clean, normalized attributes categorized as follows:

| Attribute | Classification | Available / Prepared Feature (Milestone 1) | Future Calculated Feature (Milestone 2 / 3) |
| :--- | :--- | :--- | :--- |
| `failed_login_attempts` | Numeric Feature | Clean integer count prepared in event document | Brute force velocity score & anomaly thresholding |
| `raw_cvss_score` | Risk Factor | Clean float CVSS rating (0.0 - 10.0) prepared | Composite Risk Impact Score calculation |
| `event_severity` | Risk Factor | Standardized ordinal categorical (`Critical`, `High`, `Medium`, `Low`) | Base severity weight multiplier |
| `malware_detected` | Threat Flag | Normalized boolean (`true`/`false`) | Threat presence binary multiplier |
| `asset_criticality` | Asset Risk | Standardized tier (`Critical`, `High`, `Medium`, `Low` or `null`) | Asset criticality weight multiplier |
| `threat_confidence` | Threat Intel | Standardized rating (`High`, `Medium`, `Low` or `null`) | IoC threat probability multiplier |
| `timestamp` | Temporal Feature | ISO-8601 string + extracted hour/day/month | Rolling time-window event frequency & velocity |
| `event_type` | Categorical Feature | Standardized string | Multi-class threat model vectorization |
| `mitre_id` | Threat Taxonomy | Standardized ATT&CK ID (`T1110` or `null`) | MITRE kill-chain coverage matrix heatmap |
| `event_status` | Action Result | Standardized string (`Success`, `Blocked`, `Failed`, `Detected`) | Incident exposure & mitigation urgency rating |

*Note: Milestone 1 only cleans, normalizes, and packages these features into MongoDB documents. No risk algorithms or ML models are executed in Milestone 1.*

---

## 12. Milestone 1 vs Future Milestones

```
+-------------------------------------------------------------------------+
| Milestone 1: Data Aggregation & Threat Intelligence Layer (CURRENT)     |
|  • Raw CSV Data Profiling & Immutability Preservation                   |
|  • Data Cleaning, Normalization & Null Standardisation                  |
|  • Relational Merging & Enrichment (Assets, IoC, CVE, MITRE, Incident)  |
|  • Canonical Schema Packaging & Feature Field Preparation              |
|  • MongoDB Indexing, Document Storage & REST API Services               |
+-------------------------------------------------------------------------+
                                     │
                                     ▼
+-------------------------------------------------------------------------+
| Milestone 2: Anomaly Detection & ML Threat Detection Layer (FUTURE)     |
|  • Unsupervised ML Anomaly Detection (Isolation Forest, Autoencoders)   |
|  • Statistical Velocity Thresholding & Outlier Detection                |
|  • ML Confidence Scoring & Threat Likelihood Estimation                 |
+-------------------------------------------------------------------------+
                                     │
                                     ▼
+-------------------------------------------------------------------------+
| Milestone 3: Risk Scoring & Threat Correlation Analytics (FUTURE)       |
|  • Multi-factor Composite Risk Score Calculation (Asset x CVSS x IoC)   |
|  • Multi-stage Threat Campaign Correlation & Alert Clustering           |
|  • Automated Prioritization & Remediation Playbook Recommendations      |
+-------------------------------------------------------------------------+
```

---

## 13. Example Enriched Event

Below is the complete JSON document representation for **`EVT00001`** after processing through the Milestone 1 canonical enrichment pipeline.

> [!NOTE]  
> In `EVT00001`:  
> - **Incident History:** Matches `EVT00001` (`INC001`).  
> - **Asset Catalog:** Raw asset is `"Finance-PC-02"`. Asset catalog contains `"HR-PC-01"`, so asset fields remain `null`.  
> - **Vulnerability Catalog:** Raw CVE is `"CVE-2023-1234"`. Vulnerability catalog contains `"CVE-2024-1045"`, so vulnerability catalog fields remain `null`.  
> - **MITRE ATT&CK:** Raw event type is `"Brute Force"`. MITRE dataset contains `"Failed Login"`, so MITRE fields remain `null` (`"Unmapped"`).  
> - **Threat Intelligence:** Source/Dest IPs are internal (`"10.0.7.195"` / `"10.0.3.152"`). Threat catalog contains `"185.91.22.14"`, so threat intel fields remain `null` (`threat_intel_match: false`).

```json
{
  "event_id": "EVT00001",
  "raw_event_hash": "e99a18c428cb38d5f260853678922e03",
  "timestamp": "2025-08-01T00:00:00Z",
  "event_year": 2025,
  "event_month": 8,
  "event_day": 1,
  "event_hour": 0,
  "source_ip": "10.0.7.195",
  "destination_ip": "10.0.3.152",
  "protocol": "SSH",
  "source_country": "India",
  "destination_country": "India",
  "username": "david",
  "device_name": "Device-167",
  "os": "Windows 10",
  "event_type": "Brute Force",
  "event_status": "Failed",
  "event_severity": "Critical",
  "failed_login_attempts": 3,
  "malware_detected": false,
  "raw_cvss_score": 0.3,
  "cve_id": "CVE-2023-1234",
  "vulnerability_enrichment_status": "Unmatched",
  "vulnerability_id": null,
  "vulnerability_name": null,
  "vulnerability_severity": null,
  "vulnerability_cvss_score": null,
  "vulnerability_affected_asset": null,
  "patch_available": null,
  "vulnerability_status": null,
  "asset_name": "Finance-PC-02",
  "event_department": "Sales",
  "asset_enrichment_status": "Unmatched",
  "asset_id": null,
  "asset_type": null,
  "asset_owner": null,
  "asset_department": null,
  "asset_criticality": null,
  "asset_operating_system": null,
  "threat_intel_match": false,
  "threat_intel_indicator_id": null,
  "threat_intel_indicator_type": null,
  "threat_name": null,
  "threat_actor": null,
  "threat_confidence": null,
  "threat_intel_severity": null,
  "mitre_mapping_status": "Unmapped",
  "mitre_id": null,
  "technique_name": null,
  "tactic": null,
  "incident_enrichment_status": "Enriched",
  "incident_id": "INC001",
  "incident_type": "Brute Force",
  "assigned_to": "SOC",
  "incident_status": "Closed",
  "response_time_str": "15 min",
  "response_time_minutes": 15,
  "resolution": "Blocked"
}
```

---

## 14. Schema Design Principles

1. **Raw Data Immutability:** Original CSV datasets are stored in read-only format (`data/raw/`). The canonical schema strictly reads from raw data without mutating source files.
2. **Non-Destructive Left-Outer Enrichment:** Enrichment fields are attached alongside original event fields without replacing or modifying raw log values.
3. **Explicit Null Representation:** Non-matching lookups produce explicit `null` values instead of fabricated placeholder strings.
4. **No Fabricated Intelligence:** Threat intelligence, MITRE mappings, and vulnerability data are attached ONLY when an exact join key match exists in the reference dataset.
5. **Source Traceability:** Every field explicitly defines its source dataset and transformation rule.
6. **MongoDB & ML Readiness:** Standardized field types, ISO timestamps, and namespaced keys ensure seamless BSON indexing in MongoDB and vector readiness for downstream machine learning pipelines.
