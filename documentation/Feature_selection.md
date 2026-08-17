# M2 Feature Selection

## 1. Purpose
Milestone 1 established the canonical security-event data processing, cleaning, enrichment, and MongoDB storage pipeline. Milestone 2 builds directly upon this foundation to answer the core analytical question: *"Is this activity suspicious, and how suspicious is it?"*

This document formalizes the feature selection decisions for Milestone 2 ML-assisted threat detection. It defines which fields from the processed Milestone 1 dataset will be used directly, which features will be derived through temporal and behavioral transformations, and which fields are excluded from model training to prevent noise, overfitting, or data leakage.

---

## 2. Data Source
The primary input data for Milestone 2 feature selection consists of:
- **`security_events` Dataset**: 1,800 canonical security event records processed through the Milestone 1 ETL pipeline (`data/processed/enriched_security_events.csv`).
- **MongoDB Production Database**: The `security_operations` database (specifically the `security_events` collection) serves as the persistent query and production data source for the application.
- **Reference Datasets**: Supplemental reference data (`assets.csv`, `vulnerabilities.csv`, `threat_intelligence.csv`, `mitre_attack_mapping.csv`, `incident_history.csv`) enriched the base event stream during Milestone 1.

*Note: While reference datasets provide valuable contextual metadata for SOC dashboard visualizations and risk scoring in Milestone 3, inspection reveals that several reference lookups are sparse (e.g., single-record catalogs). They are not used as primary inputs for machine learning model training.*

---

## 3. Feature Selection Criteria
Candidate features were evaluated against strict criteria to ensure high model quality and operational reliability:

1. **Security Relevance**: The feature must represent an established technical indicator of threat activity or anomalous user/network behavior.
2. **Data Availability & Completeness**: The underlying data fields must be consistently present without excessive missing values.
3. **Statistical Variance**: The feature must exhibit meaningful variance across events to allow anomaly algorithms to distinguish normal from abnormal patterns.
4. **Reliable Derivability**: Derived behavioral features must be deterministically calculable from existing event timestamps, user accounts, or network identifiers.
5. **Suitability for Unsupervised Anomaly Detection**: Features must be numeric, continuous, or categorical variables that can be effectively processed by distance- or isolation-based ML models (e.g., Isolation Forest).
6. **Prevention of High-Cardinality Noise**: High-cardinality unique identifiers (such as unique log IDs or unique IP address strings) must be excluded to prevent overfitting.
7. **Prevention of Post-Event Information Leakage**: Attributes generated *after* an incident is remediated (such as incident ticket status or SOC analyst notes) must be excluded from predictive threat detection.

---

## 4. Selected M2 Features

The following 13 features have been selected for the Milestone 2 machine learning feature matrix, categorized per the source specification:

| Feature Category | Feature | Source Field(s) | Type | Direct / Derived | Why Selected |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Authentication** | `failed_login_attempts` | `security_events.failed_login_attempts` | Integer | Direct | Directly indicates brute-force or authentication abuse velocity. |
| **Authentication** | `login_frequency_1h` | `username`, `event_type`, `timestamp` | Continuous (Numeric) | Derived | Measures rolling 1-hour authentication event frequency (`Failed Login`, `Login Success`, `Brute Force`) per user. |
| **Authentication** | `login_hour` | `security_events.timestamp` | Integer | Derived | Captures the hour of day (`0`–`23`) to identify temporal anomaly patterns. |
| **Network** | `protocol` | `security_events.protocol` | Categorical | Direct | Captures network communication protocol (`HTTP`, `HTTPS`, `SMB`, `SSH`, `TCP`). |
| **Network** | `unique_destinations_24h` | `username`, `destination_ip`, `timestamp` | Numeric | Derived | Counts distinct destination IPs accessed by a user over a rolling 24-hour window; detects internal scanning / lateral movement. |
| **User behavior** | `events_per_user_1h` | `username`, `timestamp` | Continuous (Numeric) | Derived | Quantifies short-term rolling activity volume per user account over a 1-hour window. |
| **User behavior** | `after_hours_activity` | `security_events.timestamp` | Binary | Derived | Flags events occurring outside standard operational business hours to highlight off-peak anomalies. |
| **Vulnerability** | `raw_cvss_score` | `security_events.raw_cvss_score` | Continuous (Float) | Direct | Represents the project's available CVSS score corresponding to the M2 `cvss_score` requirement; 100% complete across all 1,800 events. |
| **Vulnerability** | `vulnerability_present` | `security_events.vulnerability_id` | Binary | Derived | Indicates whether an event references an associated CVE identifier (`1` if present, `0` if null). |
| **Security** | `malware_detected` | `security_events.malware_detected` | Binary | Direct | Direct indicator of malicious software execution (`Yes`/`No` cast to `1`/`0`). |
| **Security** | `severity_score` | `security_events.event_severity` | Ordinal Numeric | Derived | Maps categorical log severity (`Low`, `Medium`, `High`, `Critical`) into a 1–4 numeric scale for ML model consumption. |
| **Security** | `event_type` | `security_events.event_type` | Categorical | Direct | Identifies security event action category across 10 normalized log types. |
| **Security** | `event_status` | `security_events.event_status` | Categorical | Direct | Captures execution outcome (`Success`, `Blocked`, `Failed`, `Detected`). |
| **Location** | *`impossible_travel_flag`* | `source_country`, `destination_country` | Binary | Derived | *Assessed in Section 6*: Excluded due to zero spatial variance (100% `"India"`) and lack of location coordinates. |

*Note: All categorical features (`protocol`, `event_type`, `event_status`) will be encoded (e.g., One-Hot Encoding) during the preprocessing stage rather than being passed as raw strings to the ML model.*

---

## 5. Derived Features

Below is the specification for how each derived feature will be calculated during preprocessing:

- **`login_hour`**: Extracted from `timestamp` (or existing `event_hour`) as an integer ranging from `0` to `23`.
- **`after_hours_activity`**: Binary flag derived from `login_hour`. 
  *Operational Assumption*: The exact operational-hours threshold will be defined and configured during the preprocessing stage as a project assumption (e.g., setting hours outside an agreed business window as `1`, otherwise `0`). The Milestone 2 specification does not mandate a fixed business window.
- **`events_per_user_1h`**: Calculated via a rolling 1-hour time window grouped by `username` and ordered by `timestamp`.
- **`login_frequency_1h`**: Calculated via a rolling 1-hour time window grouped by `username` and filtered for authentication-related event types (`Failed Login`, `Login Success`, `Brute Force`).
- **`unique_destinations_24h`**: Calculated via a rolling 24-hour time window tracking the count of distinct `destination_ip` values accessed per `username`.
- **`severity_score`**: Mapped ordinally from `event_severity`: `Low` $\rightarrow 1$, `Medium` $\rightarrow 2$, `High` $\rightarrow 3$, `Critical` $\rightarrow 4$.
- **`vulnerability_present`**: Binary transformation of `vulnerability_id` (`1` if non-null, `0` if null).

---

## 6. Impossible Travel Assessment

The M2 specification lists `impossible_travel_flag` as a recommended candidate feature. A detailed inspection of the current Milestone 1 dataset was conducted to evaluate its feasibility:

1. **`source_country`**: Contains a single static value (`"India"`) for 100% of the 1,800 records (zero variance).
2. **`destination_country`**: Contains a single static value (`"India"`) for 100% of the 1,800 records (zero variance).
3. **Geolocation Data**: No external IP geolocation lookup dataset or coordinates are present in the M1 project data.
4. **Chronological Analysis**: Sorting user timelines reveals 0 geographic country transitions across all user accounts.

### Decision:
**`impossible_travel_flag` is NOT included in the initial ML feature matrix.**

To preserve data integrity, synthetic country transitions or fake speed calculations will not be fabricated. If reliable IP geolocation data is integrated in future milestones, `impossible_travel_flag` can be re-evaluated.

---

## 7. Features Excluded

The following fields from the Milestone 1 dataset are explicitly excluded from the direct ML feature matrix:

| Excluded Field | Reason for Exclusion |
| :--- | :--- |
| `event_id`, `raw_event_hash` | Unique primary keys with zero statistical predictive value; causes arbitrary partitioning. |
| `source_ip` | Extremely high cardinality (1,800 distinct IPs across 1,800 events; 100% unique per row). Causes extreme dimensionality explosion and overfitting. |
| `source_country`, `destination_country` | Zero variance (100% `"India"`). Static columns provide no discriminatory signal. |
| `threat_intel_match` | Zero variance (100% `False` across all 1,800 events due to single-record threat feed). |
| `incident_id`, `incident_status`, `assigned_to`, `response_time`, `resolution` | Post-event information leakage. These fields represent SOC ticketing actions performed *after* log generation. |
| `vulnerability_cvss_score`, `patch_available`, `vulnerability_status` | Sparse reference join fields (missing in 1,356 of 1,800 records). `raw_cvss_score` is used instead as it has 100% coverage. |
| `asset_criticality`, `asset_type`, `asset_owner`, `asset_department` | Sparse reference join fields (missing in 1,447 of 1,800 records due to single-asset catalog). |
| `mitre_id`, `technique_name`, `tactic` | Sparse reference mapping (unmapped in 1,621 of 1,800 events). |

---

## 8. Reference Dataset Assessment

An assessment of the five Milestone 1 reference datasets yields the following findings regarding their role in Milestone 2:

- **`assets.csv`**: Contains 1 asset record (`HR-PC-01`). Matches 353 events; 1,447 events remain unmatched. Too sparse for ML training; retained for UI contextual display.
- **`vulnerabilities.csv`**: Contains 1 CVE catalog record (`CVE-2024-1045`). Matches 444 events; 1,356 events remain unmatched. Too sparse for ML training; `raw_cvss_score` and `vulnerability_present` are used instead.
- **`threat_intelligence.csv`**: Contains 1 IoC IP record (`185.91.22.14`). Results in 0 event matches across 1,800 records. Too sparse for ML feature training; retained for rule-based matching.
- **`mitre_attack_mapping.csv`**: Contains 1 mapping record (`Failed Login` $\rightarrow$ `T1110`). Maps 179 events; 1,621 events remain unmapped. Used for taxonomy mapping, not primary ML clustering.
- **`incident_history.csv`**: Contains 1 incident record (`INC001`). Excluded to prevent post-event leakage.

*Conclusion*: Reference datasets provide essential business context and UI metadata for Milestone 1 and Milestone 3 risk scoring, but are too sparse to serve as direct inputs for model training in Milestone 2.

---

## 9. Final M2 ML Feature Set

The final feature set to be generated by the upcoming preprocessing pipeline consists of:

### Numerical / Binary Features (10)
1. `failed_login_attempts`
2. `raw_cvss_score`
3. `malware_detected`
4. `severity_score`
5. `login_hour`
6. `after_hours_activity`
7. `events_per_user_1h`
8. `login_frequency_1h`
9. `unique_destinations_24h`
10. `vulnerability_present`

### Categorical Features (3)
1. `protocol`
2. `event_type`
3. `event_status`

*Categorical variables will be encoded (e.g., One-Hot Encoding) during preprocessing prior to model fitting.*

---

## 10. M2 Feature Pipeline Architecture

```
Milestone 1 Processed Security Events
                 │
                 ▼
         Feature Selection
                 │
                 ▼
    Derived Behavioral Features
                 │
                 ▼
        Categorical Encoding
                 │
                 ▼
     Scaling (Where Appropriate)
                 │
                 ▼
       Final ML Feature Matrix
                 │
                 ▼
         Isolation Forest
```

*Note: This architecture overview is for documentation and design specification purposes only. The pipeline will be implemented in M2 Step 2.*

---

## 11. Data Quality Considerations

Inspection of the Milestone 1 dataset revealed key data-quality characteristics that directly informed this feature selection:

1. **Static Geographic Fields**: Both `source_country` and `destination_country` are static (`"India"`), rendering country-level location analysis uninformative.
2. **Unique Source IP Addresses**: 100% of rows contain unique `source_ip` values, making raw IPs unusable without aggregation.
3. **Reference Table Sparsity**: Reference CSVs each contain single representative records, leading to high null counts in joined catalog fields.
4. **CVSS Score Field Selection**: `raw_cvss_score` (from `security_events.csv`) provides 100% data coverage (0 nulls), whereas catalog `vulnerability_cvss_score` is missing for 75% of records.
5. **Zero Threat Intelligence Variance**: No IP address in `security_events.csv` matches the single IoC in `threat_intelligence.csv`, resulting in 0% positive hits.

---

## 12. Next Step

The next implementation stage for Milestone 2 is:

**`M2 Step 2 — ML Preprocessing Pipeline`**

*(This next step will involve building `preprocessing.py`, generating `m2_feature_matrix.csv`, and preparing the data for unsupervised anomaly model training).*
