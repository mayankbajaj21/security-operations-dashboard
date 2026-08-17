# Prediction Storage in MongoDB Schema Specification

**Project**: Security Operations Dashboard  
**Milestone**: 2 — Prediction storage in MongoDB (Step 7)  
**Database Name**: `security_operations`  
**Collection Name**: `threat_predictions`  
**Document Status**: Production Design Specification  

---

## 1. Purpose & Overview

The `threat_predictions` collection is the primary storage layer for Milestone 2 Machine Learning anomaly detection predictions, SOC threat classifications, Threat Confidence Scores, and explainable AI (XAI) reason arrays.

It acts as the decoupling bridge between the asynchronous offline ML detection pipeline (`backend/ml/`) and real-time backend REST APIs / SOC frontend dashboard interfaces.

---

## 2. Architectural Data Ownership Model

```
+------------------------------------+        1:1 Match        +------------------------------------+
|  security_events (Authoritative)   | <=====================> |   threat_predictions (ML Results)  |
+------------------------------------+      via event_id       +------------------------------------+
| - _id                              |                         | - _id                              |
| - event_id (PK)                    |                         | - event_id (PK, FK)                |
| - timestamp                        |                         | - prediction                       |
| - source_ip, destination_ip        |                         | - anomaly_score                    |
| - event_type, event_status         |                         | - threat_type                      |
| - raw_cvss_score, asset_name       |                         | - threat_level                     |
| - failed_login_attempts            |                         | - confidence_score                 |
| - malware_detected                 |                         | - reasons []                       |
+------------------------------------+                         | - model_version                    |
                                                               | - created_at                       |
                                                               +------------------------------------+
```

### Data Ownership Principles:
1. **Zero Raw Duplication**: The `security_events` collection remains the single authoritative telemetry source for event timestamps, network IPs, device specs, CVSS scores, and asset mappings. Full event documents are **NOT** duplicated into `threat_predictions`.
2. **Relational Linkage**: The `event_id` field establishes a strict 1:1 foreign-key relationship between `threat_predictions` and `security_events`.
3. **Idempotency**: All database writes use `ReplaceOne({"event_id": event_id}, doc, upsert=True)` based on `event_id`.

---

## 3. Document Schema Specification

### Collection: `threat_predictions`

| Field | Type | Required | Description | Constraint / Bounds | Index |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `_id` | ObjectId | Yes | MongoDB internal BSON object ID | System generated | Unique Primary |
| `event_id` | String | Yes | Canonical event identifier (e.g. `EVT00034`) | Foreign key matching `security_events.event_id` | **Unique Index** |
| `prediction` | String | Yes | Isolation Forest model prediction output | `Normal` / `Suspicious` | Standard Index |
| `anomaly_score` | Double | Yes | Continuous decision function score | $-0.10017 \le S_{raw} \le +0.06152$ | None |
| `threat_type` | String | Yes | Categorical classification of security activity | e.g. `Brute Force`, `Malware`, `Phishing`, `SQL Injection` | Standard Index |
| `threat_level` | String | Yes | 5-tier calibrated SOC threat hierarchy | `Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat` | Compound Index |
| `confidence_score` | Integer | Yes | Bounded 0–100 threat confidence score | $0 \le \text{confidence\_score} \le 100$ | Standard Index |
| `reasons` | Array[String] | Yes | Human-readable explanation strings | Array of XAI explanation strings | None |
| `model_version` | String | Yes | Tracked ML model version string | Default: `isolation_forest_v1` | None |
| `created_at` | Datetime | Yes | UTC timestamp of prediction persistence | BSON Datetime (`YYYY-MM-DDTHH:MM:SSZ`) | Standard Index |

---

## 4. Sample BSON Document (`EVT00034`)

```json
{
  "_id": { "$oid": "66c0d8f1e4b0123456789abc" },
  "event_id": "EVT00034",
  "prediction": "Suspicious",
  "anomaly_score": 0.061516,
  "threat_type": "Brute Force",
  "threat_level": "Critical Threat",
  "confidence_score": 81,
  "reasons": [
    "Excessive failed login attempts (18 attempts exceeded threshold of 10)",
    "Activity occurred outside standard operational hours (02:00)",
    "Isolation Forest flagged event as anomalous (score: 0.061516)"
  ],
  "model_version": "isolation_forest_v1",
  "created_at": { "$date": "2026-08-17T21:06:03.000Z" }
}
```

---

## 5. Index Strategy & Specification

| Index Name | Index Keys | Type | Rationale / Query Target |
| :--- | :--- | :---: | :--- |
| `uniq_event_id` | `{"event_id": 1}` | **Unique** | Enforces 1:1 primary key constraint per event and accelerates $O(1)$ single-event lookups. |
| `idx_threat_level_created` | `{"threat_level": 1, "created_at": -1}` | Compound | Powers high-priority SOC dashboard feeds (e.g. filtering Critical/High alerts sorted by time). |
| `idx_prediction` | `{"prediction": 1}` | Standard | Accelerates queries filtering anomalous vs normal events (`prediction == 'Suspicious'`). |
| `idx_confidence_score` | `{"confidence_score": -1}` | Standard | Speeds up sorting events by highest confidence threat score. |
| `idx_threat_type` | `{"threat_type": 1}` | Standard | Supports threat breakdown widgets (e.g. filtering Brute Force or Malware threats). |
| `idx_created_at` | `{"created_at": -1}` | Standard | Powers chronological sorting and audit logging queries. |

---

## 6. Seeding Pipeline & Service Operations

The storage layer is accessible via `backend/app/services/threat_prediction_service.py` and seeded via `scripts/seed_threat_predictions.py`.

### Idempotency Behavior:
Seeding uses `ReplaceOne({"event_id": event_id}, doc, upsert=True)`. Running the seeding script repeatedly against the database will **never** duplicate records or orphan predictions.

---

## 7. Post-Seeding Validation & Referential Integrity

Validation executed against `security_operations` database:

| Metric | Result | Status |
| :--- | :---: | :---: |
| **`threat_predictions` Collection Count** | **1,800** | PASS |
| **`security_events` Primary Count** | **1,800** | PASS |
| **1:1 Matching `event_id` Pairings** | **1,800** | PASS |
| **Orphan Predictions** | **0** | PASS |
| **Duplicate `event_id`s** | **0** | PASS |
| **Confidence Score Bounds** | **$0 \le \text{score} \le 100$** | PASS |
| **Referential Integrity Validation** | **VALID** | **SUCCESS** |

---

## 8. Representative Verified MongoDB Documents

1. **`EVT00034`**: Prediction: `Suspicious` | Threat Type: `Brute Force` | Threat Level: `Critical Threat` | Confidence: `81/100`
2. **`EVT00036`**: Prediction: `Suspicious` | Threat Type: `Phishing` | Threat Level: `High Threat` | Confidence: `55/100`
3. **`EVT00144`**: Prediction: `Suspicious` | Threat Type: `Brute Force` | Threat Level: `Critical Threat` | Confidence: `76/100`
4. **`EVT01233`**: Prediction: `Suspicious` | Threat Type: `Malware` | Threat Level: `Critical Threat` | Confidence: `76/100`
5. **`EVT01600`**: Prediction: `Suspicious` | Threat Type: `Brute Force` | Threat Level: `Critical Threat` | Confidence: `73/100`
