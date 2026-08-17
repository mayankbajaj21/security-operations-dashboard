# Milestone 2 — Step 8: Prediction APIs

## 1. Purpose

The purpose of Milestone 2 Step 8 is to construct and deploy the REST API layer that exposes the machine learning threat detection engine, stored anomaly predictions, and model performance metrics to external consumers and the React AI Threat Detection Dashboard.

This step bridges the backend ML infrastructure (`backend/ml/`) and MongoDB prediction storage (`threat_predictions`) with standard REST endpoints, allowing live, on-the-fly event evaluation as well as fast retrieval of historical threat telemetry.

---

## 2. Architecture Flow

```
                      +----------------------------------+
                      |       Client / Frontend          |
                      +----------------------------------+
                                   |         |
                  POST /predict    |         |    GET /predictions
                 Live Inference    |         |    Stored Telemetry
                                   v         v
+----------------------------------------------------------------------------------+
|                              FastAPI REST Router                                 |
|                         (backend/app/api/predictions.py)                        |
+----------------------------------------------------------------------------------+
          |                                                       |
          | Live Pipeline                                         | Database Query
          v                                                       v
+------------------------------------+          +----------------------------------+
|           ModelLoader              |          |     ThreatPredictionService      |
|  - Preprocessing (StandardScaler)  |          |  (backend/app/services/...)      |
|  - Isolation Forest Inference      |          +----------------------------------+
+------------------------------------+                            |
          |                                                       | PyMongo Query
          v                                                       v
+------------------------------------+          +----------------------------------+
|      SecurityThreatClassifier      |          |          MongoDB Database        |
|  - Hybrid SOC Rule Evaluation      |          |        Collection:               |
+------------------------------------+          |        `threat_predictions`      |
          |                                     |        `security_events`         |
          v                                     +----------------------------------+
+------------------------------------+
|       ThreatConfidenceScorer       |
|  - 0–100 Bounded Evidence Score    |
+------------------------------------+
```

---

## 3. Six Endpoints Specification

### Endpoint Overview

| Endpoint | HTTP Method | Description | Primary Target |
| :--- | :--- | :--- | :--- |
| `/predict` | `POST` | Live on-the-fly ML inference & threat evaluation | Real-time Analyst Input / SIEM Ingestion |
| `/predictions` | `GET` | Paginated retrieval of stored predictions with filters | SOC Threat Prediction Table |
| `/predictions/{event_id}` | `GET` | Lookup single prediction joined with security event details | Event Investigation Page |
| `/anomalies` | `GET` | Filtered list of detected anomalies (`prediction == 'Suspicious'`) | AI Detection Overview / Anomaly Table |
| `/model-performance` | `GET` | Unsupervised model evaluation statistics and diagnostics | ML Model Performance Dashboard |
| `/threat-summary` | `GET` | Aggregated threat counts and score statistics | AI Threat Overview KPI Cards & Charts |

---

## 4. Request & Response Schemas

### 1. `POST /predict`
*   **Request Schema** (`PredictRequest`):
    *   `event_id`: `Optional[str]` (Default: `"EVT_LIVE_001"`)
    *   `event_type`: `Optional[str]` (e.g., `"Brute Force"`, `"Failed Login"`)
    *   `failed_login_attempts`: `Optional[int]` (e.g., `18`)
    *   `raw_cvss_score` (alias `cvss_score`): `Optional[float]` (e.g., `8.9`)
    *   `malware_detected`: `Optional[str]` (`"Yes"` / `"No"`)
    *   `event_severity` (alias `severity`): `Optional[str]` (`"Low"`, `"Medium"`, `"High"`, `"Critical"`)
    *   `protocol`: `Optional[str]` (`"SSH"`, `"TCP"`, `"HTTP"`)
    *   `event_status`: `Optional[str]` (`"Success"`, `"Failed"`, `"Blocked"`)
    *   `username`: `Optional[str]` (e.g., `"root"`)
    *   `source_ip`: `Optional[str]` (e.g., `"192.168.1.100"`)
    *   `destination_ip`: `Optional[str]` (e.g., `"10.0.0.1"`)
*   **Response Schema** (`PredictResponse`):
    ```json
    {
      "event_id": "EVT_TEST_001",
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
      "model_version": "isolation_forest_v1"
    }
    ```

### 2. `GET /predictions`
*   **Query Parameters**: `page` (default `1`), `limit` (default `50`), `prediction`, `threat_level`, `threat_type`, `min_confidence`, `search`.
*   **Response Schema** (`PaginatedPredictionsResponse`):
    ```json
    {
      "data": [
        {
          "event_id": "EVT00034",
          "prediction": "Suspicious",
          "anomaly_score": 0.061516,
          "threat_type": "Brute Force",
          "threat_level": "Critical Threat",
          "confidence_score": 81,
          "reasons": [ ... ],
          "model_version": "isolation_forest_v1",
          "created_at": "2026-08-17T21:06:03.000Z"
        }
      ],
      "pagination": { "page": 1, "limit": 50, "total": 1800, "total_pages": 36 }
    }
    ```

### 3. `GET /predictions/{event_id}`
*   **Path Parameter**: `event_id` (e.g. `EVT00034`).
*   **Response Schema** (`PredictionWithEventDetailsResponse`):
    Includes prediction document fields merged with `event_details` telemetry from `security_events`.

### 4. `GET /anomalies`
*   **Query Parameters**: `page` (default `1`), `limit` (default `50`), `min_confidence`.
*   **Response Schema** (`PaginatedPredictionsResponse`): Returns records strictly where `prediction == 'Suspicious'`.

### 5. `GET /model-performance`
*   **Response Schema** (`ModelPerformanceResponse`):
    ```json
    {
      "model_name": "Isolation Forest",
      "model_version": "isolation_forest_v1",
      "total_events_evaluated": 1800,
      "normal_count": 1710,
      "suspicious_count": 90,
      "anomaly_percentage": 5.0,
      "feature_count": 29,
      "contamination": 0.05,
      "score_distribution": {
        "min": -0.100174,
        "max": 0.061516,
        "mean": -0.039102,
        "median": -0.041507
      },
      "evaluation_note": "Evaluated via unsupervised anomaly detection diagnostics, score distribution stability, and feature variance sensitivity."
    }
    ```

### 6. `GET /threat-summary`
*   **Response Schema** (`ThreatSummaryResponse`):
    ```json
    {
      "total_events": 1800,
      "anomalies_detected": 90,
      "normal_events": 1710,
      "threat_levels": {
        "Normal": 1229,
        "Low Threat": 251,
        "Medium Threat": 232,
        "High Threat": 10,
        "Critical Threat": 78
      },
      "threat_types": {
        "Brute Force": 179,
        "Malware": 174,
        "Phishing": 185,
        "SQL Injection": 178,
        "Privilege Escalation": 172,
        "Port Scan": 181,
        "Unauthorized File Access": 182,
        "USB / Removable Media": 177,
        "Authentication Anomaly": 172
      },
      "average_confidence_score": 27.07
    }
    ```

---

## 5. Live Inference Flow

When `POST /predict` is invoked:
1.  **Payload Validation**: Input JSON is validated against `PredictRequest`.
2.  **Telemetry Data Framing**: Input fields are organized into a single-row Pandas DataFrame matching raw feature schema.
3.  **Preprocessing Transformation**: `ModelLoader` invokes the fitted `SecurityEventPreprocessor` (`backend/models/preprocessor.pkl`) to scale numeric features and one-hot encode categoricals into the 29-feature matrix.
4.  **Anomaly Detection**: `IsolationForestDetector` (`backend/models/isolation_forest.pkl`) calculates decision function anomaly score and outputs `prediction` (`Normal` or `Suspicious`).
5.  **Threat Classification**: `SecurityThreatClassifier` evaluates hybrid security detection rules to determine `threat_type`, `threat_level`, and XAI reasons.
6.  **Confidence Scoring**: `ThreatConfidenceScorer` calculates bounded 0–100 evidence score.

---

## 6. MongoDB Retrieval Flow

For read-only query endpoints (`GET /predictions`, `GET /predictions/{event_id}`, `GET /anomalies`, `GET /threat-summary`):
-   Queries run directly against the indexed MongoDB `threat_predictions` collection.
-   No re-inference is executed, ensuring sub-millisecond API response latency.
-   `GET /predictions/{event_id}` executes a secondary key lookup on `security_events` to supply full contextual telemetry for the SOC Event Investigation page.

---

## 7. Error Handling

*   **HTTP 404 Not Found**: Returned by `GET /predictions/{event_id}` when an invalid or nonexistent `event_id` (e.g. `EVT99999`) is requested.
*   **HTTP 422 Unprocessable Entity**: Returned automatically by FastAPI when request payloads violate Pydantic field constraints (e.g. negative login count, invalid CVSS score > 10.0).
*   **HTTP 503 Service Unavailable**: Returned if MongoDB cluster connection fails during collection querying.
*   **HTTP 500 Internal Server Error**: Returned if an unhandled internal exception occurs during live model inference.

---

## 8. Validation Results

*   **Test Suite Execution**: `python tests/test_prediction_api.py`
*   **Results**: `10 / 10 Tests Passed (OK)`
*   **Coverage**:
    *   Live model inference execution via `POST /predict`.
    *   Response field integrity across all endpoints.
    *   MongoDB query pagination, sorting, and filtering.
    *   HTTP 404 handling for missing `event_id`.
    *   Strict `Suspicious` filtering on `/anomalies`.
    *   Verified diagnostic statistics output on `/model-performance`.
    *   Dynamic aggregation accuracy on `/threat-summary`.
    *   Milestone 1 REST API regression safety (`/health`, `/events`, `/metrics`).
    *   Complete OpenAPI specification route registration.

---

## 9. Milestone 1 Compatibility

*   All 7 Milestone 1 REST endpoints (`/health`, `/events`, `/metrics`, `/mitre`, `/assets`, `/threat-intel`, `/trends`) remain registered and fully operational in `backend/app/main.py`.
*   Zero changes were made to existing M1 database schemas, route implementations, or response contracts.
