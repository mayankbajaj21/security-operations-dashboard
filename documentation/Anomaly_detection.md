# Milestone 2 — Isolation Forest Anomaly Detection

## 1. Objective
This document details the design, configuration, implementation, and validation of the unsupervised Isolation Forest anomaly detection model for Milestone 2 — Step 3A of the AI-Assisted Threat Detection / Security Operations Dashboard project.

The objective of this step is to implement a reproducible unsupervised model that analyzes processed security event telemetry (`data/processed/m2_feature_matrix.csv`) to identify anomalous events that deviate significantly from standard operational baselines.

- **Source Code**: `backend/ml/anomaly_detection.py`
- **Model Artifact**: `backend/models/isolation_forest.pkl`
- **Development Predictions Output**: `data/processed/m2_anomaly_predictions.csv`

---

## 2. Input Feature Matrix Specification
- **Input File**: `data/processed/m2_feature_matrix.csv`
- **Record Count**: 1,800 security event records
- **Total Columns**: 30 columns
- **Traceability Column**: `event_id` (Column 1, strictly excluded from model feature vector $X$)
- **ML Feature Vector ($X$)**: 29 numerical/encoded features (7 continuous scaled features, 3 binary flags, 19 one-hot encoded categorical columns)

---

## 3. Algorithm Selection Rationale (Isolation Forest)
Isolation Forest (`sklearn.ensemble.IsolationForest`) was selected as the primary anomaly detection algorithm for the following reasons:
1. **Unsupervised Nature**: Operates effectively on unlabeled security telemetry without requiring historical attack labels.
2. **Path Isolation Efficiency**: Explicitly isolates anomalies instead of profiling normal data points. Anomalies require fewer random split partitions to isolate in decision trees.
3. **Linear Time Complexity**: Scales efficiently to high volumes of security event logs ($O(n \log n)$ training, $O(n)$ inference).
4. **Multivariate Feature Handling**: Capable of detecting complex interactions across temporal, categorical, and behavioral continuous features.

---

## 4. Model Configuration & Parameters
The model is instantiated with the following explicit parameters:

```python
IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42,
    n_jobs=-1
)
```

| Parameter | Value | Rationale & Justification |
| :--- | :--- | :--- |
| `n_estimators` | `100` | Standard ensemble size balancing variance reduction and training execution efficiency. |
| `contamination` | `0.05` | Expected proportion of anomalies (5%) based on typical SOC baseline traffic assumptions. |
| `random_state` | `42` | Fixed seed ensuring 100% deterministic, reproducible predictions across executions. |
| `n_jobs` | `-1` | Parallel processing across all CPU threads. |

---

## 5. Meaning of Prediction Values
Isolation Forest produces raw tree prediction flags ($1$ for normal, $-1$ for anomaly). In this pipeline, these raw outputs are converted into analyst-facing domain labels:

- **`Normal`** (Raw output `1`): The security event exhibits attribute patterns consistent with standard baseline operational behavior.
- **`Suspicious`** (Raw output `-1`): The security event exhibits statistically anomalous attribute combinations (e.g. spike in failed logins, abnormal after-hours activity, rare protocol/event combinations).

---

## 6. Meaning of Anomaly Score
- **Calculation**: Inverted scikit-learn decision function score $\text{anomaly\_score} = -\text{decision\_function}(X)$.
- **Interpretation**: 
  - **Higher Positive Scores** ($> 0.0$): Indicate a higher degree of isolation / anomaly.
  - **Lower Negative Scores** ($< 0.0$): Indicate typical inlier baseline activity.
- **CRITICAL NOTE**: The `anomaly_score` is an arbitrary mathematical measure of tree path length isolation. **It is NOT an attack probability**, percentage risk score, or ground-truth threat severity.

---

## 7. Contamination Assumption
- Because this is an unsupervised model operating on unlabeled security telemetry, the `contamination=0.05` parameter is an **operational model configuration assumption**, not a ground-truth measurement of actual malicious attacks.
- Setting `contamination=0.05` instructs the Isolation Forest threshold decision boundary to label the top 5% most isolated events as `Suspicious`.
- It does **NOT** imply that exactly 5% of events are guaranteed malicious or that the remaining 95% are completely benign.

---

## 8. Training & Prediction Procedure
1. Load `data/processed/m2_feature_matrix.csv`.
2. Extract `event_id` into a separate traceability vector.
3. Form feature matrix $X$ using the remaining 29 ML model columns.
4. Fit `IsolationForestDetector` on $X$.
5. Compute raw predictions and inverted decision function scores.
6. Map prediction labels (`Normal` / `Suspicious`) and construct prediction DataFrame.
7. Serialize fitted detector object to `backend/models/isolation_forest.pkl`.
8. Save development prediction table to `data/processed/m2_anomaly_predictions.csv`.

---

## 9. Validation & Sanity Check Results

### A. Statistical Summary
- **Total Security Events Evaluated**: 1,800
- **Normal Events Predicted**: 1,710 (95.0%)
- **Suspicious Events Predicted**: 90 (5.0%)
- **Anomaly Score Minimum**: `-0.100174`
- **Anomaly Score Maximum**: `0.061516`
- **Anomaly Score Mean**: `-0.039102`
- **Anomaly Score Median**: `-0.041507`

### B. Sanity Checks Status
- **Prediction Count**: Exactly 1,800 predictions (100% complete) — **PASSED**
- **Traceability Mapping**: 1:1 mapping between `event_id` and prediction — **PASSED**
- **Data Completeness**: Zero `NaN` or `inf` values in `anomaly_score` — **PASSED**
- **Label Integrity**: Prediction values strictly constrained to `'Normal'` or `'Suspicious'` — **PASSED**
- **Feature Isolation**: `event_id` excluded from model inputs; exactly 29 features used — **PASSED**
- **Reproducibility**: Identical output across repeated runs using `random_state=42` — **PASSED**
- **Non-Degenerate Check**: Model output is balanced (95% Normal, 5% Suspicious) — **PASSED**

### C. Inspection of Top Suspicious Events
The top anomalous events identified by the model correlate strongly with security risk indicators:
1. `EVT00034` (Score: `0.061516`): User `root`, `Failed Login`, 18 failed attempts, high severity.
2. `EVT00144` (Score: `0.043279`): User `david`, `Failed Login`, 16 failed attempts, CVSS 5.9.
3. `EVT00036` (Score: `0.042562`): User `root`, `Phishing Email`, CVSS 5.0.
4. `EVT01233` (Score: `0.041656`): User `david`, `Malware Detection`, `malware_detected = Yes`.
5. `EVT01600` (Score: `0.031116`): User `admin`, `Login Success` following 20 failed login attempts.

---

## 10. Model Limitations
1. **Unsupervised Output**: Identifies statistical outliers, not confirmed malicious intent. Legitimate unusual events (e.g. system maintenance) may be labeled `Suspicious`.
2. **Fixed Contamination Threshold**: Static 5% contamination threshold does not dynamically adjust to variable attack rates.
3. **Absence of Ground Truth**: Supervised metrics (Precision, Recall, Accuracy, F1-Score) cannot be computed without annotated attack labels.

---

## 11. Why Confidence Score & Classification are NOT Implemented Yet
- **Confidence Scoring**: Calculating a calibrated 0–100% confidence score requires normal score mapping or supervised ground-truth validation, scheduled for a later M2 step.
- **Threat Classification**: Categorizing anomalies into specific attack vectors or risk priority tiers belongs to Milestone 3 risk prioritization.

---

## 12. Next M2 Step
**`Milestone 2 — Step 3B: Threat Classification & Confidence Scoring`** (or API Integration / Model Persistence as specified by project roadmap).
