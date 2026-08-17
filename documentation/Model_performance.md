# Milestone 2 — Model Evaluation Documentation

## 1. Executive Summary & Objective
This document presents the Model Evaluation diagnostics for the unsupervised Isolation Forest anomaly detection model implemented in Milestone 2 — Step 3A/3B of the AI-Assisted Threat Detection / Security Operations Dashboard project.

The objective is to conduct a scientifically rigorous evaluation of model behavior, statistical score distribution, contamination sensitivity, security-context sanity, and stability without manufacturing false metrics or altering existing model artifacts.

- **Evaluated Dataset**: `data/processed/enriched_security_events.csv` (1,800 events)
- **Feature Matrix**: `data/processed/m2_feature_matrix.csv` (29 ML features)
- **Evaluated Model Artifact**: `backend/models/isolation_forest.pkl`
- **Evaluated Output Predictions**: `data/processed/m2_anomaly_predictions.csv`

---

## 2. Ground-Truth Availability Assessment
A thorough audit of the existing workspace datasets (`security_events.csv`, `enriched_security_events.csv`, `incident_history.csv`) was conducted to determine whether reliable binary ground-truth labels exist:

- **`event_type`**: Reflects event taxonomy (`Failed Login`, `Brute Force`, `File Access`, etc.), not verified benign vs malicious labels.
- **`event_severity`**: Reflects priority classification (`Low`, `Medium`, `High`, `Critical`), not ground-truth incident validation.
- **`event_status`**: Reflects system execution outcome (`Success`, `Failed`, `Blocked`), not attack ground truth.
- **`incident_history.csv`**: Contains a single reference catalog row (`INC001`) and is not a 1,800-record incident label set.

### Scientific Determination:
> **No explicit binary ground-truth labels ("Benign" vs "Malicious" / "Attack" vs "Non-Attack") exist in the dataset.**

---

## 3. Evaluation Methodology
Because no ground-truth attack labels exist:
1. **Supervised Metrics (Precision, Recall, F1-Score, Accuracy, Confusion Matrix) CANNOT be calculated honestly.** Fabricating synthetic labels or treating model outputs as ground truth would be scientifically invalid.
2. Evaluation is conducted using **Unsupervised Model-Behavior Analysis**, **Statistical Score Distribution**, **Contamination Sensitivity Analysis**, **Feature Contribution Diagnostics**, and **Security-Context Sanity Validation**.

---

## 4. Unsupervised Evaluation & Anomaly Distribution

### A. Prediction Summary
- **Total Security Events Evaluated**: 1,800 events
- **Normal Events (`Normal`)**: 1,710 events (95.00%)
- **Suspicious Events (`Suspicious`)**: 90 events (5.00%)
- **Anomaly Percentage**: 5.00%

### B. Anomaly Score Distribution Statistics
Formula: $\text{anomaly\_score} = -\text{decision\_function}(X)$

| Statistic | Score Value | Interpretation |
| :--- | :--- | :--- |
| **Minimum Score** | `-0.100174` | Highly routine inlier event |
| **25th Percentile** | `-0.054749` | Baseline normal inlier traffic |
| **Median (50th Percentile)** | `-0.041507` | Baseline normal inlier traffic |
| **75th Percentile** | `-0.025133` | Normal traffic showing mild variance |
| **Mean Score** | `-0.039102` | Overall dataset score central tendency |
| **Standard Deviation** | `0.022277` | Score dispersion |
| **90th Percentile** | `-0.009102` | Elevated score approaching decision boundary |
| **95th Percentile (Threshold)** | `0.000000` | **Exact decision boundary between Normal and Suspicious** |
| **99th Percentile** | `0.018667` | Highly isolated anomalous events |
| **Maximum Score** | `0.061516` | Most anomalous event in dataset (`EVT00034`) |

---

## 5. Security-Context Sanity Validation

### A. High-Score Anomalies (Top 5 Suspicious Events)
Inspection confirms that events receiving the highest anomaly scores exhibit genuine security risk indicators:

1. **`EVT00034`** (Anomaly Score: `0.061516` | `Suspicious`): User `root`, `Failed Login`, 18 failed login attempts (extreme brute-force burst).
2. **`EVT00144`** (Anomaly Score: `0.043279` | `Suspicious`): User `david`, `Failed Login`, 16 failed login attempts, CVSS 5.9.
3. **`EVT00036`** (Anomaly Score: `0.042562` | `Suspicious`): User `root`, `Phishing Email`, CVSS 5.0.
4. **`EVT01233`** (Anomaly Score: `0.041656` | `Suspicious`): User `david`, `Malware Detection`, `malware_detected = Yes`.
5. **`EVT01600`** (Anomaly Score: `0.031116` | `Suspicious`): User `admin`, `Login Success` following 20 failed login attempts (successful credential stuffing).

### B. Low-Score Inliers (Top Normal Events)
Inspection confirms that events receiving the lowest anomaly scores represent standard, routine operational behavior:
- Routine `File Access` events during standard business hours (e.g. `EVT00380`, `EVT00617`, `EVT00927`, `EVT00950`, `EVT01523`).
- 0 failed login attempts, no malware detected, standard protocols, expected user activity rates.

---

## 6. Contamination & Sensitivity Analysis
The model is configured with `contamination = 0.05` (5%).

### Sensitivity Analysis Across Contamination Values (Diagnostic Only):

| Contamination Level | Normal Count | Suspicious Count | Anomaly Rate | Decision Threshold Cutoff |
| :---: | :---: | :---: | :---: | :---: |
| **1.0%** | 1,782 | 18 | 1.0% | $\approx 0.018667$ |
| **3.0%** | 1,746 | 54 | 3.0% | $\approx 0.004500$ |
| **5.0% (Production Default)** | **1,710** | **90** | **5.0%** | **$\approx 0.000000$** |
| **8.0%** | 1,656 | 144 | 8.0% | $\approx -0.006800$ |
| **10.0%** | 1,620 | 180 | 10.0% | $\approx -0.009102$ |

### Operational Insight:
- `contamination` is a SOC triage capacity tuning knob, **not** evidence of true malicious attack frequency.
- Adjusting `contamination` shifts the decision boundary score higher or lower without retraining feature representations.

---

## 7. Model Diagnostics & Stability Verification
- **Feature Dimensionality**: Exactly 29 ML features used (`event_id` excluded).
- **Data Integrity**: 0 missing/NaN/inf values in input feature matrix or output anomaly scores.
- **Degeneracy Check**: Non-degenerate output distribution (95% Normal, 5% Suspicious).
- **Stability / Reproducibility**: Executing inference across multiple independent runs with `random_state=42` produced 100% identical outputs.

---

## 8. Feature Contribution Diagnostic

Pearson correlation analysis between model features and `anomaly_score`:

| Feature Name | Correlation with Anomaly Score | Impact Direction |
| :--- | :---: | :--- |
| `malware_detected` | **+0.3376** | Higher $\rightarrow$ Significantly More Suspicious |
| `event_type_Malware Detection` | **+0.3376** | Higher $\rightarrow$ Significantly More Suspicious |
| `failed_login_attempts` | **+0.3152** | Higher $\rightarrow$ Significantly More Suspicious |
| `login_frequency_1h` | **+0.2938** | Higher $\rightarrow$ Significantly More Suspicious |
| `event_type_Login Success` | **+0.1803** | Higher $\rightarrow$ Slightly More Suspicious |
| `event_type_File Access` | **-0.3359** | Higher $\rightarrow$ Significantly More Normal (Inlier) |
| `unique_destinations_24h` | **-0.2439** | Higher $\rightarrow$ Moderately More Normal |

---

## 9. External Dataset Recommendation
- **Current Dataset Sufficiency**: The current M1 dataset is fully sufficient for baseline unsupervised anomaly detection, model loading, and pipeline verification.
- **Labeled Benchmark Recommendation**: If stakeholders require formal supervised performance metrics (Precision, Recall, F1-Score, ROC-AUC), we recommend evaluating a standardized labeled cybersecurity dataset (such as **UNSW-NB15** or **NSL-KDD**) in a separate offline benchmark track.
- **Constraint**: External datasets should **NOT** be automatically downloaded or merged into the current M1 production telemetry pipeline.

---

## 10. Summary & Conclusion
The Isolation Forest anomaly detector demonstrates strong behavioral validity, deterministic stability, and intuitive alignment with cybersecurity risk indicators. 

Because no ground-truth binary labels exist in the dataset, supervised classification metrics were intentionally omitted to maintain scientific honesty.

---

## 11. Next Implementation Step
**`Milestone 2 — Step 5: Threat Classification, Confidence Scoring & API Integration`**
