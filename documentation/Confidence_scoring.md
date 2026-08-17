# Milestone 2 — Threat Confidence Scoring Documentation

## 1. Objective & Executive Summary
This document describes the design, scientific rationale, component weights, mathematical formulation, score calibration, and empirical validation for the **Threat Confidence Score** engine implemented for Milestone 2 — Step 6 (`backend/ml/confidence_scorer.py`).

The objective is to produce a transparent, bounded **0–100** Threat Confidence Score for every security event, synthesizing:
1. **ML Isolation Forest Anomaly Score** (Statistical isolation degree).
2. **Active Malicious Behavior Telemetry** (Failed login attempts & malware payload detection).
3. **Asset Risk & Operational Context** (CVSS vulnerability score & after-hours timing).
4. **Calibrated SOC Threat Level Alignment** (5-tier threat hierarchy).

The output dataset is persisted at `data/processed/m2_confidence_scores.csv`.

---

## 2. Scientific Definition & Clarification
To maintain scientific rigor and avoid misleading SOC analysts:

> [!IMPORTANT]
> The Threat Confidence Score is **NOT** a probability of attack, an empirical attack frequency, nor a calibrated Bayesian probability.
> 
> **Definition**: *"A bounded 0–100 evidence score representing the strength and consistency of available statistical anomaly and security telemetry indicators."*

Calling this metric a "probability of attack" would require supervised labels, empirical prevalence calibration (e.g. Platt scaling or isotonic regression), and ground-truth attack distribution assumptions that are not present in unsupervised anomaly detection.

---

## 3. Evidence Components & Normalization

The scoring engine evaluates 4 distinct, non-overlapping evidence components summing to **100% Total Weight**:

```
+-----------------------------------------------------------------------+
|                       EVIDENCE COMPONENTS (100%)                       |
+-----------------------------------+-----------------------------------+
| Component 1: ML Anomaly Evidence  | Weight: 35%                       |
| Component 2: Active Behavior      | Weight: 30%                       |
| Component 3: Asset Risk & Context | Weight: 20%                       |
| Component 4: Threat Level         | Weight: 15%                       |
+-----------------------------------+-----------------------------------+
                                    │
                                    ▼
                Base Score = ∑ (Weight_i × Score_i)
                                    │
                                    ▼
                     Bounded Final Score (0 - 100)
```

### Component 1: ML Anomaly Evidence Score ($S_{ML\_norm}$, Weight: 35%)
- **Input**: Raw Isolation Forest decision function score $S_{raw} \in [-0.10017, +0.06152]$.
- **Normalization Methodology**:
  - Decision threshold $S_{raw} = 0.0$ separates ML `Normal` ($S_{raw} \le 0$) from ML `Suspicious` ($S_{raw} > 0$).
  - For ML `Normal` events ($S_{raw} \le 0$):
    $$S_{ML\_norm} = \text{clip}\left(\left(1 + \frac{S_{raw}}{0.10}\right) \times 50, \quad 0, \quad 50\right)$$
  - For ML `Suspicious` events ($S_{raw} > 0$):
    $$S_{ML\_norm} = \text{clip}\left(50 + \left(\frac{S_{raw}}{0.06}\right) \times 50, \quad 50, \quad 100\right)$$

### Component 2: Active Malicious Behavior Score ($S_{behavior\_norm}$, Weight: 30%)
- **Input**: `failed_login_attempts` and `malware_detected`.
- **Formulation**:
  - **Failed Login Evidence**:
    - $>10$ attempts: $50\text{ pts}$ (Critical Brute Force)
    - $4 \le \text{attempts} \le 10$: $30\text{ pts}$ (Elevated Logins)
    - $1 \le \text{attempts} \le 3$: $10\text{ pts}$ (Single Failed Login)
    - $0$ attempts: $0\text{ pts}$
  - **Malware Payload Evidence**:
    - `malware_detected == Yes` or `event_type == 'Malware Detection'`: $50\text{ pts}$
    - Otherwise: $0\text{ pts}$
  - $S_{behavior\_norm} = \text{min}(100, \text{Failed Login Pts} + \text{Malware Pts})$.

### Component 3: Asset Risk & Operational Context Score ($S_{context\_norm}$, Weight: 20%)
- **Input**: `raw_cvss_score` and timestamp hour (`after_hours`).
- **Formulation**:
  - **CVSS Vulnerability Evidence**:
    - $\text{CVSS} \ge 9.0$: $70\text{ pts}$ (Critical Asset)
    - $7.0 \le \text{CVSS} < 9.0$: $50\text{ pts}$ (High Asset)
    - $4.0 \le \text{CVSS} < 7.0$: $30\text{ pts}$ (Medium Asset)
    - $\text{CVSS} < 4.0$: $0\text{ pts}$
  - **After-Hours Operational Context**:
    - Hour $< 8$ or $\ge 18$: $30\text{ pts}$
    - Standard business hours: $0\text{ pts}$
  - $S_{context\_norm} = \text{min}(100, \text{CVSS Pts} + \text{After-Hours Pts})$.

### Component 4: Calibrated SOC Threat Level Alignment Score ($S_{threat\_level\_norm}$, Weight: 15%)
- **Input**: 5-tier threat level assigned during Step 5.
- **Mapping**:
  - `Normal`: $0\text{ pts}$
  - `Low Threat`: $30\text{ pts}$
  - `Medium Threat`: $60\text{ pts}$
  - `High Threat`: $85\text{ pts}$
  - `Critical Threat`: $100\text{ pts}$

---

## 4. Scoring Formula & Bounds

$$\text{Base Confidence Score} = 0.35 \cdot S_{ML\_norm} + 0.30 \cdot S_{behavior\_norm} + 0.20 \cdot S_{context\_norm} + 0.15 \cdot S_{threat\_level\_norm}$$

### Consistency & Alignment Calibration Rules:
1. **ML Normal Baseline Soft Cap**: If `prediction == 'Normal'` and NO active attack indicators are present, the score is soft-capped at **45** to prevent routine events with passive CVSS/after-hours context from receiving artificially inflated scores.
2. **ML Suspicious Floor**: If `prediction == 'Suspicious'`, the score is floored at **50** (since Isolation Forest statistically isolated the event).
3. **Severe Active Attack Boost**: If `prediction == 'Suspicious'` AND active malware or critical brute force ($>10$ logins) is present, confidence receives a **+10** boost.

### Bounded Output:
$$\text{confidence\_score} = \text{clip}(\text{round}(\text{Adjusted Base Score}), \quad 0, \quad 100)$$

---

## 5. Dataset Validation Results

Executed across all 1,800 security events in the dataset.

### A. Statistical Summary

| Statistic | Value |
| :--- | :---: |
| **Minimum Confidence Score** | **3** |
| **Maximum Confidence Score** | **83** |
| **Mean Confidence Score** | **27.07** |
| **Median Confidence Score** | **23.00** |
| **Standard Deviation** | **15.17** |

### B. Confidence Score Distribution Buckets

| Bucket Range | Event Count | Percentage |
| :--- | :---: | :---: |
| **0 – 20** (Low Confidence Baseline) | 768 | 42.7% |
| **21 – 40** (Routine / Minor Evidence) | 678 | 37.7% |
| **41 – 60** (Moderate Evidence) | 291 | 16.2% |
| **61 – 80** (High Evidence) | 60 | 3.3% |
| **81 – 100** (Critical Evidence Concentration) | 3 | 0.2% |
| **Total** | **1,800** | **100.0%** |

### C. Threat Level × Confidence Bucket Cross-Tabulation

| Threat Level | 0–20 | 21–40 | 41–60 | 61–80 | 81–100 | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Normal** | 768 | 461 | 0 | 0 | 0 | 1,229 |
| **Low Threat** | 0 | 203 | 48 | 0 | 0 | 251 |
| **Medium Threat** | 0 | 14 | 217 | 1 | 0 | 232 |
| **High Threat** | 0 | 0 | 10 | 0 | 0 | 10 |
| **Critical Threat** | 0 | 0 | 16 | 59 | 3 | 78 |
| **Total** | **768** | **678** | **291** | **60** | **3** | **1,800** |

### D. ML Prediction × Confidence Bucket Cross-Tabulation

| ML Prediction | 0–20 | 21–40 | 41–60 | 61–80 | 81–100 | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Normal** | 768 | 678 | 263 | 1 | 0 | 1,710 |
| **Suspicious** | 0 | 0 | 28 | 59 | 3 | 90 |

---

## 6. Score Inflation Verification
- **ML-Normal events with confidence $>80$**: **0 (0.00%)**
- **ML-Suspicious events with confidence $>80$**: **3 (3.33%)**
- **ML-Suspicious events with confidence $<40$**: **0 (0.00%)**

---

## 7. Validation of Representative Events

| Event ID | ML Pred (Score) | Threat Type | Threat Level | Confidence Score | Primary Reasons |
| :--- | :--- | :--- | :--- | :---: | :--- |
| **`EVT00034`** | Suspicious (`0.061516`) | Brute Force | Critical Threat | **81 / 100** | 18 failed logins, after-hours (02:00), ML anomaly |
| **`EVT00036`** | Suspicious (`0.042562`) | Phishing | High Threat | **55 / 100** | After-hours (02:00), ML anomaly |
| **`EVT00144`** | Suspicious (`0.043279`) | Brute Force | Critical Threat | **76 / 100** | 16 failed logins, ML anomaly |
| **`EVT01233`** | Suspicious (`0.041656`) | Malware | Critical Threat | **76 / 100** | Active malware payload, after-hours (06:00), ML anomaly |
| **`EVT01600`** | Suspicious (`0.031116`) | Brute Force | Critical Threat | **73 / 100** | 20 failed logins, ML anomaly |

---

## 8. Limitations & Future Integration
- **Geolocation Data**: Geolocation impossible travel rule was excluded due to data schema limits.
- **MongoDB / FastAPI Integration**: The confidence scores are stored in `data/processed/m2_confidence_scores.csv`. FastAPI `/predict` endpoints and MongoDB collection creation are strictly deferred to future steps per project rules.
