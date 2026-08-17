# Milestone 2 — Threat Classification & Security Detection Rules Documentation (Calibrated)

## 1. Objective & Executive Summary
This document describes the calibrated threat classification and security detection rules engine implemented for Milestone 2 — Step 5 of the AI-Assisted Threat Detection / Security Operations Dashboard project (`backend/ml/threat_classifier.py`).

The objective is to synthesize raw Isolation Forest anomaly detection results (`Normal`/`Suspicious` predictions and continuous numerical `anomaly_score`) with transparent domain security detection rules into analyst-facing threat classifications:

```
ML Anomaly Detection (Isolation Forest)
                 +
Explicit Security Detection Rules
                 ↓
SOC Threat Classification (Threat Level + Threat Type + Explanatory Reasons)
```

---

## 2. Decoupled Concepts: Threat Type vs Threat Level vs ML Prediction

To ensure SOC analytical clarity, the engine explicitly distinguishes three decoupled dimensions:

1. **`ML Prediction`**: Describes whether the event is statistically anomalous according to the Isolation Forest model (`Normal` vs `Suspicious`).
2. **`Threat Type`**: Describes **WHAT** kind of security activity is occurring (e.g. `Brute Force`, `Malware`, `Phishing`, `SQL Injection`, `Privilege Escalation`, `Port Scan`, `Unauthorized File Access`, `USB / Removable Media`, `Authentication Anomaly`, `Normal Activity`).
3. **`Threat Level`**: Describes the **STRENGTH OF EVIDENCE** that the activity represents a threat (`Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat`).

---

## 3. Distinction Between M2 Threat Classification & M3 Risk Prioritization

| Dimension | Milestone 2: Threat Classification | Milestone 3: Risk Prioritization (Future) |
| :--- | :--- | :--- |
| **Primary Question** | *"What type of security activity is this, and how strong is the evidence of a threat?"* | *"Which overall security incident or asset requires immediate analyst triage and response first?"* |
| **Inputs** | ML Anomaly Score + Security Indicators (Failed logins, Malware, CVSS, Time of Day) | Threat Classification + Business Asset Criticality + Department Risk + Incident Context |
| **Output Taxonomy** | Analyst Threat Levels (`Normal`, `Low Threat`, `Medium Threat`, `High Threat`, `Critical Threat`) | Prioritized Risk Score (0–100) & Escalation Triage Ranks |

---

## 4. Threat-Level Taxonomy (5-Tier Analyst Hierarchy)

1. **`Normal`**: Standard operational event matching routine baseline behavior with no active attack indicators.
2. **`Low Threat`**: Minor policy deviation, isolated active attack flag on normal ML baseline, or passive vulnerability context with after-hours activity.
3. **`Medium Threat`**: ML `Suspicious` anomaly without strong supporting attack indicators OR ML `Normal` event with strong active attack indicators (`malware_detected = Yes` or `failed_login_attempts > 10`) combined with risk context.
4. **`High Threat`**: ML `Suspicious` anomaly supported by moderate attack indicators OR ML `Normal` baseline with multiple independent strong active attack flags.
5. **`Critical Threat`**: Severe security threat requiring immediate intervention (e.g. ML `Suspicious` anomaly backed by active malware, excessive brute force $>10$ failed logins, or critical CVSS context).

---

## 5. Threat Type Taxonomy

Categorized based on telemetry taxonomy, security rule flags, and log metadata:

- **`Brute Force`**: Excessive or elevated failed login attempts (`failed_login_attempts > 3` or `event_type == 'Brute Force'`).
- **`Malware`**: Active malware payload or malicious signature (`malware_detected == Yes` or `event_type == 'Malware Detection'`).
- **`Phishing`**: Email payload or credential harvest attempt (`event_type == 'Phishing Email'`).
- **`SQL Injection`**: Database injection attack telemetry (`event_type == 'Sql Injection Attempt'`).
- **`Privilege Escalation`**: Unauthorized permission escalation (`event_type == 'Privilege Escalation'`).
- **`Port Scan`**: Network reconnaissance scan (`event_type == 'Port Scan'`).
- **`Unauthorized File Access`**: Sensitive file access with `Failed`/`Blocked` status or `after_hours`.
- **`File Access`**: Routine authorized file access.
- **`USB / Removable Media`**: Removable media connection events (`event_type == 'Usb Device Connected'`).
- **`Authentication Anomaly`**: Anomalous login success flagged by Isolation Forest.
- **`Other Suspicious Activity`**: Uncategorized ML anomaly.
- **`Normal Activity`**: Routine baseline telemetry.

---

## 6. Explicit Security Detection Rules & Calibration Rationale

The engine evaluates transparent security rules based on domain indicators:

1. **Active Attack Indicator 1 — Malware Detection**: `malware_detected == Yes` or `event_type == 'Malware Detection'`.
2. **Active Attack Indicator 2 — Critical Brute Force**: `failed_login_attempts > 10`.
3. **Active Attack Indicator 3 — Elevated Failed Logins**: `3 < failed_login_attempts <= 10`.
4. **Passive Vulnerability Indicator — Critical CVSS**: `raw_cvss_score >= 9.0` (Treated as asset vulnerability state context, NOT an active attack flag alone).
5. **Passive Vulnerability Indicator — High CVSS**: `7.0 <= raw_cvss_score < 9.0`.
6. **Contextual Indicator — After-Hours Activity**: Hour $< 8$ or $\ge 18$.
7. **Impossible Travel**: *Explicitly NOT implemented* because the M1 telemetry dataset lacks location coordinates.

### Calibration Rationale:
In the initial uncalibrated model, 461 ML-Normal events were escalated to `Medium Threat` due to a single `raw_cvss_score >= 9.0` rule. Under calibration:
- `raw_cvss_score >= 9.0` represents a passive asset vulnerability state (e.g. an unpatched web server). On its own, during routine ML-Normal activity without malware or brute force, it does NOT indicate an active threat.
- Therefore, passive CVSS scores alone on an ML Normal baseline remain **`Threat Level: Normal`**, preventing massive alert inflation while preserving visibility.

---

## 7. Hybrid Decision Logic & Precedence Model

The classifier follows a deterministic precedence model:

### Scenario A: ML Isolation Forest Prediction is `Suspicious` (Primary Signal)
- **`Critical Threat`**: Triggered if ML prediction is `Suspicious` AND $\ge 1$ Active Attack Flag (`MALWARE` or `CRITICAL_BRUTE_FORCE`), OR (`CRITICAL_CVSS` + `AFTER_HOURS`), OR `event_severity == Critical`.
- **`High Threat`**: Triggered if ML prediction is `Suspicious` AND $\ge 1$ Moderate/Passive Flag (`ELEVATED_FAILED_LOGINS`, `CRITICAL_CVSS`, `AFTER_HOURS`, or high-risk threat types).
- **`Medium Threat`**: Triggered if ML prediction is `Suspicious` without additional active attack indicators (isolated ML anomaly).

### Scenario B: ML Isolation Forest Prediction is `Normal` (Routine Baseline)
- **`High Threat`**: Escalated ONLY if $\ge 2$ Independent Active Attack Indicators trigger simultaneously (`MALWARE` + `CRITICAL_BRUTE_FORCE`).
- **`Medium Threat`**: Escalated if a Strong Active Attack Indicator (`MALWARE` or `CRITICAL_BRUTE_FORCE`) is present AND combined with risk context (`CRITICAL_CVSS` or `AFTER_HOURS`).
- **`Low Threat`**: Minor escalation if an isolated Strong Active Attack Indicator is present alone, OR `ELEVATED_FAILED_LOGINS` (4–10 attempts), OR (`CRITICAL_CVSS` + `AFTER_HOURS` + `event_severity == Critical`).
- **`Normal`**: Maintained if no active attack indicators are present.

---

## 8. Machine-Readable Explanation Data (XAI Preparation)

Each classification output includes a `reasons` field containing a JSON array of explanatory strings:

**Example (`EVT00034`)**:
```json
[
  "Excessive failed login attempts (18 attempts exceeded threshold of 10)",
  "Activity occurred outside standard operational hours (02:00)",
  "Isolation Forest flagged event as anomalous (score: 0.061516)"
]
```

---

## 9. Calibrated Dataset Validation Results

The threat classification engine was executed across all 1,800 events in `data/processed/enriched_security_events.csv`.

### A. Previous vs New Threat-Level Distribution

| Threat Level | Previous (Uncalibrated) | New (Calibrated) | Calibrated % |
| :--- | :---: | :---: | :---: |
| **Normal** | 1,055 | **1,229** | **68.3%** |
| **Low Threat** | 161 | **251** | **13.9%** |
| **Medium Threat** | 466 | **232** | **12.9%** |
| **Critical Threat** | 73 | **78** | **4.3%** |
| **High Threat** | 45 | **10** | **0.6%** |
| **Total** | **1,800** | **1,800** | **100.0%** |

### B. Previous vs New ML Prediction × Threat-Level Cross-Tabulation

#### Previous (Uncalibrated Cross-Tab):
| ML Prediction | Critical Threat | High Threat | Medium Threat | Low Threat | Normal | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Normal** | 0 | 33 | 461 | 161 | 1,055 | 1,710 |
| **Suspicious** | 73 | 12 | 5 | 0 | 0 | 90 |

#### New (Calibrated Cross-Tab):
| ML Prediction | Critical Threat | High Threat | Medium Threat | Low Threat | Normal | Total |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Normal** | 0 | 0 | 230 | 251 | **1,229** | 1,710 |
| **Suspicious** | 78 | 10 | 2 | 0 | 0 | 90 |

### Key Improvements:
- **ML Normal Events Escalated Above Normal**: Reduced from 655 (38.3%) to 481 (28.13%).
- **ML Normal Events Remaining Normal**: Increased from 1,055 (61.7%) to 1,229 (71.87%).
- **ML Normal Events Escalated to High Threat**: Reduced from 33 to **0**.
- **ML Suspicious Events Classified below High**: Only **2** (classified as Medium Threat due to isolated anomaly during routine activity).

---

## 10. Representative Examples Validation

1. **`EVT00034`**: ML `Suspicious` (Score `0.061516`) $\rightarrow$ **Threat Type: `Brute Force` | Threat Level: `Critical Threat`**
   - *Reasons*: 18 failed login attempts exceeded threshold, after-hours (02:00), Isolation Forest ML anomaly.
2. **`EVT00144`**: ML `Suspicious` (Score `0.043279`) $\rightarrow$ **Threat Type: `Brute Force` | Threat Level: `Critical Threat`**
   - *Reasons*: 16 failed login attempts exceeded threshold, Isolation Forest ML anomaly.
3. **`EVT00036`**: ML `Suspicious` (Score `0.042562`) $\rightarrow$ **Threat Type: `Phishing` | Threat Level: `High Threat`**
   - *Reasons*: Phishing email telemetry, after-hours (02:00), Isolation Forest ML anomaly.
4. **`EVT01233`**: ML `Suspicious` (Score `0.041656`) $\rightarrow$ **Threat Type: `Malware` | Threat Level: `Critical Threat`**
   - *Reasons*: Active malware payload, after-hours (06:00), Isolation Forest ML anomaly.
5. **`EVT01600`**: ML `Suspicious` (Score `0.031116`) $\rightarrow$ **Threat Type: `Brute Force` | Threat Level: `Critical Threat`**
   - *Reasons*: 20 failed login attempts exceeded threshold, Isolation Forest ML anomaly.

---

## 11. Limitations & Sanity Checks
- **No Confidence Score**: Threat confidence scores are strictly deferred to Milestone 2 — Step 6.
- **Data Boundaries**: Geolocation impossible travel rule remains excluded due to data schema limits.
- **Storage**: Output dataset is persisted to `data/processed/m2_threat_classification.csv`. MongoDB and FastAPI routes remain untouched.

---

## 12. Next Implementation Step
**`Milestone 2 — Step 6: Threat Confidence Scoring`** (Calculating bounded 0–100% confidence scores combining ML decision function scores and rule weightings).
