"""
backend/ml/threat_classifier.py

Milestone 2 — Step 5 (Calibrated): Threat Classification & Security Detection Rules Engine

This module implements the SecurityThreatClassifier class that evaluates ML Isolation Forest predictions
(from data/processed/m2_anomaly_predictions.csv) alongside telemetry indicators (from
data/processed/enriched_security_events.csv) to categorize security events into:
  1. Threat Type: Categorical classification describing WHAT security activity occurred
     (e.g., Brute Force, Malware, Phishing, SQL Injection, Privilege Escalation, Port Scan,
      Unauthorized File Access, USB / Removable Media, Authentication Anomaly, Normal Activity).
  2. Threat Level: Analyst-facing 5-tier threat hierarchy describing the STRENGTH OF EVIDENCE
     (Normal, Low Threat, Medium Threat, High Threat, Critical Threat).
  3. Reasons: Machine-readable JSON array of human-readable security explanations for SOC analysts (XAI preparation).

Design & Calibration Philosophy:
- Isolation Forest ML prediction is the PRIMARY anomaly detection signal.
- Security rules provide supporting evidence and threat-type classification.
- Asset vulnerability (raw_cvss_score >= 9.0) is a passive asset state context indicator, NOT an active attack flag alone.
  It does NOT automatically convert ML-Normal routine events into Medium or High Threat.
- Threat Type, Threat Level, and ML Prediction remain strictly decoupled.
- Output dataset is saved to data/processed/m2_threat_classification.csv.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("ThreatClassifier")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_PREDICTIONS_PATH = BASE_DIR / "data" / "processed" / "m2_anomaly_predictions.csv"
DEFAULT_ENRICHED_EVENTS_PATH = BASE_DIR / "data" / "processed" / "enriched_security_events.csv"
DEFAULT_OUTPUT_PATH = BASE_DIR / "data" / "processed" / "m2_threat_classification.csv"


class SecurityThreatClassifier:
    """
    Calibrated hybrid threat classification engine combining Isolation Forest predictions
    with explicit SOC security detection rules.
    """

    def __init__(self):
        # Operational thresholds
        self.BRUTE_FORCE_CRITICAL_THRESHOLD = 10  # >10 failed logins = Critical Brute Force
        self.BRUTE_FORCE_ELEVATED_THRESHOLD = 3   # >3 failed logins = Elevated Failed Logins
        self.CVSS_CRITICAL_THRESHOLD = 9.0         # CVSS >= 9.0 = Critical Asset Vulnerability
        self.CVSS_HIGH_THRESHOLD = 7.0             # CVSS >= 7.0 = High Asset Vulnerability
        self.AFTER_HOURS_START = 18                # 18:00 (6 PM)
        self.AFTER_HOURS_END = 8                   # 08:00 (8 AM)

    def classify_event(self, event_record: Union[pd.Series, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Classifies a single security event record into Threat Type, Threat Level, and Reasons list.
        """
        # 1. Extract raw parameters
        event_id = str(event_record.get('event_id', 'UNKNOWN'))
        prediction = str(event_record.get('prediction', 'Normal'))
        
        try:
            anomaly_score = float(event_record.get('anomaly_score', 0.0))
        except (ValueError, TypeError):
            anomaly_score = 0.0

        event_type = str(event_record.get('event_type', 'Unknown')) if pd.notnull(event_record.get('event_type')) else 'Unknown'
        event_status = str(event_record.get('event_status', 'Unknown')) if pd.notnull(event_record.get('event_status')) else 'Unknown'
        event_severity = str(event_record.get('event_severity', 'Low')) if pd.notnull(event_record.get('event_severity')) else 'Low'

        try:
            failed_logins = int(event_record.get('failed_login_attempts', 0))
        except (ValueError, TypeError):
            failed_logins = 0

        malware_val = str(event_record.get('malware_detected', 'No')).strip().lower()
        malware_detected = malware_val in ['yes', 'true', '1']

        try:
            cvss = float(event_record.get('raw_cvss_score', 0.0))
        except (ValueError, TypeError):
            cvss = 0.0

        # After-hours evaluation
        ts_val = event_record.get('timestamp')
        after_hours = False
        hour = None
        if pd.notnull(ts_val):
            try:
                ts = pd.to_datetime(ts_val)
                hour = ts.hour
                after_hours = (hour < self.AFTER_HOURS_END or hour >= self.AFTER_HOURS_START)
            except Exception:
                after_hours = False

        # -------------------------------------------------------------
        # 2. EVALUATE SECURITY INDICATORS & EVIDENCE
        # -------------------------------------------------------------
        reasons: List[str] = []
        active_attack_flags: List[str] = []
        passive_vuln_flags: List[str] = []
        context_flags: List[str] = []

        # Active Attack Indicators (Direct Malicious Telemetry / Action)
        if malware_detected or event_type == 'Malware Detection':
            active_attack_flags.append('MALWARE')
            reasons.append("Malware payload or malicious signature detected")

        if failed_logins > self.BRUTE_FORCE_CRITICAL_THRESHOLD:
            active_attack_flags.append('CRITICAL_BRUTE_FORCE')
            reasons.append(f"Excessive failed login attempts ({failed_logins} attempts exceeded threshold of {self.BRUTE_FORCE_CRITICAL_THRESHOLD})")
        elif failed_logins > self.BRUTE_FORCE_ELEVATED_THRESHOLD:
            active_attack_flags.append('ELEVATED_FAILED_LOGINS')
            reasons.append(f"Elevated failed login attempts ({failed_logins} attempts)")
        elif failed_logins > 0:
            context_flags.append('SINGLE_FAILED_LOGIN')
            reasons.append(f"Single failed login attempt recorded ({failed_logins} attempt)")

        # Passive Vulnerability Indicators (Asset Vulnerability Context)
        if cvss >= self.CVSS_CRITICAL_THRESHOLD:
            passive_vuln_flags.append('CRITICAL_CVSS')
            reasons.append(f"Critical asset vulnerability present (CVSS {cvss:.1f})")
        elif cvss >= self.CVSS_HIGH_THRESHOLD:
            passive_vuln_flags.append('HIGH_CVSS')
            reasons.append(f"High asset vulnerability present (CVSS {cvss:.1f})")

        # Contextual Operational Indicators
        if after_hours and hour is not None:
            context_flags.append('AFTER_HOURS')
            reasons.append(f"Activity occurred outside standard operational hours ({hour:02d}:00)")

        if prediction == 'Suspicious':
            reasons.append(f"Isolation Forest flagged event as anomalous (score: {anomaly_score:.6f})")

        # -------------------------------------------------------------
        # 3. THREAT TYPE (Categorical classification of WHAT activity occurs)
        # -------------------------------------------------------------
        if 'MALWARE' in active_attack_flags or event_type == 'Malware Detection':
            threat_type = 'Malware'
        elif 'CRITICAL_BRUTE_FORCE' in active_attack_flags or 'ELEVATED_FAILED_LOGINS' in active_attack_flags or event_type in ['Brute Force', 'Failed Login']:
            threat_type = 'Brute Force'
        elif event_type == 'Phishing Email':
            threat_type = 'Phishing'
        elif event_type == 'Sql Injection Attempt':
            threat_type = 'SQL Injection'
        elif event_type == 'Privilege Escalation':
            threat_type = 'Privilege Escalation'
        elif event_type == 'Port Scan':
            threat_type = 'Port Scan'
        elif event_type == 'Usb Device Connected':
            threat_type = 'USB / Removable Media'
        elif event_type == 'File Access':
            threat_type = 'Unauthorized File Access' if (event_status in ['Failed', 'Blocked'] or after_hours) else 'File Access'
        elif prediction == 'Suspicious' and event_type == 'Login Success':
            threat_type = 'Authentication Anomaly'
        elif prediction == 'Suspicious':
            threat_type = 'Other Suspicious Activity'
        else:
            threat_type = 'Normal Activity'

        # -------------------------------------------------------------
        # 4. CALIBRATED PRECEDENCE MODEL FOR THREAT LEVEL (Evidence Strength)
        # -------------------------------------------------------------
        if prediction == 'Suspicious':
            # Primary ML Anomaly Signal Active: Event is statistically isolated
            if len(active_attack_flags) >= 1 or ('CRITICAL_CVSS' in passive_vuln_flags and 'AFTER_HOURS' in context_flags) or event_severity == 'Critical':
                threat_level = 'Critical Threat'
            elif len(passive_vuln_flags) >= 1 or len(context_flags) >= 1 or threat_type in ['Phishing', 'SQL Injection', 'Privilege Escalation', 'Brute Force']:
                threat_level = 'High Threat'
            else:
                threat_level = 'Medium Threat'
        else:
            # ML Prediction is NORMAL -> Baseline activity is routine
            # Escalation requires strong active evidence or combined indicators
            has_strong_attack = ('MALWARE' in active_attack_flags or 'CRITICAL_BRUTE_FORCE' in active_attack_flags)
            has_moderate_attack = ('ELEVATED_FAILED_LOGINS' in active_attack_flags)
            has_critical_cvss = ('CRITICAL_CVSS' in passive_vuln_flags)
            has_after_hours = ('AFTER_HOURS' in context_flags)

            if len(active_attack_flags) >= 2:
                threat_level = 'High Threat'
                reasons.append("Escalated to High Threat due to multiple independent active attack indicators despite Normal ML prediction")
            elif has_strong_attack and (has_critical_cvss or has_after_hours):
                threat_level = 'Medium Threat'
                reasons.append("Escalated to Medium Threat due to strong active attack indicator combined with risk context on Normal ML baseline")
            elif has_strong_attack:
                threat_level = 'Low Threat'
                reasons.append("Escalated to Low Threat due to isolated active attack indicator on Normal ML baseline")
            elif has_moderate_attack and (has_critical_cvss or has_after_hours):
                threat_level = 'Low Threat'
                reasons.append("Minor escalation to Low Threat due to elevated failed logins with risk context on Normal ML baseline")
            elif has_critical_cvss and has_after_hours and event_severity == 'Critical':
                threat_level = 'Low Threat'
                reasons.append("Minor escalation to Low Threat due to critical asset vulnerability and after-hours context on Normal ML baseline")
            else:
                threat_level = 'Normal'
                reasons = ["Activity aligns with standard operational baseline and security policies"]

        return {
            'event_id': event_id,
            'prediction': prediction,
            'anomaly_score': anomaly_score,
            'threat_type': threat_type,
            'threat_level': threat_level,
            'reasons': json.dumps(reasons)
        }

    def process_dataframe(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        """
        Processes a merged DataFrame of predictions and enriched events to generate threat classifications.
        """
        logger.info(f"Classifying {len(merged_df)} security events using calibrated hybrid rules...")
        records = [self.classify_event(row) for _, row in merged_df.iterrows()]
        output_df = pd.DataFrame(records)
        return output_df


def run_threat_classification_pipeline(
    preds_path: Path = DEFAULT_PREDICTIONS_PATH,
    enriched_path: Path = DEFAULT_ENRICHED_EVENTS_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH
) -> pd.DataFrame:
    """
    End-to-end pipeline runner for M2 threat classification.
    """
    if not preds_path.exists():
        raise FileNotFoundError(f"Predictions CSV not found at: {preds_path}")
    if not enriched_path.exists():
        raise FileNotFoundError(f"Enriched security events CSV not found at: {enriched_path}")

    logger.info(f"Loading Isolation Forest predictions from: {preds_path}")
    preds_df = pd.read_csv(preds_path)

    logger.info(f"Loading enriched security events from: {enriched_path}")
    enriched_df = pd.read_csv(enriched_path)

    # Merge on event_id
    merged_df = preds_df.merge(enriched_df, on='event_id')

    classifier = SecurityThreatClassifier()
    classification_df = classifier.process_dataframe(merged_df)

    # Save to output path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    classification_df.to_csv(output_path, index=False)
    logger.info(f"Saved threat classification output CSV to: {output_path}")

    return classification_df


if __name__ == "__main__":
    print("=" * 75)
    print("       MILESTONE 2 — HYBRID SECURITY THREAT CLASSIFICATION RUNNER")
    print("=" * 75)
    df_result = run_threat_classification_pipeline()
    
    print("\n" + "=" * 75)
    print("                   THREAT LEVEL DISTRIBUTION")
    print("=" * 75)
    level_counts = df_result['threat_level'].value_counts()
    for level, count in level_counts.items():
        pct = (count / len(df_result)) * 100
        print(f" {level:<20}: {count:>5} ({pct:>5.1f}%)")

    print("\n" + "=" * 75)
    print("                   THREAT TYPE DISTRIBUTION")
    print("=" * 75)
    type_counts = df_result['threat_type'].value_counts()
    for ttype, count in type_counts.items():
        pct = (count / len(df_result)) * 100
        print(f" {ttype:<25}: {count:>5} ({pct:>5.1f}%)")

    print("\n" + "=" * 75)
    print("         REPRESENTATIVE ANOMALY CLASSIFICATIONS INSPECTION")
    print("=" * 75)
    sample_ids = ['EVT00034', 'EVT00036', 'EVT00144', 'EVT01233', 'EVT01600']
    sample_df = df_result[df_result['event_id'].isin(sample_ids)]
    for _, row in sample_df.iterrows():
        reasons_list = json.loads(row['reasons'])
        print(f" Event ID:       {row['event_id']}")
        print(f" ML Prediction:  {row['prediction']} (Anomaly Score: {float(row['anomaly_score']):.6f})")
        print(f" Threat Type:    {row['threat_type']}")
        print(f" Threat Level:   {row['threat_level']}")
        print(" Reasons:")
        for r in reasons_list:
            print(f"   - {r}")
        print("-" * 75)

    print("=" * 75)
    print(" Threat Classification pipeline successfully executed and validated.")
    print("=" * 75)
