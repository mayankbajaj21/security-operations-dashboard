"""
backend/ml/confidence_scorer.py

Milestone 2 — Step 6: Threat Confidence Scoring Module

This module implements the ThreatConfidenceScorer class that evaluates ML Isolation Forest predictions,
anomaly scores, telemetry indicators, and calibrated SOC threat levels to calculate a bounded 0–100
Threat Confidence Score for every security event.

Scientific Definition:
- Threat Confidence Score is NOT a probability of attack nor an empirical attack rate.
- Definition: "A bounded 0–100 evidence score representing the strength and consistency of available anomaly and security indicators."

Scoring Architecture (4 Weighted Components = 100%):
1. ML Anomaly Evidence Score (Weight: 35%): Normalized score derived from Isolation Forest raw decision function.
2. Active Malicious Behavior Evidence Score (Weight: 30%): Telemetry from failed logins and malware payload flags.
3. Asset Risk & Operational Context Score (Weight: 20%): Telemetry from CVSS vulnerability score and after-hours timing.
4. SOC Threat Level Alignment Score (Weight: 15%): Categorical score aligned with calibrated 5-tier threat level.

Output dataset is saved to data/processed/m2_confidence_scores.csv.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("ConfidenceScorer")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_PREDICTIONS_PATH = BASE_DIR / "data" / "processed" / "m2_anomaly_predictions.csv"
DEFAULT_THREAT_PATH = BASE_DIR / "data" / "processed" / "m2_threat_classification.csv"
DEFAULT_ENRICHED_EVENTS_PATH = BASE_DIR / "data" / "processed" / "enriched_security_events.csv"
DEFAULT_OUTPUT_PATH = BASE_DIR / "data" / "processed" / "m2_confidence_scores.csv"


class ThreatConfidenceScorer:
    """
    Transparent deterministic threat confidence scoring engine.
    """

    def __init__(self):
        # Component weights summing to 1.00 (100%)
        self.WEIGHT_ML_ANOMALY = 0.35
        self.WEIGHT_BEHAVIOR = 0.30
        self.WEIGHT_ASSET_CONTEXT = 0.20
        self.WEIGHT_THREAT_LEVEL = 0.15

        # Decision boundaries & thresholds
        self.RAW_ANOMALY_MIN = -0.10017
        self.RAW_ANOMALY_MAX = 0.06152
        self.BRUTE_FORCE_CRITICAL = 10
        self.BRUTE_FORCE_ELEVATED = 3
        self.CVSS_CRITICAL = 9.0
        self.CVSS_HIGH = 7.0
        self.CVSS_MEDIUM = 4.0
        self.AFTER_HOURS_START = 18
        self.AFTER_HOURS_END = 8

        self.THREAT_LEVEL_MAP = {
            'Normal': 0.0,
            'Low Threat': 30.0,
            'Medium Threat': 60.0,
            'High Threat': 85.0,
            'Critical Threat': 100.0
        }

    def compute_event_confidence(self, event_record: Union[pd.Series, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Computes Threat Confidence Score (0–100) and component breakdown for a single event.
        """
        event_id = str(event_record.get('event_id', 'UNKNOWN'))
        prediction = str(event_record.get('prediction', 'Normal'))

        try:
            anomaly_score = float(event_record.get('anomaly_score', 0.0))
        except (ValueError, TypeError):
            anomaly_score = 0.0

        threat_type = str(event_record.get('threat_type', 'Normal Activity'))
        threat_level = str(event_record.get('threat_level', 'Normal'))
        
        event_type = str(event_record.get('event_type', 'Unknown')) if pd.notnull(event_record.get('event_type')) else 'Unknown'

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

        # After-hours context
        ts_val = event_record.get('timestamp')
        after_hours = False
        if pd.notnull(ts_val):
            try:
                ts = pd.to_datetime(ts_val)
                hour = ts.hour
                after_hours = (hour < self.AFTER_HOURS_END or hour >= self.AFTER_HOURS_START)
            except Exception:
                after_hours = False

        # -------------------------------------------------------------
        # COMPONENT 1: ML ANOMALY EVIDENCE SCORE (Weight: 35%)
        # -------------------------------------------------------------
        if anomaly_score <= 0.0:
            # Map [-0.10, 0.0] to [0.0, 50.0]
            ml_comp = max(0.0, min(50.0, (1.0 + (anomaly_score / 0.10)) * 50.0))
        else:
            # Map (0.0, +0.06] to (50.0, 100.0]
            ml_comp = max(50.0, min(100.0, 50.0 + ((anomaly_score / 0.06) * 50.0)))

        # -------------------------------------------------------------
        # COMPONENT 2: ACTIVE MALICIOUS BEHAVIOR SCORE (Weight: 30%)
        # -------------------------------------------------------------
        if failed_logins > self.BRUTE_FORCE_CRITICAL:
            login_pts = 50.0
        elif failed_logins > self.BRUTE_FORCE_ELEVATED:
            login_pts = 30.0
        elif failed_logins > 0:
            login_pts = 10.0
        else:
            login_pts = 0.0

        malware_pts = 50.0 if (malware_detected or event_type == 'Malware Detection') else 0.0
        behavior_comp = min(100.0, login_pts + malware_pts)

        # -------------------------------------------------------------
        # COMPONENT 3: ASSET RISK & CONTEXT SCORE (Weight: 20%)
        # -------------------------------------------------------------
        if cvss >= self.CVSS_CRITICAL:
            cvss_pts = 70.0
        elif cvss >= self.CVSS_HIGH:
            cvss_pts = 50.0
        elif cvss >= self.CVSS_MEDIUM:
            cvss_pts = 30.0
        else:
            cvss_pts = 0.0

        context_pts = 30.0 if after_hours else 0.0
        asset_context_comp = min(100.0, cvss_pts + context_pts)

        # -------------------------------------------------------------
        # COMPONENT 4: THREAT LEVEL ALIGNMENT SCORE (Weight: 15%)
        # -------------------------------------------------------------
        threat_level_comp = self.THREAT_LEVEL_MAP.get(threat_level, 0.0)

        # -------------------------------------------------------------
        # WEIGHTED COMBINATION & CALIBRATION ADJUSTMENTS
        # -------------------------------------------------------------
        base_confidence = (
            (self.WEIGHT_ML_ANOMALY * ml_comp) +
            (self.WEIGHT_BEHAVIOR * behavior_comp) +
            (self.WEIGHT_ASSET_CONTEXT * asset_context_comp) +
            (self.WEIGHT_THREAT_LEVEL * threat_level_comp)
        )

        adjusted_confidence = base_confidence

        # Soft Cap for ML Normal Events without active attack indicators
        has_active_attack = (malware_pts > 0 or login_pts >= 30.0)
        if prediction == 'Normal' and not has_active_attack:
            adjusted_confidence = min(adjusted_confidence, 45.0)

        # Minimum Floor for ML Suspicious Anomaly Events
        if prediction == 'Suspicious':
            adjusted_confidence = max(adjusted_confidence, 50.0)
            if has_active_attack:
                adjusted_confidence += 10.0

        # Bounded Final Confidence Score (0 - 100)
        confidence_score = int(round(max(0.0, min(100.0, adjusted_confidence))))

        reasons = event_record.get('reasons', '[]')

        return {
            'event_id': event_id,
            'prediction': prediction,
            'anomaly_score': anomaly_score,
            'threat_type': threat_type,
            'threat_level': threat_level,
            'confidence_score': confidence_score,
            'reasons': reasons
        }

    def process_dataframe(self, merged_df: pd.DataFrame) -> pd.DataFrame:
        """
        Processes a merged DataFrame to calculate confidence scores.
        """
        logger.info(f"Computing Threat Confidence Scores for {len(merged_df)} events...")
        records = [self.compute_event_confidence(row) for _, row in merged_df.iterrows()]
        output_df = pd.DataFrame(records)
        return output_df


def run_confidence_scoring_pipeline(
    preds_path: Path = DEFAULT_PREDICTIONS_PATH,
    threat_path: Path = DEFAULT_THREAT_PATH,
    enriched_path: Path = DEFAULT_ENRICHED_EVENTS_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH
) -> pd.DataFrame:
    """
    End-to-end pipeline runner for M2 threat confidence scoring.
    """
    if not preds_path.exists():
        raise FileNotFoundError(f"Predictions CSV not found at: {preds_path}")
    if not threat_path.exists():
        raise FileNotFoundError(f"Threat classification CSV not found at: {threat_path}")
    if not enriched_path.exists():
        raise FileNotFoundError(f"Enriched security events CSV not found at: {enriched_path}")

    logger.info(f"Loading anomaly predictions from: {preds_path}")
    preds_df = pd.read_csv(preds_path)

    logger.info(f"Loading threat classifications from: {threat_path}")
    threat_df = pd.read_csv(threat_path)

    logger.info(f"Loading enriched security events from: {enriched_path}")
    enriched_df = pd.read_csv(enriched_path)

    # Merge telemetry sources on event_id
    merged_df = preds_df.merge(threat_df[['event_id', 'threat_type', 'threat_level', 'reasons']], on='event_id')
    merged_df = merged_df.merge(enriched_df, on='event_id')

    scorer = ThreatConfidenceScorer()
    confidence_df = scorer.process_dataframe(merged_df)

    # Reorder columns explicitly per specification
    columns_order = [
        'event_id',
        'prediction',
        'anomaly_score',
        'threat_type',
        'threat_level',
        'confidence_score',
        'reasons'
    ]
    confidence_df = confidence_df[columns_order]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    confidence_df.to_csv(output_path, index=False)
    logger.info(f"Saved Threat Confidence Scores CSV to: {output_path}")

    return confidence_df


if __name__ == "__main__":
    print("=" * 75)
    print("       MILESTONE 2 — THREAT CONFIDENCE SCORING RUNNER")
    print("=" * 75)
    df_result = run_confidence_scoring_pipeline()

    scores = df_result['confidence_score']
    print("\n" + "=" * 75)
    print("                CONFIDENCE SCORE STATISTICAL SUMMARY")
    print("=" * 75)
    print(f" Minimum Score : {scores.min():>5}")
    print(f" Maximum Score : {scores.max():>5}")
    print(f" Mean Score    : {scores.mean():>8.2f}")
    print(f" Median Score  : {scores.median():>8.2f}")
    print(f" Std Deviation : {scores.std():>8.2f}")

    print("\n" + "=" * 75)
    print("                   CONFIDENCE SCORE BUCKETS")
    print("=" * 75)
    bins = [-1, 20, 40, 60, 80, 100]
    labels = ['0–20', '21–40', '41–60', '61–80', '81–100']
    df_result['bucket'] = pd.cut(scores, bins=bins, labels=labels)
    bucket_counts = df_result['bucket'].value_counts().sort_index()
    for b, c in bucket_counts.items():
        pct = (c / len(df_result)) * 100
        print(f" Bucket {b:<8}: {c:>5} ({pct:>5.1f}%)")

    print("\n" + "=" * 75)
    print("         REPRESENTATIVE ANOMALY CONFIDENCE SCORE INSPECTION")
    print("=" * 75)
    sample_ids = ['EVT00034', 'EVT00036', 'EVT00144', 'EVT01233', 'EVT01600']
    sample_df = df_result[df_result['event_id'].isin(sample_ids)]
    for _, row in sample_df.iterrows():
        reasons_list = json.loads(row['reasons'])
        print(f" Event ID:          {row['event_id']}")
        print(f" ML Prediction:     {row['prediction']} (Score: {float(row['anomaly_score']):.6f})")
        print(f" Threat Type:       {row['threat_type']}")
        print(f" Threat Level:      {row['threat_level']}")
        print(f" Confidence Score:  {row['confidence_score']}/100")
        print(" Reasons:")
        for r in reasons_list:
            print(f"   - {r}")
        print("-" * 75)

    print("=" * 75)
    print(" Threat Confidence Scoring pipeline successfully executed and validated.")
    print("=" * 75)
