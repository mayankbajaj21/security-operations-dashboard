"""
Milestone 2 ML Anomaly Detection Script
Project: AI-Assisted Threat Detection / Security Operations Dashboard
Milestone: Milestone 2 — Step 3A: Isolation Forest Anomaly Detection

This module implements the unsupervised Isolation Forest anomaly detection model using the
approved 29 ML features from data/processed/m2_feature_matrix.csv.

Outputs:
- Trained model artifact: backend/models/isolation_forest.pkl
- Development predictions CSV: data/processed/m2_anomaly_predictions.csv
"""

import sys
import logging
from pathlib import Path
from typing import Tuple, Dict, List, Optional, Union
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("MLAnomalyDetection")

# Define project path structure relative to backend/ml/anomaly_detection.py
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "backend" / "models"

INPUT_FEATURE_MATRIX_FILE = DATA_PROCESSED_DIR / "m2_feature_matrix.csv"
OUTPUT_MODEL_FILE = MODELS_DIR / "isolation_forest.pkl"
OUTPUT_PREDICTIONS_FILE = DATA_PROCESSED_DIR / "m2_anomaly_predictions.csv"


class IsolationForestDetector:
    """
    Isolation Forest Anomaly Detector for Security Event Telemetry.
    
    Unsupervised model that detects anomalous security events based on tree isolation path lengths.
    Uses 29 numerical/encoded features from the M2 feature matrix.
    
    Attributes:
        n_estimators (int): Number of isolation trees in the ensemble. Default: 100.
        contamination (float): Expected proportion of anomalies in dataset assumption (0.0 to 0.5). Default: 0.05 (5%).
        random_state (int): Random seed for deterministic reproducibility. Default: 42.
    """
    
    DEFAULT_N_ESTIMATORS = 100
    DEFAULT_CONTAMINATION = 0.05 # 5% baseline operational assumption
    DEFAULT_RANDOM_STATE = 42

    def __init__(self, n_estimators: int = DEFAULT_N_ESTIMATORS,
                 contamination: float = DEFAULT_CONTAMINATION,
                 random_state: int = DEFAULT_RANDOM_STATE):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.feature_names_in: List[str] = []
        self.is_fitted: bool = False

    def fit(self, X: pd.DataFrame) -> "IsolationForestDetector":
        """
        Fits the Isolation Forest model on the 29 numerical model features.
        
        Args:
            X (pd.DataFrame): Model feature matrix excluding event_id.
        """
        if 'event_id' in X.columns:
            raise ValueError("event_id column must be removed prior to fitting the model.")
            
        self.feature_names_in = list(X.columns)
        num_features = len(self.feature_names_in)
        
        if num_features != 29:
            logger.warning(f"Expected 29 model features, but received {num_features}.")

        logger.info(f"Training IsolationForest (n_estimators={self.n_estimators}, "
                    f"contamination={self.contamination}, random_state={self.random_state}) "
                    f"on {len(X)} events with {num_features} features...")

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.model.fit(X)
        self.is_fitted = True
        logger.info("IsolationForest training successfully completed.")
        return self

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Generates predictions and anomaly scores for the input dataset.
        
        Args:
            df (pd.DataFrame): Feature matrix containing event_id column and 29 ML features.
            
        Returns:
            pd.DataFrame: Contains event_id, prediction ('Normal'/'Suspicious'), and anomaly_score.
        """
        if not self.is_fitted or self.model is None:
            raise RuntimeError("Model must be fitted before generating predictions.")

        if 'event_id' not in df.columns:
            raise ValueError("Input DataFrame must contain 'event_id' column for traceability.")

        event_ids = df['event_id'].values
        X = df.drop(columns=['event_id'])

        # Generate raw predictions: 1 for inliers (Normal), -1 for outliers (Suspicious)
        raw_preds = self.model.predict(X)
        predictions = np.where(raw_preds == -1, 'Suspicious', 'Normal')

        # Decision function: lower values mean more anomalous
        # Inverting so HIGHER score = MORE ANOMALOUS
        dec_scores = self.model.decision_function(X)
        anomaly_scores = -dec_scores

        results_df = pd.DataFrame({
            'event_id': event_ids,
            'prediction': predictions,
            'anomaly_score': anomaly_scores
        })

        return results_df

    def fit_predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fits model and returns predictions in a single step."""
        X = df.drop(columns=['event_id']) if 'event_id' in df.columns else df.copy()
        self.fit(X)
        return self.predict(df)

    def save(self, filepath: Union[str, Path] = OUTPUT_MODEL_FILE) -> Path:
        """Serializes the fitted Isolation Forest model to disk using joblib."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save unfitted model.")

        target_path = Path(filepath)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target_path)
        logger.info(f"Saved fitted Isolation Forest detector object to: {target_path}")
        return target_path

    @classmethod
    def load(cls, filepath: Union[str, Path] = OUTPUT_MODEL_FILE) -> "IsolationForestDetector":
        """Loads a serialized IsolationForestDetector object from disk."""
        target_path = Path(filepath)
        if not target_path.exists():
            raise FileNotFoundError(f"Model artifact not found at: {target_path}")
        detector = joblib.load(target_path)
        logger.info(f"Loaded Isolation Forest detector object from: {target_path}")
        return detector


def main() -> None:
    """Main pipeline execution for Milestone 2 Step 3A Anomaly Detection."""
    print("=" * 75)
    print("      MILESTONE 2 — ISOLATION FOREST ANOMALY DETECTION TRAINING")
    print("=" * 75)

    # 1. Load Feature Matrix
    if not INPUT_FEATURE_MATRIX_FILE.exists():
        logger.error(f"Input feature matrix file missing: {INPUT_FEATURE_MATRIX_FILE}")
        sys.exit(1)

    logger.info(f"Loading M2 feature matrix from: {INPUT_FEATURE_MATRIX_FILE.relative_to(BASE_DIR)}")
    matrix_df = pd.read_csv(INPUT_FEATURE_MATRIX_FILE)
    total_events = len(matrix_df)
    logger.info(f"Feature Matrix loaded successfully. Total events: {total_events}")

    # 2. Instantiate and Train Detector
    detector = IsolationForestDetector(
        n_estimators=IsolationForestDetector.DEFAULT_N_ESTIMATORS,
        contamination=IsolationForestDetector.DEFAULT_CONTAMINATION,
        random_state=IsolationForestDetector.DEFAULT_RANDOM_STATE
    )

    predictions_df = detector.fit_predict(matrix_df)

    # 3. Save Model Artifact and Development Predictions
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    saved_model_path = detector.save(OUTPUT_MODEL_FILE)

    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    predictions_df.to_csv(OUTPUT_PREDICTIONS_FILE, index=False)
    logger.info(f"Saved development predictions CSV to: {OUTPUT_PREDICTIONS_FILE.relative_to(BASE_DIR)}")

    # 4. Statistical Calculations & Validation
    normal_count = int((predictions_df['prediction'] == 'Normal').sum())
    suspicious_count = int((predictions_df['prediction'] == 'Suspicious').sum())
    anomaly_pct = (suspicious_count / total_events) * 100.0

    scores = predictions_df['anomaly_score']
    score_min = float(scores.min())
    score_max = float(scores.max())
    score_mean = float(scores.mean())
    score_median = float(scores.median())

    # Sanity Checks
    logger.info("Executing Anomaly Detection Pipeline Validation Checks...")
    validation_passed = True

    if len(predictions_df) != 1800:
        logger.error(f"Validation Failure: Prediction count is {len(predictions_df)}, expected 1,800!")
        validation_passed = False

    if predictions_df['event_id'].nunique() != 1800:
        logger.error("Validation Failure: event_id mapping is not 1:1 unique across predictions!")
        validation_passed = False

    if scores.isnull().any():
        logger.error("Validation Failure: NaN values detected in anomaly scores!")
        validation_passed = False

    valid_labels = set(predictions_df['prediction'].unique())
    if not valid_labels.issubset({'Normal', 'Suspicious'}):
        logger.error(f"Validation Failure: Invalid prediction labels found: {valid_labels}")
        validation_passed = False

    if len(detector.feature_names_in) != 29:
        logger.error(f"Validation Failure: Model used {len(detector.feature_names_in)} features, expected 29!")
        validation_passed = False

    if suspicious_count == 0 or suspicious_count == total_events:
        logger.error(f"Validation Failure: Degenerate prediction output detected ({suspicious_count} suspicious)!")
        validation_passed = False

    # 5. Output Summary Report
    print("\n" + "=" * 75)
    print("                 ANOMALY DETECTION VALIDATION REPORT")
    print("=" * 75)
    print(f" Input Feature Matrix:           {INPUT_FEATURE_MATRIX_FILE.relative_to(BASE_DIR)}")
    print(f" Model Artifact Path:            {saved_model_path.relative_to(BASE_DIR)}")
    print(f" Development Predictions CSV:    {OUTPUT_PREDICTIONS_FILE.relative_to(BASE_DIR)}")
    print(f" Model Features Used:            {len(detector.feature_names_in)} (event_id excluded)")
    print(f" Total Security Events:          {total_events}")
    print(f" Normal Predictions:             {normal_count} ({(normal_count/total_events)*100:.1f}%)")
    print(f" Suspicious Predictions:         {suspicious_count} ({anomaly_pct:.1f}%)")
    print(f" Anomaly Score Min:              {score_min:.6f}")
    print(f" Anomaly Score Max:              {score_max:.6f}")
    print(f" Anomaly Score Mean:             {score_mean:.6f}")
    print(f" Anomaly Score Median:           {score_median:.6f}")
    print(f" Validation Status:              {'PASSED SUCCESSFUL' if validation_passed else 'FAILED'}")
    print("=" * 75)

    print("\nTop 10 Most Suspicious Events:")
    top_10 = predictions_df.sort_values('anomaly_score', ascending=False).head(10)
    print(top_10.to_string(index=False))
    print("=" * 75)


if __name__ == "__main__":
    main()
