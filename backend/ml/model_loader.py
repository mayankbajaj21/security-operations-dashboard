"""
Milestone 2 ML Model Loader & Inference Infrastructure
Project: AI-Assisted Threat Detection / Security Operations Dashboard
Milestone: Milestone 2 — Step 3B: Reusable Model-Loading Infrastructure

This module provides a unified, reusable interface for loading serialized ML artifacts
(preprocessor and Isolation Forest model) with path resolution, validation checks,
and single/batch inference execution routines.

Artifacts:
- Preprocessor: backend/models/preprocessor.pkl
- Model: backend/models/isolation_forest.pkl
"""

import sys
import logging
from pathlib import Path
from typing import Tuple, Dict, Any, Optional, Union
import pandas as pd
import numpy as np

# Ensure backend modules can be imported relative to project root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.ml.preprocessing import SecurityEventPreprocessor
from backend.ml.anomaly_detection import IsolationForestDetector

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("MLModelLoader")

# Define standard relative artifact paths
MODELS_DIR = BASE_DIR / "backend" / "models"
DEFAULT_PREPROCESSOR_PATH = MODELS_DIR / "preprocessor.pkl"
DEFAULT_MODEL_PATH = MODELS_DIR / "isolation_forest.pkl"


def load_preprocessor(filepath: Union[str, Path] = DEFAULT_PREPROCESSOR_PATH) -> SecurityEventPreprocessor:
    """
    Loads and validates the serialized SecurityEventPreprocessor artifact.
    
    Args:
        filepath (Union[str, Path]): Path to preprocessor.pkl artifact.
        
    Returns:
        SecurityEventPreprocessor: Loaded fitted preprocessor instance.
    """
    target_path = Path(filepath).resolve()
    if not target_path.exists():
        raise FileNotFoundError(
            f"Preprocessor artifact not found at: '{target_path}'. "
            "Please run 'python backend/ml/preprocessing.py' to generate the artifact."
        )

    # Ensure __main__ has class attribute for joblib pickle compatibility
    main_mod = sys.modules.get('__main__')
    if main_mod:
        if not hasattr(main_mod, 'SecurityEventPreprocessor'):
            setattr(main_mod, 'SecurityEventPreprocessor', SecurityEventPreprocessor)
        if not hasattr(main_mod, 'IsolationForestDetector'):
            setattr(main_mod, 'IsolationForestDetector', IsolationForestDetector)

    try:
        preprocessor = SecurityEventPreprocessor.load(target_path)
    except Exception as e:
        raise ValueError(f"Failed to deserialize preprocessor artifact from '{target_path}': {e}") from e

    if not getattr(preprocessor, "is_fitted", False):
        raise ValueError(f"Loaded preprocessor from '{target_path}' is not fitted.")

    logger.info(f"Preprocessor successfully loaded from: {target_path}")
    return preprocessor


def load_detector(filepath: Union[str, Path] = DEFAULT_MODEL_PATH) -> IsolationForestDetector:
    """
    Loads and validates the serialized IsolationForestDetector artifact.
    
    Args:
        filepath (Union[str, Path]): Path to isolation_forest.pkl artifact.
        
    Returns:
        IsolationForestDetector: Loaded fitted model detector instance.
    """
    target_path = Path(filepath).resolve()
    if not target_path.exists():
        raise FileNotFoundError(
            f"Isolation Forest model artifact not found at: '{target_path}'. "
            "Please run 'python backend/ml/anomaly_detection.py' to train and save the model."
        )

    try:
        detector = IsolationForestDetector.load(target_path)
    except Exception as e:
        raise ValueError(f"Failed to deserialize model artifact from '{target_path}': {e}") from e

    if not getattr(detector, "is_fitted", False):
        raise ValueError(f"Loaded Isolation Forest model from '{target_path}' is not fitted.")

    # Validate model configuration parameters
    expected_features = 29
    expected_estimators = 100
    expected_contamination = 0.05
    expected_random_state = 42

    actual_features = len(detector.feature_names_in)
    actual_estimators = detector.model.n_estimators
    actual_contamination = detector.model.contamination
    actual_random_state = detector.model.random_state

    if actual_features != expected_features:
        raise ValueError(f"Model feature count mismatch! Expected {expected_features}, got {actual_features}.")

    if actual_estimators != expected_estimators:
        raise ValueError(f"Model n_estimators mismatch! Expected {expected_estimators}, got {actual_estimators}.")

    if not np.isclose(actual_contamination, expected_contamination):
        raise ValueError(f"Model contamination mismatch! Expected {expected_contamination}, got {actual_contamination}.")

    if actual_random_state != expected_random_state:
        raise ValueError(f"Model random_state mismatch! Expected {expected_random_state}, got {actual_random_state}.")

    logger.info(f"Isolation Forest model successfully loaded and verified from: {target_path}")
    return detector


class ModelLoader:
    """
    Singleton-style container and execution pipeline for ML inference.
    Loads and caches both the preprocessor and model artifacts.
    """

    def __init__(self, preprocessor_path: Union[str, Path] = DEFAULT_PREPROCESSOR_PATH,
                 model_path: Union[str, Path] = DEFAULT_MODEL_PATH):
        self.preprocessor_path = Path(preprocessor_path).resolve()
        self.model_path = Path(model_path).resolve()
        
        self._preprocessor: Optional[SecurityEventPreprocessor] = None
        self._detector: Optional[IsolationForestDetector] = None

    def load_artifacts(self) -> None:
        """Loads both preprocessor and detector artifacts into memory."""
        self._preprocessor = load_preprocessor(self.preprocessor_path)
        self._detector = load_detector(self.model_path)
        logger.info("All ML artifacts successfully loaded and cached in memory.")

    @property
    def preprocessor(self) -> SecurityEventPreprocessor:
        if self._preprocessor is None:
            self._preprocessor = load_preprocessor(self.preprocessor_path)
        return self._preprocessor

    @property
    def detector(self) -> IsolationForestDetector:
        if self._detector is None:
            self._detector = load_detector(self.model_path)
        return self._detector

    def predict_events(self, raw_events_df: pd.DataFrame,
                       historical_context_df: Optional[pd.DataFrame] = None) -> pd.DataFrame:
        """
        Executes end-to-end inference on raw/enriched security events DataFrame.
        
        Args:
            raw_events_df (pd.DataFrame): Raw or enriched security event records to evaluate.
            historical_context_df (pd.DataFrame, optional): Full historical dataset if computing
                                                           rolling features in context.
                                                           
        Returns:
            pd.DataFrame: Contains event_id, prediction ('Normal'/'Suspicious'), and anomaly_score.
        """
        if historical_context_df is not None:
            # Merge or run full context transformation
            transformed_full = self.preprocessor.transform(historical_context_df, return_df=True)
            target_ids = set(raw_events_df['event_id'])
            feature_matrix = transformed_full[transformed_full['event_id'].isin(target_ids)].copy()
        else:
            feature_matrix = self.preprocessor.transform(raw_events_df, return_df=True)

        predictions_df = self.detector.predict(feature_matrix)
        return predictions_df


def run_smoke_test(test_event_id: str = "EVT00034") -> Dict[str, Any]:
    """
    Executes a local inference smoke test for a specific event ID.
    
    Returns:
        Dict containing smoke test execution details and consistency verification.
    """
    logger.info(f"--- Running Model Loader Inference Smoke Test (Target: {test_event_id}) ---")

    # 1. Instantiate ModelLoader and load artifacts
    loader = ModelLoader()
    loader.load_artifacts()

    # 2. Load enriched dataset and extract test event
    enriched_file = BASE_DIR / "data" / "processed" / "enriched_security_events.csv"
    if not enriched_file.exists():
        raise FileNotFoundError(f"Enriched security events CSV missing at: {enriched_file}")

    full_enriched_df = pd.read_csv(enriched_file)
    single_event_df = full_enriched_df[full_enriched_df['event_id'] == test_event_id].copy()

    if single_event_df.empty:
        raise ValueError(f"Test event ID '{test_event_id}' not found in enriched dataset.")

    # 3. Transform via preprocessor within full dataset context for exact feature parity
    transformed_df = loader.preprocessor.transform(full_enriched_df, return_df=True)
    event_feature_row = transformed_df[transformed_df['event_id'] == test_event_id].copy()

    # 4. Predict via loaded Isolation Forest
    prediction_result = loader.detector.predict(event_feature_row)
    
    pred_label = prediction_result['prediction'].values[0]
    score = float(prediction_result['anomaly_score'].values[0])

    # 5. Check consistency with pre-generated development predictions CSV
    predictions_file = BASE_DIR / "data" / "processed" / "m2_anomaly_predictions.csv"
    saved_preds_df = pd.read_csv(predictions_file)
    saved_row = saved_preds_df[saved_preds_df['event_id'] == test_event_id]
    
    saved_label = saved_row['prediction'].values[0]
    saved_score = float(saved_row['anomaly_score'].values[0])

    label_matches = (pred_label == saved_label)
    score_diff = abs(score - saved_score)

    smoke_test_summary = {
        "event_id": test_event_id,
        "input_features_count": len(loader.detector.feature_names_in),
        "prediction": pred_label,
        "anomaly_score": score,
        "saved_prediction": saved_label,
        "saved_anomaly_score": saved_score,
        "label_matches": label_matches,
        "score_difference": score_diff,
        "status": "PASSED" if label_matches and score_diff < 1e-6 else "FAILED"
    }

    return smoke_test_summary


def main() -> None:
    """CLI Entry point for model loader verification and smoke testing."""
    print("=" * 75)
    print("         MILESTONE 2 — MODEL LOADER INFRASTRUCTURE VERIFICATION")
    print("=" * 75)

    try:
        test_summary = run_smoke_test(test_event_id="EVT00034")
    except Exception as e:
        logger.error(f"Model loader verification failed: {e}")
        sys.exit(1)

    print("\n" + "=" * 75)
    print("                    MODEL LOADER SMOKE TEST REPORT")
    print("=" * 75)
    print(f" Target Event ID:              {test_summary['event_id']}")
    print(f" Model Feature Count:          {test_summary['input_features_count']} (event_id excluded)")
    print(f" Live Inference Prediction:    {test_summary['prediction']}")
    print(f" Live Anomaly Score:           {test_summary['anomaly_score']:.6f}")
    print(f" Saved Reference Prediction:   {test_summary['saved_prediction']}")
    print(f" Saved Reference Anomaly Score:{test_summary['saved_anomaly_score']:.6f}")
    print(f" Label Consistency:            {'EXACT MATCH' if test_summary['label_matches'] else 'MISMATCH'}")
    print(f" Score Difference:             {test_summary['score_difference']:.8f}")
    print(f" Verification Status:          {test_summary['status']}")
    print("=" * 75)


if __name__ == "__main__":
    main()
