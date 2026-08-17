"""
Milestone 2 ML Preprocessing Pipeline Script
Project: AI-Assisted Threat Detection / Security Operations Dashboard
Milestone: Milestone 2 — Anomaly Detection & ML Threat Detection Layer

This module implements the deterministic, reusable feature engineering, categorical encoding,
and scaling pipeline for security event telemetry based on the approved feature selection
specification in documentation/Feature_selection.md.

Outputs:
- Transformed feature matrix: data/processed/m2_feature_matrix.csv
- Fitted preprocessor artifact: backend/models/preprocessor.pkl
"""

import sys
import logging
from pathlib import Path
from typing import Tuple, List, Optional, Union
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.compose import ColumnTransformer

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")
logger = logging.getLogger("MLPreprocessing")

# Define project path structure relative to backend/ml/preprocessing.py
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "backend" / "models"

INPUT_ENRICHED_FILE = DATA_PROCESSED_DIR / "enriched_security_events.csv"
OUTPUT_MATRIX_FILE = DATA_PROCESSED_DIR / "m2_feature_matrix.csv"
OUTPUT_PREPROCESSOR_FILE = MODELS_DIR / "preprocessor.pkl"


class SecurityEventPreprocessor:
    """
    Reusable Preprocessor for Security Event Machine Learning Features.
    
    Transforms raw/enriched security events into a numerical model-ready feature matrix
    suitable for unsupervised anomaly detection models (e.g., Isolation Forest).
    
    Attributes:
        business_hours_start (int): Start hour for standard operational business day (0-23). Default: 8 (08:00 AM).
        business_hours_end (int): End hour for standard operational business day (0-23). Default: 18 (06:00 PM).
    """
    
    # Operational configuration assumption:
    # Business hours are defined as 08:00 to 18:00 (8 AM to 6 PM).
    # Events outside this window are flagged as after_hours_activity = 1.
    DEFAULT_BUSINESS_HOURS_START = 8
    DEFAULT_BUSINESS_HOURS_END = 18
    
    SEVERITY_MAP = {
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    
    AUTH_EVENT_TYPES = {'Failed Login', 'Login Success', 'Brute Force'}
    
    NUMERICAL_FEATURES = [
        'failed_login_attempts',
        'raw_cvss_score',
        'severity_score',
        'login_hour',
        'events_per_user_1h',
        'login_frequency_1h',
        'unique_destinations_24h'
    ]
    
    BINARY_FEATURES = [
        'malware_detected',
        'after_hours_activity',
        'vulnerability_present'
    ]
    
    CATEGORICAL_FEATURES = [
        'protocol',
        'event_type',
        'event_status'
    ]

    def __init__(self, business_hours_start: int = DEFAULT_BUSINESS_HOURS_START, 
                 business_hours_end: int = DEFAULT_BUSINESS_HOURS_END):
        self.business_hours_start = business_hours_start
        self.business_hours_end = business_hours_end
        self.column_transformer: Optional[ColumnTransformer] = None
        self.feature_names_out: List[str] = []
        self.is_fitted: bool = False

    def _derive_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Calculates all approved derived behavioral and temporal features.
        Guarantees no future temporal data leakage by executing rolling window operations
        strictly backward in time [t - window, t].
        """
        data = df.copy()
        
        # Ensure ISO timestamp parsing and chronological ordering
        if 'dt' not in data.columns:
            data['dt'] = pd.to_datetime(data['timestamp'], utc=True, errors='coerce').dt.tz_localize(None)
            
        data = data.sort_values('dt').reset_index(drop=True)
        
        # 1. login_hour
        data['login_hour'] = data['dt'].dt.hour.fillna(0).astype(int)
        
        # 2. after_hours_activity (configurable operational threshold)
        data['after_hours_activity'] = data['login_hour'].apply(
            lambda h: 1 if (h < self.business_hours_start or h >= self.business_hours_end) else 0
        )
        
        # 3. severity_score (ordinal mapping: Low->1, Medium->2, High->3, Critical->4)
        def map_severity(val):
            if pd.isna(val):
                return 1
            val_str = str(val).strip().lower()
            return self.SEVERITY_MAP.get(val_str, 1)
            
        data['severity_score'] = data['event_severity'].apply(map_severity)
        
        # 4. vulnerability_present (1 if vulnerability_id is non-null, else 0)
        data['vulnerability_present'] = data['vulnerability_id'].notnull().astype(int)
        
        # 5. malware_detected (boolean/string to binary integer 0/1)
        def map_malware(val):
            if pd.isna(val):
                return 0
            val_str = str(val).strip().lower()
            return 1 if val_str in ('yes', 'true', '1') else 0
            
        data['malware_detected'] = data['malware_detected'].apply(map_malware)
        
        # 6. Numeric conversions for direct features
        data['failed_login_attempts'] = pd.to_numeric(data['failed_login_attempts'], errors='coerce').fillna(0).astype(int)
        data['raw_cvss_score'] = pd.to_numeric(data['raw_cvss_score'], errors='coerce').fillna(0.0).astype(float)
        
        # 7. Identify authentication events for login_frequency_1h calculation
        data['is_auth_event'] = data['event_type'].astype(str).isin(self.AUTH_EVENT_TYPES)
        
        # 8. Rolling Temporal Window Behavioral Features (preventing data leakage)
        events_1h_list = []
        login_freq_1h_list = []
        unique_dests_24h_list = []
        
        # Group by username and calculate temporal window metrics
        for username, group in data.groupby('username'):
            user_times = group['dt'].values
            user_auth_times = group[group['is_auth_event']]['dt'].values
            user_dests = group['destination_ip'].values
            
            for idx, t in zip(group.index, user_times):
                t_1h_ago = t - np.timedelta64(1, 'h')
                t_24h_ago = t - np.timedelta64(24, 'h')
                
                # events_per_user_1h: count of events in [t - 1h, t] for user
                cnt_1h = np.sum((user_times >= t_1h_ago) & (user_times <= t))
                events_1h_list.append((idx, cnt_1h))
                
                # login_frequency_1h: count of auth events in [t - 1h, t] for user
                cnt_auth_1h = np.sum((user_auth_times >= t_1h_ago) & (user_auth_times <= t))
                login_freq_1h_list.append((idx, cnt_auth_1h))
                
                # unique_destinations_24h: count of distinct destination IPs in [t - 24h, t] for user
                mask_24h = (user_times >= t_24h_ago) & (user_times <= t)
                uniq_dests = len(set(user_dests[mask_24h]))
                unique_dests_24h_list.append((idx, uniq_dests))
                
        # Reassign derived metrics back in correct DataFrame index order
        data['events_per_user_1h'] = pd.Series(dict(events_1h_list), dtype=float)
        data['login_frequency_1h'] = pd.Series(dict(login_freq_1h_list), dtype=float)
        data['unique_destinations_24h'] = pd.Series(dict(unique_dests_24h_list), dtype=float)
        
        return data

    def fit(self, df: pd.DataFrame) -> "SecurityEventPreprocessor":
        """
        Fits the categorical OneHotEncoder and numerical StandardScaler on derived data.
        """
        logger.info("Deriving features for preprocessor fitting...")
        derived_df = self._derive_features(df)
        
        # Define column transformer
        self.column_transformer = ColumnTransformer(
            transformers=[
                ('num', StandardScaler(), self.NUMERICAL_FEATURES),
                ('bin', 'passthrough', self.BINARY_FEATURES),
                ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), self.CATEGORICAL_FEATURES)
            ],
            remainder='drop'
        )
        
        logger.info("Fitting ColumnTransformer (StandardScaler + OneHotEncoder)...")
        self.column_transformer.fit(derived_df)
        
        # Build deterministic output feature names
        cat_encoder = self.column_transformer.named_transformers_['cat']
        encoded_cat_names = list(cat_encoder.get_feature_names_out(self.CATEGORICAL_FEATURES))
        
        self.feature_names_out = (
            self.NUMERICAL_FEATURES + 
            self.BINARY_FEATURES + 
            encoded_cat_names
        )
        
        self.is_fitted = True
        logger.info(f"Preprocessor successfully fitted. Total model features: {len(self.feature_names_out)}")
        return self

    def transform(self, df: pd.DataFrame, return_df: bool = True) -> Union[pd.DataFrame, np.ndarray]:
        """
        Transforms raw/enriched security events into scaled/encoded feature matrix.
        
        Args:
            df (pd.DataFrame): Raw or enriched security event DataFrame.
            return_df (bool): If True, returns a pandas DataFrame with event_id as index/first column.
                              If False, returns a pure 2D NumPy feature array.
        """
        if not self.is_fitted or self.column_transformer is None:
            raise RuntimeError("SecurityEventPreprocessor must be fitted before calling transform().")
            
        derived_df = self._derive_features(df)
        event_ids = derived_df['event_id'].values
        
        # Execute transformer
        transformed_matrix = self.column_transformer.transform(derived_df)
        
        # Fill any unexpected NaN values with 0.0 for model safety
        if np.isnan(transformed_matrix).any():
            logger.warning("NaN values detected post-transformation. Imputing with 0.0.")
            transformed_matrix = np.nan_to_num(transformed_matrix, nan=0.0, posinf=0.0, neginf=0.0)
            
        if return_df:
            matrix_df = pd.DataFrame(transformed_matrix, columns=self.feature_names_out)
            matrix_df.insert(0, 'event_id', event_ids)
            return matrix_df
            
        return transformed_matrix

    def fit_transform(self, df: pd.DataFrame, return_df: bool = True) -> Union[pd.DataFrame, np.ndarray]:
        """Fits preprocessor and transforms input data in a single step."""
        return self.fit(df).transform(df, return_df=return_df)

    def save(self, filepath: Union[str, Path] = OUTPUT_PREPROCESSOR_FILE) -> Path:
        """Serializes the fitted preprocessor instance to disk using joblib."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save unfitted preprocessor.")
            
        target_path = Path(filepath)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, target_path)
        logger.info(f"Saved fitted preprocessor object to: {target_path}")
        return target_path

    @classmethod
    def load(cls, filepath: Union[str, Path] = OUTPUT_PREPROCESSOR_FILE) -> "SecurityEventPreprocessor":
        """Loads a serialized preprocessor object from disk."""
        target_path = Path(filepath)
        if not target_path.exists():
            raise FileNotFoundError(f"Preprocessor artifact not found at: {target_path}")
        preprocessor = joblib.load(target_path)
        logger.info(f"Loaded preprocessor object from: {target_path}")
        return preprocessor


def main() -> None:
    """Main pipeline execution for Milestone 2 Step 2 ML Preprocessing."""
    print("=" * 75)
    print("      MILESTONE 2 — ML PREPROCESSING PIPELINE EXECUTION")
    print("=" * 75)
    
    # 1. Load Input Data
    if not INPUT_ENRICHED_FILE.exists():
        logger.error(f"Input enriched CSV file missing: {INPUT_ENRICHED_FILE}")
        sys.exit(1)
        
    logger.info(f"Loading M1 enriched security events from: {INPUT_ENRICHED_FILE.relative_to(BASE_DIR)}")
    df_raw = pd.read_csv(INPUT_ENRICHED_FILE)
    rows_in = len(df_raw)
    logger.info(f"Input Dataset loaded successfully. Total rows: {rows_in}")
    
    # Missing values before preprocessing report
    null_counts_in = df_raw[['failed_login_attempts', 'raw_cvss_score', 'malware_detected', 
                             'event_severity', 'vulnerability_id', 'protocol', 
                             'event_type', 'event_status']].isnull().sum().to_dict()
    logger.info(f"Missing values in key fields before preprocessing: {null_counts_in}")
    
    # 2. Instantiate and Fit Preprocessor
    preprocessor = SecurityEventPreprocessor(
        business_hours_start=SecurityEventPreprocessor.DEFAULT_BUSINESS_HOURS_START,
        business_hours_end=SecurityEventPreprocessor.DEFAULT_BUSINESS_HOURS_END
    )
    
    matrix_df = preprocessor.fit_transform(df_raw, return_df=True)
    rows_out = len(matrix_df)
    
    # 3. Save Output Artifacts
    DATA_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    matrix_df.to_csv(OUTPUT_MATRIX_FILE, index=False)
    logger.info(f"Saved final ML feature matrix CSV to: {OUTPUT_MATRIX_FILE.relative_to(BASE_DIR)}")
    
    saved_prep_path = preprocessor.save(OUTPUT_PREPROCESSOR_FILE)
    
    # 4. Validation Checks
    logger.info("Executing Preprocessing Pipeline Validation Checks...")
    
    # Missing values check after preprocessing
    null_counts_out = matrix_df.isnull().sum().sum()
    
    validation_passed = True
    if rows_in != rows_out:
        logger.error(f"Validation Failure: Input row count ({rows_in}) != Output row count ({rows_out})")
        validation_passed = False
    if null_counts_out != 0:
        logger.error(f"Validation Failure: Output feature matrix contains {null_counts_out} NaN values!")
        validation_passed = False
    if 'event_id' not in matrix_df.columns:
        logger.error("Validation Failure: event_id column missing from feature matrix output!")
        validation_passed = False
    if len(matrix_df.columns) != 30: # 1 event_id + 29 feature columns
        logger.error(f"Validation Failure: Feature matrix column count is {len(matrix_df.columns)}, expected 30")
        validation_passed = False
        
    print("\n" + "=" * 75)
    print("                 ML PREPROCESSING VALIDATION REPORT")
    print("=" * 75)
    print(f" Input Data Source:              {INPUT_ENRICHED_FILE.relative_to(BASE_DIR)}")
    print(f" Input Event Count:              {rows_in}")
    print(f" Output Matrix Event Count:      {rows_out}")
    print(f" Output Matrix CSV Path:         {OUTPUT_MATRIX_FILE.relative_to(BASE_DIR)}")
    print(f" Preprocessor Artifact Path:     {saved_prep_path.relative_to(BASE_DIR)}")
    print(f" Total Feature Matrix Columns:   {len(matrix_df.columns)} (1 ID column + 29 ML features)")
    print(f" Missing Values Post-Processing: {null_counts_out}")
    print(f" Pipeline Validation Status:     {'PASSED SUCCESSFUL' if validation_passed else 'FAILED'}")
    print("=" * 75)
    
    print("\nModel Feature Columns (29):")
    feature_cols = [c for c in matrix_df.columns if c != 'event_id']
    for idx, col in enumerate(feature_cols, 1):
        print(f"  {idx:2d}. {col}")
        
    print("\nSample Feature Matrix Rows (First 3):")
    print(matrix_df[['event_id', 'failed_login_attempts', 'raw_cvss_score', 'severity_score', 
                    'events_per_user_1h', 'login_frequency_1h', 'unique_destinations_24h', 
                    'malware_detected', 'after_hours_activity', 'vulnerability_present']].head(3).to_string())
    print("\nCategorical One-Hot Sample Rows (First 3):")
    print(matrix_df[['event_id', 'protocol_HTTP', 'protocol_SSH', 'event_type_Brute Force', 
                    'event_type_Failed Login', 'event_status_Blocked', 'event_status_Success']].head(3).to_string())
    print("=" * 75)


if __name__ == "__main__":
    main()
