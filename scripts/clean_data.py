"""
Data Cleaning and Validation Pipeline Script
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

This script validates schemas, handles duplicates, standardizes datatypes/casing,
and exports cleaned versions of the six raw security datasets to data/processed/.

Raw data files in data/raw/ are immutable and left untouched.
"""

from pathlib import Path
import re
import sys
import pandas as pd


# Define project root directory
BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

# Expected Raw Dataset Schemas (from documentation/data_dictionary.md)
EXPECTED_SCHEMAS = {
    "security_events.csv": [
        "event_id", "timestamp", "source_ip", "destination_ip", "username",
        "event_type", "protocol", "source_country", "destination_country",
        "device_name", "os", "event_status", "severity", "failed_login_attempts",
        "malware_detected", "vulnerability_id", "cvss_score", "asset_name", "department"
    ],
    "threat_intelligence.csv": [
        "indicator_id", "indicator_type", "indicator_value", "threat_name",
        "threat_actor", "confidence", "severity"
    ],
    "vulnerabilities.csv": [
        "vulnerability_id", "cve_id", "vulnerability_name", "severity",
        "cvss_score", "affected_asset", "patch_available", "status"
    ],
    "mitre_attack_mapping.csv": [
        "event_type", "mitre_id", "technique_name", "tactic"
    ],
    "incident_history.csv": [
        "incident_id", "event_id", "incident_type", "assigned_to",
        "status", "response_time", "resolution"
    ],
    "assets.csv": [
        "asset_id", "asset_name", "asset_type", "owner",
        "department", "criticality", "operating_system"
    ]
}


def load_raw_datasets() -> dict[str, pd.DataFrame]:
    """
    Loads all six raw CSV files from data/raw/ into Pandas DataFrames.
    Raises FileNotFoundError if any required CSV file is missing.
    """
    datasets = {}
    for filename in EXPECTED_SCHEMAS:
        filepath = RAW_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Required raw dataset missing: {filepath}")
        datasets[filename] = pd.read_csv(filepath)
    return datasets


def validate_schema(filename: str, df: pd.DataFrame) -> None:
    """
    Validates that a DataFrame contains all expected columns.
    Raises ValueError detailing missing columns if validation fails.
    """
    expected_cols = set(EXPECTED_SCHEMAS[filename])
    actual_cols = set(df.columns)
    missing_cols = expected_cols - actual_cols
    
    if missing_cols:
        raise ValueError(
            f"Schema validation failed for dataset '{filename}'. "
            f"Missing required columns: {sorted(list(missing_cols))}"
        )


def remove_duplicates(filename: str, df: pd.DataFrame) -> tuple[pd.DataFrame, int, int, int]:
    """
    Checks and removes exact duplicate rows from a DataFrame.
    Returns (cleaned_df, rows_before, rows_after, dupes_removed).
    """
    rows_before = len(df)
    dupes_removed = int(df.duplicated().sum())
    cleaned_df = df.drop_duplicates().copy()
    rows_after = len(cleaned_df)
    return cleaned_df, rows_before, rows_after, dupes_removed


def clean_string_series(series: pd.Series, title_case: bool = False, upper_case: bool = False) -> pd.Series:
    """
    Strips leading/trailing whitespace and normalizes string casing.
    Preserves null / NA values.
    """
    s = series.astype(str).str.strip()
    # Restore actual NaNs that get turned into 'nan' strings
    mask_null = series.isnull() | (s.str.lower() == "nan") | (s == "")
    
    if upper_case:
        s = s.str.upper()
    elif title_case:
        s = s.str.title()
        
    s[mask_null] = None
    return s


def clean_security_events(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans security_events.csv dataframe:
    - Normalizes string whitespace and casing
    - Converts timestamp to Pandas datetime format
    - Ensures numeric types for failed_login_attempts and cvss_score
    - Standardizes malware_detected to Yes/No
    - Preserves nullable vulnerability_id
    """
    df = df.copy()
    
    df["event_id"] = clean_string_series(df["event_id"])
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    df["source_ip"] = clean_string_series(df["source_ip"])
    df["destination_ip"] = clean_string_series(df["destination_ip"])
    df["username"] = clean_string_series(df["username"])
    df["event_type"] = clean_string_series(df["event_type"], title_case=True)
    df["protocol"] = clean_string_series(df["protocol"], upper_case=True)
    df["source_country"] = clean_string_series(df["source_country"], title_case=True)
    df["destination_country"] = clean_string_series(df["destination_country"], title_case=True)
    df["device_name"] = clean_string_series(df["device_name"])
    df["os"] = clean_string_series(df["os"])
    df["event_status"] = clean_string_series(df["event_status"], title_case=True)
    df["severity"] = clean_string_series(df["severity"], title_case=True)
    
    df["failed_login_attempts"] = pd.to_numeric(df["failed_login_attempts"], errors="coerce").fillna(0).astype(int)
    
    # Standardize malware_detected to Yes/No
    malware_clean = clean_string_series(df["malware_detected"], title_case=True)
    df["malware_detected"] = malware_clean.map({"True": "Yes", "False": "No", "1": "Yes", "0": "No"}).fillna(malware_clean)
    
    # vulnerability_id stays nullable string
    df["vulnerability_id"] = clean_string_series(df["vulnerability_id"])
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["asset_name"] = clean_string_series(df["asset_name"])
    df["department"] = clean_string_series(df["department"])
    
    return df


def clean_threat_intelligence(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans threat_intelligence.csv dataframe:
    - Strips whitespace and standardizes categorical fields
    - Preserves indicator_value IP format exactly
    """
    df = df.copy()
    df["indicator_id"] = clean_string_series(df["indicator_id"])
    df["indicator_type"] = clean_string_series(df["indicator_type"])
    df["indicator_value"] = clean_string_series(df["indicator_value"])
    df["threat_name"] = clean_string_series(df["threat_name"], title_case=True)
    df["threat_actor"] = clean_string_series(df["threat_actor"])
    df["confidence"] = clean_string_series(df["confidence"], title_case=True)
    df["severity"] = clean_string_series(df["severity"], title_case=True)
    return df


def clean_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans vulnerabilities.csv dataframe:
    - Normalizes strings, severity, patch_available, and status
    - Validates numeric cvss_score
    """
    df = df.copy()
    df["vulnerability_id"] = clean_string_series(df["vulnerability_id"])
    df["cve_id"] = clean_string_series(df["cve_id"])
    df["vulnerability_name"] = clean_string_series(df["vulnerability_name"])
    df["severity"] = clean_string_series(df["severity"], title_case=True)
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["affected_asset"] = clean_string_series(df["affected_asset"])
    df["patch_available"] = clean_string_series(df["patch_available"], title_case=True)
    df["status"] = clean_string_series(df["status"], title_case=True)
    return df


def clean_mitre_attack_mapping(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans mitre_attack_mapping.csv dataframe:
    - Trims whitespace and normalizes event_type, technique_name, tactic
    - Preserves mitre_id
    """
    df = df.copy()
    df["event_type"] = clean_string_series(df["event_type"], title_case=True)
    df["mitre_id"] = clean_string_series(df["mitre_id"], upper_case=True)
    df["technique_name"] = clean_string_series(df["technique_name"], title_case=True)
    df["tactic"] = clean_string_series(df["tactic"], title_case=True)
    return df


def parse_response_time_minutes(val: str) -> float | None:
    """
    Parses a string duration such as '15 min' or '1.5 hours' into numeric minutes.
    Returns None if value is missing or unparseable.
    """
    if pd.isna(val) or not str(val).strip():
        return None
    val_str = str(val).strip().lower()
    
    # Match number in string
    match = re.search(r"(\d+(?:\.\d+)?)", val_str)
    if not match:
        return None
    
    number = float(match.group(1))
    if "hour" in val_str or "hr" in val_str:
        return number * 60.0
    return number


def clean_incident_history(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans incident_history.csv dataframe:
    - Trims whitespace and normalizes categorical strings
    - Preserves original response_time text column for traceability
    - Adds parsed numeric response_time_minutes column
    """
    df = df.copy()
    df["incident_id"] = clean_string_series(df["incident_id"])
    df["event_id"] = clean_string_series(df["event_id"])
    df["incident_type"] = clean_string_series(df["incident_type"], title_case=True)
    df["assigned_to"] = clean_string_series(df["assigned_to"])
    df["status"] = clean_string_series(df["status"], title_case=True)
    df["response_time"] = clean_string_series(df["response_time"])
    df["resolution"] = clean_string_series(df["resolution"])
    
    # Create derived numeric response_time_minutes while keeping original response_time
    df["response_time_minutes"] = df["response_time"].apply(parse_response_time_minutes)
    
    return df


def clean_assets(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans assets.csv dataframe:
    - Trims whitespace and normalizes text fields
    """
    df = df.copy()
    df["asset_id"] = clean_string_series(df["asset_id"])
    df["asset_name"] = clean_string_series(df["asset_name"])
    df["asset_type"] = clean_string_series(df["asset_type"], title_case=True)
    df["owner"] = clean_string_series(df["owner"], title_case=True)
    df["department"] = clean_string_series(df["department"])
    df["criticality"] = clean_string_series(df["criticality"], title_case=True)
    df["operating_system"] = clean_string_series(df["operating_system"])
    return df


CLEANING_DISPATCH = {
    "security_events.csv": clean_security_events,
    "threat_intelligence.csv": clean_threat_intelligence,
    "vulnerabilities.csv": clean_vulnerabilities,
    "mitre_attack_mapping.csv": clean_mitre_attack_mapping,
    "incident_history.csv": clean_incident_history,
    "assets.csv": clean_assets,
}

OUTPUT_FILENAMES = {
    "security_events.csv": "cleaned_security_events.csv",
    "threat_intelligence.csv": "cleaned_threat_intelligence.csv",
    "vulnerabilities.csv": "cleaned_vulnerabilities.csv",
    "mitre_attack_mapping.csv": "cleaned_mitre_attack_mapping.csv",
    "incident_history.csv": "cleaned_incident_history.csv",
    "assets.csv": "cleaned_assets.csv",
}


def main():
    """Main execution function for data validation and cleaning."""
    print("=" * 70)
    print("      DATA CLEANING & VALIDATION PIPELINE (MILESTONE 1)")
    print("=" * 70)
    
    # Ensure processed output directory exists
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Load Raw Datasets
    raw_datasets = load_raw_datasets()
    
    summary_report = []
    
    # 2. Process each dataset
    for filename, raw_df in raw_datasets.items():
        print(f"\n[+] Processing Dataset: {filename}")
        
        # A. Validate Schema
        validate_schema(filename, raw_df)
        print("    - Schema Validation: PASSED")
        
        # B. Deduplication
        dedup_df, rows_before, rows_after, dupes_removed = remove_duplicates(filename, raw_df)
        print(f"    - Rows Before: {rows_before}")
        print(f"    - Rows After:  {rows_after}")
        print(f"    - Duplicates Removed: {dupes_removed}")
        
        # C. Specialized Dataset Cleaning
        cleaning_fn = CLEANING_DISPATCH[filename]
        cleaned_df = cleaning_fn(dedup_df)
        
        # D. Count Missing Values
        missing_counts = cleaned_df.isnull().sum().to_dict()
        print("    - Datatype Conversions & Casing Normalization: COMPLETE")
        print("    - Null Value Summary:")
        for col, null_cnt in missing_counts.items():
            if null_cnt > 0:
                pct = (null_cnt / len(cleaned_df)) * 100
                print(f"       * {col}: {null_cnt} ({pct:.2f}%)")
        if not any(missing_counts.values()):
            print("       * No missing values found.")
            
        # E. Save Cleaned Dataset to data/processed/
        output_path = PROCESSED_DIR / OUTPUT_FILENAMES[filename]
        cleaned_df.to_csv(output_path, index=False)
        print(f"    - Saved to: {output_path.relative_to(BASE_DIR)}")
        
        summary_report.append({
            "dataset": filename,
            "rows_before": rows_before,
            "rows_after": rows_after,
            "dupes_removed": dupes_removed,
            "output_file": OUTPUT_FILENAMES[filename]
        })
        
    print("\n" + "=" * 70)
    print("                     CLEANING SUMMARY REPORT")
    print("=" * 70)
    for report in summary_report:
        print(f" Dataset: {report['dataset']:<25} | Rows: {report['rows_after']:<5} | Dupes Removed: {report['dupes_removed']:<2}")
    
    print("\nCleaning completed successfully.")


if __name__ == "__main__":
    main()
