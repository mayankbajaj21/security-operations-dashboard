"""
scripts/seed_threat_predictions.py

Milestone 2 — Step 7: Prediction storage in MongoDB Seeding Script

Idempotently loads Milestone 2 threat confidence and classification output from
data/processed/m2_confidence_scores.csv into the threat_predictions collection in the
security_operations MongoDB database.

Performs document formatting, unique & query performance index creation, and referential
integrity validation against security_events.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
import pandas as pd

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.core.database import check_database_connection, get_database
from backend.app.services.threat_prediction_service import ThreatPredictionService

INPUT_CSV_PATH = BASE_DIR / "data" / "processed" / "m2_confidence_scores.csv"


def seed_threat_predictions() -> dict:
    """
    Main function for loading M2 confidence score predictions into MongoDB.
    """
    print("=" * 75)
    print("       MONGODB THREAT PREDICTIONS SEEDING & INDEXING PIPELINE")
    print("=" * 75)

    # 1. Connection Health Check
    is_healthy, conn_msg = check_database_connection()
    if not is_healthy:
        print(f"\n[!] MongoDB Connection FAILED: {conn_msg}")
        sys.exit(1)

    print("\n[+] MongoDB Connection: SUCCESS")
    print("    Database Target: security_operations")
    print(f"    Source Data:     {INPUT_CSV_PATH}")

    if not INPUT_CSV_PATH.exists():
        print(f"\n[!] Error: Required input dataset not found at {INPUT_CSV_PATH}")
        sys.exit(1)

    # 2. Read Source CSV
    df = pd.read_csv(INPUT_CSV_PATH)
    source_count = len(df)
    print(f"\n[+] Loaded {source_count} records from CSV.")

    required_cols = [
        'event_id', 'prediction', 'anomaly_score', 'threat_type',
        'threat_level', 'confidence_score', 'reasons'
    ]
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        print(f"\n[!] Error: Input CSV missing required columns: {missing_cols}")
        sys.exit(1)

    if df['event_id'].duplicated().any():
        dupes = df[df['event_id'].duplicated()]['event_id'].tolist()
        print(f"\n[!] Error: Duplicate primary keys found in source CSV: {dupes}")
        sys.exit(1)

    # 3. Initialize Service & Ensure Indexes
    service = ThreatPredictionService()
    print("\n[+] Creating Indexes on 'threat_predictions' collection...")
    created_indexes = service.ensure_indexes()
    print(f"    - Indexes Ensured ({len(created_indexes)}): {created_indexes}")

    # 4. Perform Idempotent Bulk Upsert
    print("\n[+] Executing Idempotent Bulk Upsert...")
    records = df.to_dict(orient="records")
    
    # Add creation timestamp
    now = datetime.now(timezone.utc)
    for rec in records:
        rec["created_at"] = now

    stats = service.bulk_upsert_predictions(records)

    print(f"    - Total Input Records:  {stats['total']}")
    print(f"    - Newly Inserted:       {stats['inserted']}")
    print(f"    - Updated Existing:     {stats['updated']}")
    print(f"    - Failures:             {stats['failed']}")

    # 5. Perform Post-Seeding Validation & Referential Integrity
    print("\n[+] Performing Referential Integrity & Document Validation...")
    ref_stats = service.validate_referential_integrity()

    print(f"    - Prediction Collection Total: {ref_stats['prediction_count']}")
    print(f"    - Security Events Total:      {ref_stats['security_events_count']}")
    print(f"    - Matching event_id Pairs:    {ref_stats['matching_count']}")
    print(f"    - Orphan Predictions:         {ref_stats['orphan_predictions']}")
    print(f"    - Duplicate event_ids:        {ref_stats['duplicate_predictions']}")

    if not ref_stats['is_valid']:
        print("\n[!] Referential Integrity Validation FAILED!")
        sys.exit(1)

    print("\n[+] Referential Integrity Validation: SUCCESS (100% 1:1 match with security_events)")

    # 6. Representative Events Verification
    print("\n[+] Representative Events Inspection from MongoDB:")
    target_ids = ['EVT00034', 'EVT00036', 'EVT00144', 'EVT01233', 'EVT01600']
    for eid in target_ids:
        doc = service.get_prediction_by_event_id(eid)
        if doc:
            print(f"    ID: {doc['event_id']} | ML: {doc['prediction']} | Type: {doc['threat_type']:<22} | Level: {doc['threat_level']:<15} | Score: {doc['confidence_score']}/100")
        else:
            print(f"    [!] Error: Representative event {eid} not found in MongoDB!")
            sys.exit(1)

    print("\n" + "=" * 75)
    print("            THREAT PREDICTIONS SEEDING SUMMARY REPORT")
    print("=" * 75)
    print(f" Collection Name:          threat_predictions")
    print(f" Source CSV Count:         {source_count}")
    print(f" MongoDB Document Count:   {ref_stats['prediction_count']}")
    print(f" Matching Security Events: {ref_stats['matching_count']}")
    print(f" Referential Integrity:    VALID (0 Orphans, 0 Duplicates)")
    print("=" * 75)

    return {
        "source_count": source_count,
        "db_count": ref_stats['prediction_count'],
        "inserted_new": stats['inserted'],
        "updated_existing": stats['updated'],
        "referential_valid": ref_stats['is_valid']
    }


if __name__ == "__main__":
    seed_threat_predictions()
