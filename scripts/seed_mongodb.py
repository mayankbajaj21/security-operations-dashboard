"""
MongoDB Database Seeding & Index Creation Pipeline Script
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Seeds the security_operations MongoDB database idempotently using processed CSV datasets
from data/processed/ and creates required unique and query performance indexes.

Raw CSV files in data/raw/ are left untouched.
"""

from datetime import datetime
from pathlib import Path
import sys
import pandas as pd
from pymongo import ReplaceOne
from pymongo.database import Database
from pymongo.errors import PyMongoError

# Add project root to Python module search path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from backend.app.core.database import check_database_connection, get_database

PROCESSED_DIR = BASE_DIR / "data" / "processed"

# Collection Configuration Mapping
COLLECTION_CONFIGS = [
    {
        "name": "security_events",
        "file": "enriched_security_events.csv",
        "pk": "event_id",
        "unique_indexes": [["event_id"]],
        "query_indexes": [
            [("timestamp", -1)],
            [("event_severity", 1), ("timestamp", -1)],
            [("event_status", 1)],
            [("threat_intel_match", 1)],
            [("mitre_id", 1)],
            [("asset_name", 1)]
        ]
    },
    {
        "name": "assets",
        "file": "cleaned_assets.csv",
        "pk": "asset_id",
        "unique_indexes": [["asset_id"], ["asset_name"]],
        "query_indexes": [
            [("department", 1)]
        ]
    },
    {
        "name": "vulnerabilities",
        "file": "cleaned_vulnerabilities.csv",
        "pk": "vulnerability_id",
        "unique_indexes": [["vulnerability_id"], ["cve_id"]],
        "query_indexes": [
            [("affected_asset", 1)]
        ]
    },
    {
        "name": "threat_intelligence",
        "file": "cleaned_threat_intelligence.csv",
        "pk": "indicator_id",
        "unique_indexes": [["indicator_id"], ["indicator_value"]],
        "query_indexes": []
    },
    {
        "name": "mitre_attack_mapping",
        "file": "cleaned_mitre_attack_mapping.csv",
        "pk": "event_type",
        "unique_indexes": [["event_type"]],
        "query_indexes": []
    }
]


def prepare_document(doc: dict, collection_name: str) -> dict:
    """
    Cleans and prepares a row dictionary for MongoDB BSON insertion:
    - Replaces pandas NaNs with Python None
    - Converts timestamps to Python datetime objects
    - Standardizes booleans and numeric types
    """
    clean_doc = {}
    for key, val in doc.items():
        if pd.isna(val):
            clean_doc[key] = None
        elif collection_name == "security_events" and key == "timestamp":
            if isinstance(val, str):
                clean_doc[key] = datetime.fromisoformat(val)
            elif isinstance(val, pd.Timestamp):
                clean_doc[key] = val.to_pydatetime()
            else:
                clean_doc[key] = val
        elif collection_name == "security_events" and key == "threat_intel_match":
            clean_doc[key] = bool(val)
        else:
            clean_doc[key] = val
    return clean_doc


def seed_collection(db: Database, config: dict) -> dict:
    """
    Reads a processed CSV file and performs idempotent bulk upsert seeding.
    Returns operational metrics.
    """
    coll_name = config["name"]
    filename = config["file"]
    pk = config["pk"]
    
    filepath = PROCESSED_DIR / filename
    if not filepath.exists():
        raise FileNotFoundError(
            f"Missing required dataset for seeding: {filepath}. "
            "Please run scripts/clean_data.py and scripts/enrich_data.py first."
        )
        
    df = pd.read_csv(filepath)
    source_count = len(df)
    
    # Check primary key presence and uniqueness in source data
    if pk not in df.columns:
        raise ValueError(f"Primary key '{pk}' missing from source file '{filename}'")
        
    if df[pk].duplicated().any():
        dupes = df[df[pk].duplicated()][pk].tolist()
        raise ValueError(f"Duplicate primary key '{pk}' values in source '{filename}': {dupes}")
        
    collection = db[coll_name]
    
    # Prepare bulk operations for idempotent upsert
    bulk_ops = []
    for row in df.to_dict(orient="records"):
        clean_doc = prepare_document(row, coll_name)
        pk_val = clean_doc[pk]
        bulk_ops.append(ReplaceOne({pk: pk_val}, clean_doc, upsert=True))
        
    if bulk_ops:
        result = collection.bulk_write(bulk_ops)
        inserted_new = result.upserted_count
        updated_existing = result.modified_count
    else:
        inserted_new = 0
        updated_existing = 0
        
    db_count = collection.count_documents({})
    
    return {
        "collection": coll_name,
        "source_count": source_count,
        "db_count": db_count,
        "inserted_new": inserted_new,
        "updated_existing": updated_existing
    }


def create_collection_indexes(db: Database, config: dict) -> None:
    """Creates unique and query performance indexes for a collection."""
    coll_name = config["name"]
    collection = db[coll_name]
    
    # Create Unique Indexes
    for fields in config.get("unique_indexes", []):
        keys = [(field, 1) for field in fields]
        collection.create_index(keys, unique=True)
        
    # Create Query Indexes
    for index_spec in config.get("query_indexes", []):
        collection.create_index(index_spec)


def main():
    """Main execution function for database seeding and validation."""
    print("=" * 70)
    print("      MONGODB DATABASE SEEDING & INDEXING PIPELINE")
    print("=" * 70)
    
    # 1. Test Database Connection
    is_healthy, conn_msg = check_database_connection()
    if not is_healthy:
        print(f"\n[!] MongoDB connection: FAILED")
        print(f"    Error: {conn_msg}")
        print("\nExiting seeding process without altering database state.")
        sys.exit(1)
        
    print("\n[+] MongoDB connection: SUCCESS")
    print("    Database: security_operations")
    
    db = get_database()
    seeding_stats = []
    
    # 2. Seed Collections
    print("\n[+] Seeding Collections from data/processed/...")
    for config in COLLECTION_CONFIGS:
        stat = seed_collection(db, config)
        seeding_stats.append(stat)
        print(f"    - Collection '{stat['collection']}': "
              f"Source: {stat['source_count']} | DB Total: {stat['db_count']} "
              f"(New Inserted: {stat['inserted_new']}, Updated: {stat['updated_existing']})")
        
    # 3. Create Indexes
    print("\n[+] Creating Indexes...")
    for config in COLLECTION_CONFIGS:
        create_collection_indexes(db, config)
    print("Index creation: SUCCESS")
    
    # 4. Validation
    print("\n[+] Performing Post-Seeding Validation...")
    events_coll = db["security_events"]
    sec_events_count = events_coll.count_documents({})
    unique_event_ids = len(events_coll.distinct("event_id"))
    
    validation_passed = True
    for stat in seeding_stats:
        if stat["db_count"] != stat["source_count"]:
            validation_passed = False
            print(f"    [!] Validation Failure for '{stat['collection']}': "
                  f"Source count ({stat['source_count']}) != DB count ({stat['db_count']})")
            
    if sec_events_count != 1800:
        validation_passed = False
        print(f"    [!] Validation Failure: security_events count ({sec_events_count}) != 1800")
        
    if unique_event_ids != 1800:
        validation_passed = False
        print(f"    [!] Validation Failure: unique event_id count ({unique_event_ids}) != 1800")

    if not validation_passed:
        print("\n[!] Validation FAILED: Database document counts do not match expected source totals.")
        sys.exit(1)

    print(f"Validation:")
    print(f"security_events = {sec_events_count}")
    print(f"unique event_id = {unique_event_ids}")
    
    print("\n" + "=" * 70)
    print("                    SEEDING SUMMARY REPORT")
    print("=" * 70)
    for stat in seeding_stats:
        print(f" Collection: {stat['collection']:<25} | Source: {stat['source_count']:<5} | DB Total: {stat['db_count']:<5}")
    print("=" * 70)
    
    print("\nMongoDB seeding completed successfully.")


if __name__ == "__main__":
    main()
