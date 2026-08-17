"""
backend/app/services/threat_prediction_service.py

Milestone 2 — Step 7: Prediction storage in MongoDB Service Module

Provides database operations for the `threat_predictions` MongoDB collection in the
`security_operations` database using PyMongo.

Data Ownership Architecture:
- `security_events` collection remains the authoritative primary telemetry collection.
- `threat_predictions` collection stores ML anomaly predictions, threat classifications,
  confidence scores, and XAI reasons, linked to `security_events` strictly via `event_id`.
- Full security event documents are NOT duplicated into `threat_predictions`.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from pymongo import ReplaceOne, ASCENDING, DESCENDING
from pymongo.database import Database
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database

# Configure logger
logger = logging.getLogger("ThreatPredictionService")
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s - %(message)s")

COLLECTION_NAME = "threat_predictions"
MODEL_VERSION = "isolation_forest_v1"

INDEX_SPECIFICATIONS = [
    # 1. Unique primary key index
    {"keys": [("event_id", ASCENDING)], "unique": True, "name": "uniq_event_id"},
    # 2. Query indexes for dashboard filtering and performance
    {"keys": [("threat_level", ASCENDING), ("created_at", DESCENDING)], "name": "idx_threat_level_created"},
    {"keys": [("prediction", ASCENDING)], "name": "idx_prediction"},
    {"keys": [("confidence_score", DESCENDING)], "name": "idx_confidence_score"},
    {"keys": [("threat_type", ASCENDING)], "name": "idx_threat_type"},
    {"keys": [("created_at", DESCENDING)], "name": "idx_created_at"},
]


class ThreatPredictionService:
    """
    Service layer providing PyMongo CRUD operations, index management,
    and bulk upserts for the `threat_predictions` collection.
    """

    def __init__(self, db: Optional[Database] = None):
        self.db = db if db is not None else get_database()
        self.collection = self.db[COLLECTION_NAME]

    def ensure_indexes(self) -> List[str]:
        """
        Creates required unique and query performance indexes on threat_predictions.
        Returns created index names.
        """
        created_indexes = []
        for index_spec in INDEX_SPECIFICATIONS:
            keys = index_spec["keys"]
            unique = index_spec.get("unique", False)
            name = index_spec.get("name")
            
            idx_name = self.collection.create_index(keys, unique=unique, name=name)
            created_indexes.append(idx_name)
            logger.info(f"Ensured index '{idx_name}' on collection '{COLLECTION_NAME}'")
        return created_indexes

    def format_prediction_document(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validates and standardizes an input prediction record dictionary into a BSON-compliant document.
        """
        event_id = str(record.get("event_id", "")).strip()
        if not event_id:
            raise ValueError("Document missing required primary key 'event_id'")

        prediction = str(record.get("prediction", "Normal")).strip()
        
        try:
            anomaly_score = float(record.get("anomaly_score", 0.0))
        except (ValueError, TypeError):
            anomaly_score = 0.0

        threat_type = str(record.get("threat_type", "Normal Activity")).strip()
        threat_level = str(record.get("threat_level", "Normal")).strip()

        try:
            confidence_score = int(round(float(record.get("confidence_score", 0))))
        except (ValueError, TypeError):
            confidence_score = 0
            
        confidence_score = max(0, min(100, confidence_score))

        # Handle reasons: parse stringified JSON array or preserve list
        reasons_raw = record.get("reasons", [])
        if isinstance(reasons_raw, str):
            try:
                reasons = json.loads(reasons_raw)
            except Exception:
                reasons = [reasons_raw] if reasons_raw else []
        elif isinstance(reasons_raw, list):
            reasons = [str(r) for r in reasons_raw]
        else:
            reasons = []

        # Parse or default timestamp
        created_at_raw = record.get("created_at")
        if isinstance(created_at_raw, datetime):
            created_at = created_at_raw
        elif isinstance(created_at_raw, str):
            try:
                created_at = datetime.fromisoformat(created_at_raw)
            except Exception:
                created_at = datetime.now(timezone.utc)
        else:
            created_at = datetime.now(timezone.utc)

        model_version = str(record.get("model_version", MODEL_VERSION))

        return {
            "event_id": event_id,
            "prediction": prediction,
            "anomaly_score": anomaly_score,
            "threat_type": threat_type,
            "threat_level": threat_level,
            "confidence_score": confidence_score,
            "reasons": reasons,
            "model_version": model_version,
            "created_at": created_at
        }

    def insert_prediction(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Inserts or updates a single prediction document idempotently by event_id.
        """
        doc = self.format_prediction_document(record)
        self.collection.replace_one({"event_id": doc["event_id"]}, doc, upsert=True)
        return doc

    def bulk_upsert_predictions(self, records: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Performs idempotent bulk upsert of prediction records.
        Returns stats: {"total": N, "inserted": N_new, "updated": N_mod, "failed": 0}.
        """
        if not records:
            return {"total": 0, "inserted": 0, "updated": 0, "failed": 0}

        bulk_ops = []
        for record in records:
            doc = self.format_prediction_document(record)
            bulk_ops.append(ReplaceOne({"event_id": doc["event_id"]}, doc, upsert=True))

        result = self.collection.bulk_write(bulk_ops)
        return {
            "total": len(records),
            "inserted": result.upserted_count,
            "updated": result.modified_count,
            "failed": 0
        }

    def get_prediction_by_event_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a prediction document by unique event_id."""
        doc = self.collection.find_one({"event_id": event_id}, {"_id": 0})
        return doc

    def get_recent_predictions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves the most recent predictions ordered by created_at descending."""
        cursor = self.collection.find({}, {"_id": 0}).sort("created_at", DESCENDING).limit(limit)
        return list(cursor)

    def get_suspicious_predictions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves predictions where prediction == 'Suspicious'."""
        cursor = self.collection.find({"prediction": "Suspicious"}, {"_id": 0}).sort("confidence_score", DESCENDING).limit(limit)
        return list(cursor)

    def get_predictions_by_threat_level(self, threat_level: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves predictions matching a specific threat_level."""
        cursor = self.collection.find({"threat_level": threat_level}, {"_id": 0}).sort("confidence_score", DESCENDING).limit(limit)
        return list(cursor)

    def get_predictions_by_threat_type(self, threat_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves predictions matching a specific threat_type."""
        cursor = self.collection.find({"threat_type": threat_type}, {"_id": 0}).sort("confidence_score", DESCENDING).limit(limit)
        return list(cursor)

    def validate_referential_integrity(self) -> Dict[str, Any]:
        """
        Validates referential integrity between `threat_predictions` and `security_events`:
        - Checks total prediction count
        - Verifies that every threat_predictions.event_id exists in security_events.event_id
        - Detects orphan predictions or duplicate event_ids
        """
        events_coll = self.db["security_events"]
        
        pred_count = self.collection.count_documents({})
        event_ids_in_pred = self.collection.distinct("event_id")
        
        sec_event_count = events_coll.count_documents({})
        event_ids_in_sec = set(events_coll.distinct("event_id"))
        
        pred_event_ids_set = set(event_ids_in_pred)
        
        # Check matching
        matching_count = len(pred_event_ids_set.intersection(event_ids_in_sec))
        orphans = list(pred_event_ids_set - event_ids_in_sec)
        duplicates = pred_count - len(pred_event_ids_set)
        
        return {
            "prediction_count": pred_count,
            "security_events_count": sec_event_count,
            "matching_count": matching_count,
            "orphan_predictions": len(orphans),
            "duplicate_predictions": duplicates,
            "is_valid": (pred_count == sec_event_count == matching_count and duplicates == 0 and len(orphans) == 0)
        }
