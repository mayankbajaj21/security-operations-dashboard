"""
backend/app/api/predictions.py

Milestone 2 — Step 8: Prediction APIs REST Router

Provides REST API endpoints for Milestone 2 Threat Detection:
1. POST /predict            - On-the-fly live inference pipeline
2. GET /predictions         - Paginated query & filtering of stored predictions
3. GET /predictions/{event_id} - Single prediction lookup joined with telemetry (404 on missing)
4. GET /anomalies           - Specialized query returning only 'Suspicious' predictions
5. GET /model-performance   - Diagnostic model evaluation statistics
6. GET /threat-summary      - Aggregated SOC dashboard KPI metrics derived from MongoDB
"""

from datetime import datetime, timezone
import json
import math
import re
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query, status
import pandas as pd
from pymongo.errors import PyMongoError

from backend.app.core.database import get_database
from backend.app.services.threat_prediction_service import ThreatPredictionService
from backend.app.schemas.prediction import (
    PredictRequest,
    PredictResponse,
    PredictionDocumentResponse,
    PaginatedPredictionsResponse,
    PredictionWithEventDetailsResponse,
    ModelPerformanceResponse,
    ScoreDistribution,
    ThreatSummaryResponse,
    PaginationMeta
)
from backend.ml.model_loader import ModelLoader
from backend.ml.threat_classifier import SecurityThreatClassifier
from backend.ml.confidence_scorer import ThreatConfidenceScorer

router = APIRouter(tags=["Threat Predictions"])

# Initialize cached singletons for services and ML models
_model_loader: Optional[ModelLoader] = None
_threat_classifier: Optional[SecurityThreatClassifier] = None
_confidence_scorer: Optional[ThreatConfidenceScorer] = None


def get_model_loader_instance() -> ModelLoader:
    """Returns cached ModelLoader instance."""
    global _model_loader
    if _model_loader is None:
        _model_loader = ModelLoader()
        _model_loader.load_artifacts()
    return _model_loader


def get_threat_classifier_instance() -> SecurityThreatClassifier:
    """Returns cached SecurityThreatClassifier instance."""
    global _threat_classifier
    if _threat_classifier is None:
        _threat_classifier = SecurityThreatClassifier()
    return _threat_classifier


def get_confidence_scorer_instance() -> ThreatConfidenceScorer:
    """Returns cached ThreatConfidenceScorer instance."""
    global _confidence_scorer
    if _confidence_scorer is None:
        _confidence_scorer = ThreatConfidenceScorer()
    return _confidence_scorer


def parse_reasons(reasons_val: Any) -> List[str]:
    """Helper to parse reasons field safely whether JSON string, list, or null."""
    if isinstance(reasons_val, list):
        return reasons_val
    if isinstance(reasons_val, str):
        try:
            parsed = json.loads(reasons_val)
            if isinstance(parsed, list):
                return parsed
            return [str(parsed)]
        except Exception:
            return [reasons_val] if reasons_val.strip() else []
    return []


def serialize_datetime(dt_val: Any) -> str:
    """Converts datetime or string timestamp into clean ISO string."""
    if isinstance(dt_val, datetime):
        return dt_val.isoformat()
    if isinstance(dt_val, str):
        return dt_val
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# 1. POST /predict — Live On-The-Fly Inference Endpoint
# ============================================================================
@router.post("/predict", response_model=PredictResponse, status_code=status.HTTP_200_OK)
def predict_event(payload: PredictRequest) -> PredictResponse:
    """
    Executes live on-the-fly threat prediction for an incoming security event.
    
    Pipeline Execution Flow:
    1. Preprocesses raw telemetry features via SecurityEventPreprocessor.
    2. Evaluates Isolation Forest decision function anomaly score.
    3. Categorizes event into Threat Type & Threat Level via SecurityThreatClassifier rules.
    4. Computes Threat Confidence Score (0–100) via ThreatConfidenceScorer.
    """
    try:
        loader = get_model_loader_instance()
        classifier = get_threat_classifier_instance()
        scorer = get_confidence_scorer_instance()

        event_id = payload.event_id or "EVT_LIVE_001"
        ts_str = payload.timestamp or datetime.now(timezone.utc).isoformat()

        # Construct single-event dictionary for preprocessing
        raw_event_dict = {
            "event_id": event_id,
            "timestamp": ts_str,
            "failed_login_attempts": payload.failed_login_attempts,
            "raw_cvss_score": payload.raw_cvss_score,
            "malware_detected": payload.malware_detected,
            "event_severity": payload.event_severity,
            "protocol": payload.protocol,
            "event_type": payload.event_type,
            "event_status": payload.event_status,
            "username": payload.username,
            "source_ip": payload.source_ip,
            "destination_ip": payload.destination_ip,
            "after_hours_activity": payload.after_hours_activity,
            "events_per_user_1h": payload.events_per_user_1h,
            "login_frequency_1h": payload.login_frequency_1h,
            "unique_destinations_24h": payload.unique_destinations_24h,
            "vulnerability_present": payload.vulnerability_present,
            "vulnerability_id": "CVE-2026-0001" if payload.vulnerability_present else None
        }

        # 1. Preprocess and run Isolation Forest inference
        raw_df = pd.DataFrame([raw_event_dict])
        ml_prediction_df = loader.predict_events(raw_df)

        prediction_label = str(ml_prediction_df['prediction'].values[0])
        anomaly_score_val = float(ml_prediction_df['anomaly_score'].values[0])

        raw_event_dict['prediction'] = prediction_label
        raw_event_dict['anomaly_score'] = anomaly_score_val

        # 2. Apply hybrid security threat classification rules
        classified = classifier.classify_event(raw_event_dict)
        raw_event_dict.update(classified)

        # 3. Compute Threat Confidence Score (0–100)
        confidence_result = scorer.compute_event_confidence(raw_event_dict)

        reasons_list = parse_reasons(confidence_result.get('reasons', '[]'))

        return PredictResponse(
            event_id=event_id,
            prediction=prediction_label,
            anomaly_score=anomaly_score_val,
            threat_type=str(confidence_result.get('threat_type', 'Normal Activity')),
            threat_level=str(confidence_result.get('threat_level', 'Normal')),
            confidence_score=int(confidence_result.get('confidence_score', 0)),
            reasons=reasons_list,
            model_version="isolation_forest_v1"
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Live inference execution failed: {str(e)}"
        )


# ============================================================================
# 2. GET /predictions — Stored Prediction Query Endpoint
# ============================================================================
@router.get("/predictions", response_model=PaginatedPredictionsResponse, status_code=status.HTTP_200_OK)
def get_predictions(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    prediction: Optional[str] = Query(default=None, description="Filter by prediction ('Normal' or 'Suspicious')"),
    threat_level: Optional[str] = Query(default=None, description="Filter by threat level"),
    threat_type: Optional[str] = Query(default=None, description="Filter by threat type"),
    min_confidence: Optional[int] = Query(default=None, ge=0, le=100, description="Minimum confidence score"),
    search: Optional[str] = Query(default=None, description="Search term matching event_id, threat_type, or threat_level")
) -> PaginatedPredictionsResponse:
    """
    Retrieves paginated threat predictions stored in MongoDB with optional filtering.
    """
    try:
        db = get_database()
        collection = db["threat_predictions"]

        conditions = []
        if prediction:
            conditions.append({"prediction": prediction})
        if threat_level:
            conditions.append({"threat_level": threat_level})
        if threat_type:
            conditions.append({"threat_type": threat_type})
        if min_confidence is not None:
            conditions.append({"confidence_score": {"$gte": min_confidence}})
        if search and search.strip():
            safe_search = re.escape(search.strip())
            regex_pat = {"$regex": safe_search, "$options": "i"}
            conditions.append({
                "$or": [
                    {"event_id": regex_pat},
                    {"threat_type": regex_pat},
                    {"threat_level": regex_pat}
                ]
            })

        query_filter = {} if not conditions else (conditions[0] if len(conditions) == 1 else {"$and": conditions})

        total = collection.count_documents(query_filter)
        total_pages = math.ceil(total / limit) if total > 0 else 0
        skip_count = (page - 1) * limit

        cursor = collection.find(query_filter, {"_id": 0}).sort("event_id", 1).skip(skip_count).limit(limit)

        records = []
        for doc in cursor:
            records.append(PredictionDocumentResponse(
                event_id=doc.get("event_id", ""),
                prediction=doc.get("prediction", "Normal"),
                anomaly_score=float(doc.get("anomaly_score", 0.0)),
                threat_type=doc.get("threat_type", "Normal Activity"),
                threat_level=doc.get("threat_level", "Normal"),
                confidence_score=int(doc.get("confidence_score", 0)),
                reasons=parse_reasons(doc.get("reasons", [])),
                model_version=doc.get("model_version", "isolation_forest_v1"),
                created_at=serialize_datetime(doc.get("created_at"))
            ))

        return PaginatedPredictionsResponse(
            data=records,
            pagination=PaginationMeta(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        )

    except PyMongoError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database service unavailable")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to query predictions: {str(e)}")


# ============================================================================
# 3. GET /predictions/{event_id} — Single Prediction & Telemetry Endpoint
# ============================================================================
@router.get("/predictions/{event_id}", response_model=PredictionWithEventDetailsResponse, status_code=status.HTTP_200_OK)
def get_prediction_by_id(event_id: str) -> PredictionWithEventDetailsResponse:
    """
    Retrieves a single threat prediction by event ID joined with security event telemetry.
    Returns HTTP 404 if the prediction record does not exist.
    """
    try:
        service = ThreatPredictionService()
        pred_doc = service.get_prediction_by_event_id(event_id)

        if not pred_doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Prediction not found for event_id '{event_id}'"
            )

        # Retrieve authoritative telemetry details from security_events collection
        db = get_database()
        event_doc = db["security_events"].find_one({"event_id": event_id}, {"_id": 0})

        event_details_map = None
        if event_doc:
            event_details_map = {}
            for k, v in event_doc.items():
                event_details_map[k] = v.isoformat() if isinstance(v, datetime) else v

        return PredictionWithEventDetailsResponse(
            event_id=pred_doc.get("event_id", event_id),
            prediction=pred_doc.get("prediction", "Normal"),
            anomaly_score=float(pred_doc.get("anomaly_score", 0.0)),
            threat_type=pred_doc.get("threat_type", "Normal Activity"),
            threat_level=pred_doc.get("threat_level", "Normal"),
            confidence_score=int(pred_doc.get("confidence_score", 0)),
            reasons=parse_reasons(pred_doc.get("reasons", [])),
            model_version=pred_doc.get("model_version", "isolation_forest_v1"),
            created_at=serialize_datetime(pred_doc.get("created_at")),
            event_details=event_details_map
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to retrieve event: {str(e)}")


# ============================================================================
# 4. GET /anomalies — Suspicious Predictions Endpoint
# ============================================================================
@router.get("/anomalies", response_model=PaginatedPredictionsResponse, status_code=status.HTTP_200_OK)
def get_anomalies(
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    min_confidence: Optional[int] = Query(default=None, ge=0, le=100, description="Minimum confidence score")
) -> PaginatedPredictionsResponse:
    """
    Retrieves stored threat predictions filtered strictly for prediction == 'Suspicious'.
    """
    try:
        db = get_database()
        collection = db["threat_predictions"]

        query_filter: Dict[str, Any] = {"prediction": "Suspicious"}
        if min_confidence is not None:
            query_filter["confidence_score"] = {"$gte": min_confidence}

        total = collection.count_documents(query_filter)
        total_pages = math.ceil(total / limit) if total > 0 else 0
        skip_count = (page - 1) * limit

        cursor = collection.find(query_filter, {"_id": 0}).sort("confidence_score", -1).skip(skip_count).limit(limit)

        records = []
        for doc in cursor:
            records.append(PredictionDocumentResponse(
                event_id=doc.get("event_id", ""),
                prediction="Suspicious",
                anomaly_score=float(doc.get("anomaly_score", 0.0)),
                threat_type=doc.get("threat_type", "Normal Activity"),
                threat_level=doc.get("threat_level", "Medium Threat"),
                confidence_score=int(doc.get("confidence_score", 0)),
                reasons=parse_reasons(doc.get("reasons", [])),
                model_version=doc.get("model_version", "isolation_forest_v1"),
                created_at=serialize_datetime(doc.get("created_at"))
            ))

        return PaginatedPredictionsResponse(
            data=records,
            pagination=PaginationMeta(
                page=page,
                limit=limit,
                total=total,
                total_pages=total_pages
            )
        )

    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to query anomalies: {str(e)}")


# ============================================================================
# 5. GET /model-performance — Diagnostic Model Evaluation Endpoint
# ============================================================================
@router.get("/model-performance", response_model=ModelPerformanceResponse, status_code=status.HTTP_200_OK)
def get_model_performance() -> ModelPerformanceResponse:
    """
    Returns verified model evaluation diagnostics for the unsupervised Isolation Forest model.
    Exposes score distribution statistics and contamination parameters established in M2 Step 4.
    """
    return ModelPerformanceResponse(
        model_name="Isolation Forest",
        model_version="isolation_forest_v1",
        total_events_evaluated=1800,
        normal_count=1710,
        suspicious_count=90,
        anomaly_percentage=5.0,
        feature_count=29,
        contamination=0.05,
        score_distribution=ScoreDistribution(
            min=-0.100174,
            max=0.061516,
            mean=-0.039102,
            median=-0.041507
        ),
        evaluation_note="Evaluated via unsupervised anomaly detection diagnostics, score distribution stability, and feature variance sensitivity."
    )


# ============================================================================
# 6. GET /threat-summary — Aggregated SOC Dashboard KPI Endpoint
# ============================================================================
@router.get("/threat-summary", response_model=ThreatSummaryResponse, status_code=status.HTTP_200_OK)
def get_threat_summary() -> ThreatSummaryResponse:
    """
    Returns aggregated threat metrics dynamically calculated from stored threat_predictions in MongoDB.
    Powers the React AI Threat Detection Dashboard overview cards and summary charts.
    """
    try:
        db = get_database()
        collection = db["threat_predictions"]

        total_events = collection.count_documents({})
        anomalies_detected = collection.count_documents({"prediction": "Suspicious"})
        normal_events = collection.count_documents({"prediction": "Normal"})

        # Threat levels breakdown
        threat_level_pipeline = [
            {"$group": {"_id": "$threat_level", "count": {"$sum": 1}}}
        ]
        threat_levels_res = list(collection.aggregate(threat_level_pipeline))
        threat_levels_dict = {doc["_id"]: doc["count"] for doc in threat_levels_res if doc["_id"]}

        # Threat types breakdown
        threat_type_pipeline = [
            {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}}
        ]
        threat_types_res = list(collection.aggregate(threat_type_pipeline))
        threat_types_dict = {doc["_id"]: doc["count"] for doc in threat_types_res if doc["_id"]}

        # Average confidence score calculation
        avg_confidence_pipeline = [
            {"$group": {"_id": None, "avg_confidence": {"$avg": "$confidence_score"}}}
        ]
        avg_res = list(collection.aggregate(avg_confidence_pipeline))
        avg_confidence = float(round(avg_res[0]["avg_confidence"], 2)) if avg_res else 0.0

        return ThreatSummaryResponse(
            total_events=total_events,
            anomalies_detected=anomalies_detected,
            normal_events=normal_events,
            threat_levels=threat_levels_dict,
            threat_types=threat_types_dict,
            average_confidence_score=avg_confidence
        )

    except PyMongoError:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Database service unavailable")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to calculate threat summary: {str(e)}")
