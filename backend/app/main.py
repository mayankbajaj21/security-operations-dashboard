"""
Main FastAPI Application Entry Point
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Initializes the FastAPI application, configures CORS middleware for frontend access,
and registers core API routers (health, events, metrics, mitre, assets, threat-intel, trends).
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.assets import router as assets_router
from backend.app.api.attack_chains import router as attack_chains_router
from backend.app.api.auth import router as auth_router
from backend.app.api.events import router as events_router
from backend.app.api.health import router as health_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.metrics import router as metrics_router
from backend.app.api.mitre import router as mitre_router
from backend.app.api.predictions import router as predictions_router
from backend.app.api.risk import router as risk_router
from backend.app.api.threat_intel import router as threat_intel_router
from backend.app.api.trends import router as trends_router
from backend.app.services.auth_service import get_auth_service

app = FastAPI(
    title="Security Operations Dashboard API",
    description="REST API serving aggregated security telemetry, threat intelligence, and risk mitigation analytics.",
    version="1.0.0"
)

# Configure CORS Middleware to allow requests from the React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits local frontend development connections
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    """Ensures database indexes and default users exist on application startup."""
    try:
        get_auth_service().seed_default_users()
    except Exception as e:
        # Non-blocking log to ensure API functions even if DB connection is delayed
        pass

# Register M1 & M2 API routers
app.include_router(health_router)
app.include_router(events_router)
app.include_router(metrics_router)
app.include_router(mitre_router)
app.include_router(assets_router)
app.include_router(threat_intel_router)
app.include_router(trends_router)
app.include_router(predictions_router)

# Register Authentication router under /api/v1, /v1, and /
app.include_router(auth_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/v1")
app.include_router(auth_router)

# Register M3 Risk, Incident, Recommendation, and Attack Chain routers under /api/v1 and /v1
app.include_router(risk_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(attack_chains_router, prefix="/api/v1")
app.include_router(risk_router, prefix="/v1")
app.include_router(incidents_router, prefix="/v1")
app.include_router(attack_chains_router, prefix="/v1")


