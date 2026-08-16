"""
Database Core Connection Module
Milestone 1: Security Data Aggregation & Threat Intelligence Layer

Provides reusable PyMongo database connection handling for the security_operations database.
Supports environment configuration via python-dotenv without hardcoding credentials.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.database import Database
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError

# Load environment variables from .env at project root if present
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = "security_operations"

# Global lazy client instance
_client: Optional[MongoClient] = None


def get_client() -> MongoClient:
    """
    Returns a singleton PyMongo MongoClient instance.
    Initializes lazily on first access.
    """
    global _client
    if _client is None:
        try:
            _client = MongoClient(
                MONGODB_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000
            )
        except Exception as e:
            raise ConnectionError(f"Failed to initialize PyMongo client: {e}")
    return _client


def get_database(db_name: str = DB_NAME) -> Database:
    """
    Returns the handle for the security_operations MongoDB database.
    """
    client = get_client()
    return client[db_name]


def check_database_connection() -> tuple[bool, str]:
    """
    Lightweight health check for MongoDB connection.
    Executes a ping command against the server.
    
    Returns (is_healthy, status_message).
    """
    try:
        client = get_client()
        # Admin command ping forces network round-trip verification
        client.admin.command("ping")
        return True, "MongoDB connection established successfully."
    except (ConnectionFailure, ServerSelectionTimeoutError) as e:
        return False, f"MongoDB connection failed: Could not connect to server at {MONGODB_URI}. Error: {e}"
    except Exception as e:
        return False, f"Unexpected database connection error: {e}"


def close_database_connection() -> None:
    """Closes active PyMongo client connections."""
    global _client
    if _client is not None:
        _client.close()
        _client = None
