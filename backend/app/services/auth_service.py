"""
Authentication & User Identity Service
Milestone 1-3 Extension: Enterprise Security Operations Authentication Layer

Handles secure user registration, bcrypt password hashing & verification,
MongoDB 'users' collection indexing, idempotent user seeding, and JWT bearer token issuance.
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Any
import bcrypt
import jwt
from pymongo.database import Database
from pymongo.errors import DuplicateKeyError

from backend.app.core.database import get_database

# Configuration loaded securely from environment variables
JWT_SECRET_KEY = os.getenv(
    "JWT_SECRET_KEY",
    "soc-secret-jwt-key-operations-center-2026-secure-32"
)
JWT_ALGORITHM = "HS256"
DEFAULT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "1440"))  # 24 Hours

# Default Seeded Demo Accounts (Idempotent initial bootstrap)
DEFAULT_SEEDED_USERS = [
    {
        "email": "analyst@soc.internal",
        "password": "Password123!",
        "full_name": "SOC Analyst",
        "role": "SOC Analyst"
    },
    {
        "email": "1304mayanksvjc@gmail.com",
        "password": "Password123!",
        "full_name": "Mayank Bajaj",
        "role": "SOC Administrator"
    }
]


class AuthService:
    """Service handling credential verification, user persistence, and JWT tokens."""

    def __init__(self, db: Optional[Database] = None):
        self.db = db if db is not None else get_database()
        self.collection_name = "users"
        self._ensure_indexes()

    @property
    def users_collection(self):
        return self.db[self.collection_name]

    def _ensure_indexes(self) -> None:
        """Enforces unique index constraint on the normalized email field."""
        try:
            self.users_collection.create_index([("email", 1)], unique=True)
        except Exception:
            # Fallback if MongoDB connection is pending or read-only during unit tests
            pass

    @staticmethod
    def hash_password(plain_password: str) -> str:
        """Securely hashes a plaintext password using bcrypt with salt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verifies a plaintext password against a stored bcrypt hash."""
        if not plain_password or not hashed_password:
            return False
        try:
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8")
            )
        except Exception:
            return False

    @staticmethod
    def create_access_token(
        data: dict[str, Any],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Generates a cryptographically signed HS256 JWT access token."""
        to_encode = data.copy()
        now = datetime.now(timezone.utc)
        if expires_delta:
            expire = now + expires_delta
        else:
            expire = now + timedelta(minutes=DEFAULT_EXPIRATION_MINUTES)

        to_encode.update({
            "exp": expire,
            "iat": now,
            "iss": "soc-operations-auth"
        })
        return jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    @staticmethod
    def decode_access_token(token: str) -> Optional[dict[str, Any]]:
        """Decodes and validates a JWT token using the configured secret key."""
        try:
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                options={"verify_iss": True},
                issuer="soc-operations-auth"
            )
            return payload
        except (jwt.PyJWTError, Exception):
            return None

    def get_user_by_email(self, email: str) -> Optional[dict[str, Any]]:
        """Retrieves a user document by normalized lowercase email."""
        normalized = email.strip().lower()
        return self.users_collection.find_one({"email": normalized})

    def authenticate_user(self, email: str, password: str) -> Optional[dict[str, Any]]:
        """
        Authenticates a user against MongoDB users collection.
        Returns user document if valid, None if user does not exist or password mismatch.
        Never reveals whether it was the email or password that was incorrect.
        """
        user = self.get_user_by_email(email)
        if not user:
            return None

        stored_hash = user.get("hashed_password")
        if not stored_hash or not self.verify_password(password, stored_hash):
            return None

        return user

    def create_user(
        self,
        email: str,
        password: str,
        full_name: str,
        role: str = "SOC Analyst"
    ) -> dict[str, Any]:
        """
        Creates a new user record with normalized email and bcrypt-hashed password.
        Raises ValueError if user already exists or inputs are invalid.
        """
        normalized_email = email.strip().lower()
        if not normalized_email:
            raise ValueError("Email cannot be empty.")
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters.")

        existing = self.get_user_by_email(normalized_email)
        if existing:
            raise ValueError(f"User with email '{normalized_email}' already exists.")

        user_doc = {
            "email": normalized_email,
            "hashed_password": self.hash_password(password),
            "full_name": full_name.strip(),
            "role": role.strip() if role else "SOC Analyst",
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        try:
            self.users_collection.insert_one(user_doc)
        except DuplicateKeyError:
            raise ValueError(f"User with email '{normalized_email}' already exists.")

        return user_doc

    def seed_default_users(self) -> list[str]:
        """
        Idempotent seeder: Ensures default demo/analyst accounts exist in the database.
        If a user already exists, it is left untouched.
        Returns list of seeded emails.
        """
        self._ensure_indexes()
        seeded = []
        for user_meta in DEFAULT_SEEDED_USERS:
            email = user_meta["email"].strip().lower()
            existing = self.get_user_by_email(email)
            if not existing:
                self.create_user(
                    email=email,
                    password=user_meta["password"],
                    full_name=user_meta["full_name"],
                    role=user_meta["role"]
                )
                seeded.append(email)
        return seeded


# Singleton service instance
_auth_service: Optional[AuthService] = None


def get_auth_service(db: Optional[Database] = None) -> AuthService:
    """Returns a singleton AuthService instance."""
    global _auth_service
    if _auth_service is None or db is not None:
        service = AuthService(db=db)
        if db is None:
            _auth_service = service
        return service
    return _auth_service
