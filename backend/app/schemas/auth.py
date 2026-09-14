"""
Authentication Schemas
Milestone 1-3 Extension: Production Backend Authentication

Pydantic schemas for user login, registration, and safe identity token responses.
Guarantees password hashes are never exposed in response models.
"""

from typing import Optional
from pydantic import BaseModel, Field, field_validator


class LoginRequest(BaseModel):
    """Payload schema for user authentication requests."""
    email: str = Field(..., min_length=3, description="User email address")
    password: str = Field(..., min_length=1, description="Plaintext password for verification")

    @field_validator("email")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean or "@" not in clean or "." not in clean:
            raise ValueError("A valid email address is required.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Password cannot be empty or whitespace.")
        return v


class RegisterRequest(BaseModel):
    """Payload schema for creating a new user account."""
    email: str = Field(..., min_length=3, description="Unique user email address")
    password: str = Field(..., min_length=8, description="User password (min 8 chars)")
    full_name: str = Field(..., min_length=1, description="Full name of the user/analyst")
    role: Optional[str] = Field("SOC Analyst", description="Assigned organizational role")

    @field_validator("email")
    @classmethod
    def validate_and_normalize_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not clean or "@" not in clean or "." not in clean:
            raise ValueError("A valid email address is required.")
        return clean

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        return v


class UserResponse(BaseModel):
    """Safe public user identity model with all sensitive credentials omitted."""
    email: str = Field(..., description="Normalized user email")
    full_name: str = Field(..., description="Full display name")
    role: str = Field(..., description="User role in the SOC")
    created_at: Optional[str] = Field(None, description="ISO timestamp of account creation")


class TokenResponse(BaseModel):
    """JWT Bearer token and authenticated user profile response."""
    access_token: str = Field(..., description="Signed JWT Bearer token")
    token_type: str = Field("bearer", description="Token type identifier")
    user: UserResponse = Field(..., description="Authenticated user metadata")
