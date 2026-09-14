"""
Authentication API Endpoints
Milestone 1-3 Extension: Enterprise Security Operations Authentication Layer

Provides REST endpoints for user authentication, registration, session verification,
and JWT bearer token generation.
"""

from fastapi import APIRouter, HTTPException, Depends, status, Header
from typing import Optional

from backend.app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse
)
from backend.app.services.auth_service import AuthService, get_auth_service

router = APIRouter(prefix="/auth", tags=["Authentication"])


def get_auth_dep() -> AuthService:
    """Dependency provider returning singleton AuthService instance."""
    return get_auth_service()


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and return JWT Bearer token"
)
async def login(
    payload: LoginRequest,
    auth_service: AuthService = Depends(get_auth_dep)
) -> TokenResponse:
    """
    Authenticates user credentials against MongoDB users collection.
    - Validates email and password.
    - Emits a signed JWT access token upon success.
    - Emits HTTP 401 Unauthorized with safe error message on failure.
    - Never exposes password hashes or database internals.
    """
    user = auth_service.authenticate_user(payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Issue JWT access token
    token_payload = {
        "sub": user["email"],
        "name": user.get("full_name", ""),
        "role": user.get("role", "SOC Analyst")
    }
    access_token = auth_service.create_access_token(token_payload)

    user_response = UserResponse(
        email=user["email"],
        full_name=user.get("full_name", "SOC Analyst"),
        role=user.get("role", "SOC Analyst"),
        created_at=user.get("created_at")
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new SOC analyst user"
)
async def register(
    payload: RegisterRequest,
    auth_service: AuthService = Depends(get_auth_dep)
) -> TokenResponse:
    """
    Registers a new user into MongoDB with a bcrypt-hashed password.
    - Enforces email uniqueness.
    - Validates password length.
    - Automatically signs in the new user and returns a JWT access token.
    """
    try:
        new_user = auth_service.create_user(
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
            role=payload.role or "SOC Analyst"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

    token_payload = {
        "sub": new_user["email"],
        "name": new_user["full_name"],
        "role": new_user["role"]
    }
    access_token = auth_service.create_access_token(token_payload)

    user_response = UserResponse(
        email=new_user["email"],
        full_name=new_user["full_name"],
        role=new_user["role"],
        created_at=new_user["created_at"]
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve current authenticated user from JWT token"
)
async def get_current_user(
    authorization: Optional[str] = Header(None),
    auth_service: AuthService = Depends(get_auth_dep)
) -> UserResponse:
    """
    Verifies the JWT Bearer token in the Authorization header and retrieves
    safe user identity information.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = authorization.split(" ")[1].strip()
    payload = auth_service.decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = auth_service.get_user_by_email(payload["sub"])
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User associated with token no longer exists."
        )

    return UserResponse(
        email=user["email"],
        full_name=user.get("full_name", ""),
        role=user.get("role", "SOC Analyst"),
        created_at=user.get("created_at")
    )
