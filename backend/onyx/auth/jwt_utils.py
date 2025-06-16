import json
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Any
from typing import Dict
from typing import Optional

import httpx
import jwt
from fastapi import HTTPException
from fastapi import status
from jwt import PyJWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from onyx.configs.app_configs import JWT_ACCESS_TOKEN_EXPIRE_MINUTES
from onyx.configs.app_configs import JWT_ALGORITHM
from onyx.configs.app_configs import JWT_AUDIENCE
from onyx.configs.app_configs import JWT_ISSUER
from onyx.configs.app_configs import JWT_PUBLIC_KEY_URL
from onyx.configs.app_configs import JWT_REFRESH_TOKEN_EXPIRE_DAYS
from onyx.configs.app_configs import JWT_SECRET_KEY
from onyx.db.models import User
from onyx.utils.logger import setup_logger

logger = setup_logger()

_public_key_cache: Dict[str, Any] = {}


async def get_public_key() -> str:
    """Fetch and cache public key for external JWT verification"""
    if not JWT_PUBLIC_KEY_URL:
        raise ValueError("JWT_PUBLIC_KEY_URL not configured")
    
    # Check cache with 1-hour expiry
    cache_key = "public_key"
    cached_data = _public_key_cache.get(cache_key)
    
    if cached_data and cached_data["expires_at"] > time.time():
        return cached_data["key"]
    
    async with httpx.AsyncClient() as client:
        response = await client.get(JWT_PUBLIC_KEY_URL)
        response.raise_for_status()
        
        # Handle JWKS endpoint
        if JWT_PUBLIC_KEY_URL.endswith("/.well-known/jwks.json"):
            jwks_data = response.json()
            # Get the first key (in production, match by kid)
            key_data = jwks_data["keys"][0]
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_data))
            public_key_pem = public_key.public_bytes(
                encoding=jwt.api_jws.serialization.Encoding.PEM,
                format=jwt.api_jws.serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8")
        else:
            # Direct PEM key
            public_key_pem = response.text
    
    # Cache for 1 hour
    _public_key_cache[cache_key] = {
        "key": public_key_pem,
        "expires_at": time.time() + 3600
    }
    
    return public_key_pem


def create_access_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    if JWT_ISSUER:
        to_encode["iss"] = JWT_ISSUER
    
    if JWT_AUDIENCE:
        to_encode["aud"] = JWT_AUDIENCE
    
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def create_refresh_token(
    data: dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """Create a JWT refresh token"""
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            days=JWT_REFRESH_TOKEN_EXPIRE_DAYS
        )
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    })
    
    if JWT_ISSUER:
        to_encode["iss"] = JWT_ISSUER
    
    if JWT_AUDIENCE:
        to_encode["aud"] = JWT_AUDIENCE
    
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


async def verify_jwt_token(
    token: str,
    token_type: str = "access",
    async_db_session: Optional[AsyncSession] = None
) -> dict[str, Any]:
    """Verify a JWT token and return the payload"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Use external public key if configured
        if JWT_PUBLIC_KEY_URL:
            public_key = await get_public_key()
            payload = jwt.decode(
                token,
                public_key,
                algorithms=[JWT_ALGORITHM],
                audience=JWT_AUDIENCE if JWT_AUDIENCE else None,
                issuer=JWT_ISSUER if JWT_ISSUER else None
            )
        else:
            # Use local secret key
            payload = jwt.decode(
                token,
                JWT_SECRET_KEY,
                algorithms=[JWT_ALGORITHM],
                audience=JWT_AUDIENCE if JWT_AUDIENCE else None,
                issuer=JWT_ISSUER if JWT_ISSUER else None
            )
        
        # Verify token type
        if payload.get("type") != token_type:
            raise credentials_exception
        
        return payload
        
    except PyJWTError as e:
        logger.error(f"JWT verification failed: {str(e)}")
        raise credentials_exception


async def get_user_from_jwt_token(
    token: str,
    async_db_session: AsyncSession
) -> Optional[User]:
    """Get user from JWT token"""
    try:
        from onyx.auth.users import get_user_by_email
        payload = await verify_jwt_token(token, "access", async_db_session)
        
        # Get user identifier from token
        user_email = payload.get("sub")
        if not user_email:
            return None
        
        # Look up user in database
        user = await async_db_session.execute(
                    select(User).where(func.lower(User.email) == func.lower(user_email))
                )
        user = user.scalars().first()
        
        if not user or not user.is_active:
            return None
        
        return user
        
    except HTTPException:
        return None
    except Exception as e:
        logger.error(f"Error getting user from JWT: {str(e)}")
        return None


def create_token_pair(user_data: dict[str, Any]) -> dict[str, str]:
    """Create both access and refresh tokens"""
    access_token = create_access_token(data=user_data)
    refresh_token = create_refresh_token(data=user_data)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }