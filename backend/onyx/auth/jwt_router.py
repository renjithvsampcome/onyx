from typing import Dict
from typing import Optional

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from onyx.auth.jwt_utils import create_token_pair
from onyx.auth.jwt_utils import verify_jwt_token
from onyx.auth.schemas import LoginRequest
from onyx.auth.schemas import RefreshTokenRequest
from onyx.auth.schemas import TokenResponse
from onyx.auth.users import get_user_manager
from onyx.auth.users import UserManager
from onyx.configs.app_configs import AUTH_TYPE
from onyx.configs.constants import AuthType
from onyx.db.auth import get_user_by_email
from onyx.db.engine import get_async_session
from onyx.utils.logger import setup_logger

logger = setup_logger()

jwt_auth_router = APIRouter(prefix="/auth/jwt", tags=["auth"])


@jwt_auth_router.post("/login", response_model=TokenResponse)
async def jwt_login(
    credentials: OAuth2PasswordRequestForm = Depends(),
    user_manager: UserManager = Depends(get_user_manager),
) -> TokenResponse:
    """JWT login endpoint that returns access and refresh tokens"""
    
    # Use the user manager's authenticate method which handles multi-tenancy
    user = await user_manager.authenticate(credentials)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled",
        )
    
    # Create token pair
    user_data = {
        "sub": user.email,
        "user_id": str(user.id),
        "role": user.role.value,
    }
    
    tokens = create_token_pair(user_data)
    
    logger.info(f"JWT login successful for user: {user.email}")
    
    return TokenResponse(**tokens)


@jwt_auth_router.post("/refresh", response_model=TokenResponse)
async def jwt_refresh(
    refresh_request: RefreshTokenRequest,
    async_db_session: AsyncSession = Depends(get_async_session),
) -> TokenResponse:
    """Refresh JWT tokens using a refresh token"""
    
    try:
        # Verify refresh token
        payload = await verify_jwt_token(
            refresh_request.refresh_token, 
            token_type="refresh",
            async_db_session=async_db_session
        )
        
        # Get user and verify they're still active
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )
        
        user = await get_user_by_email(user_email, async_db_session)
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        
        # Create new token pair
        user_data = {
            "sub": user.email,
            "user_id": str(user.id),
            "role": user.role.value,
        }
        
        tokens = create_token_pair(user_data)
        
        logger.info(f"JWT tokens refreshed for user: {user.email}")
        
        return TokenResponse(**tokens)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing JWT tokens: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )


@jwt_auth_router.post("/logout")
async def jwt_logout() -> Dict[str, str]:
    """
    JWT logout endpoint. 
    Since JWTs are stateless, this just returns a success message.
    The client should remove the token from storage.
    """
    return {"message": "Successfully logged out"}


@jwt_auth_router.get("/me")
async def get_current_user_info(
    async_db_session: AsyncSession = Depends(get_async_session),
    authorization: Optional[str] = Depends(lambda r: r.headers.get("Authorization")),
) -> Dict[str, any]:
    """Get current user information from JWT token"""
    
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = authorization.split(" ")[1]
    
    try:
        # Verify access token
        payload = await verify_jwt_token(
            token, 
            token_type="access",
            async_db_session=async_db_session
        )
        
        user_email = payload.get("sub")
        if not user_email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        
        user = await get_user_by_email(user_email, async_db_session)
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        
        return {
            "id": str(user.id),
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting user info: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )