import uuid
from typing import Optional

from fastapi import Depends
from fastapi_users.authentication import Strategy
from fastapi_users.manager import BaseUserManager
from sqlalchemy.ext.asyncio import AsyncSession

from onyx.auth.jwt_utils import create_access_token
from onyx.auth.jwt_utils import get_user_from_jwt_token
from onyx.configs.app_configs import JWT_ACCESS_TOKEN_EXPIRE_MINUTES
from onyx.db.engine import get_async_session
from onyx.db.models import User
from onyx.db.users import get_user_tenant_id
from onyx.utils.logger import setup_logger

logger = setup_logger()


class JWTStrategy(Strategy[User, uuid.UUID]):
    """JWT-based authentication strategy for stateless authentication"""
    
    def __init__(self, lifetime_seconds: Optional[int] = None):
        self.lifetime_seconds = lifetime_seconds or (JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    
    async def read_token(
        self, 
        token: Optional[str], 
        user_manager: BaseUserManager[User, uuid.UUID]
    ) -> Optional[User]:
        """Validate JWT token and return user"""
        if not token:
            return None
        
        try:
            # Get the database session from user_manager
            if hasattr(user_manager, 'user_db') and hasattr(user_manager.user_db, 'session'):
                async_session = user_manager.user_db.session
            else:
                # Fallback to getting a new session
                async_session = await anext(get_async_session())
            
            user = await get_user_from_jwt_token(token, async_session)
            return user
            
        except Exception as e:
            logger.error(f"Error reading JWT token: {str(e)}")
            return None
    
    async def write_token(self, user: User) -> str:
        """Create JWT token for user"""
        # Get tenant ID for the user
        tenant_id = None
        try:
            async_session = await anext(get_async_session())
            tenant_id = get_user_tenant_id(async_session, user)
        except Exception as e:
            logger.warning(f"Could not get tenant ID for user {user.id}: {str(e)}")
        
        user_data = {
            "sub": user.email,
            "user_id": str(user.id),
            "role": user.role.value,
        }
        
        if tenant_id:
            user_data["tenant_id"] = tenant_id
        
        return create_access_token(user_data)
    
    async def destroy_token(self, token: str, user: User) -> None:
        """
        JWT tokens are stateless - nothing to destroy on server side.
        Client should remove the token.
        """
        pass