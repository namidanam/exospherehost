import os
import jwt
from datetime import datetime, timedelta
from starlette.responses import JSONResponse
from bson import ObjectId
from typing import Union
from bson.errors import InvalidId

from ..models.refresh_token_request import RefreshTokenRequest
from ..models.token_response import TokenResponse
from ..models.token_claims import TokenClaims
from ..models.token_type_enum import TokenType

from app.singletons.logs_manager import LogsManager

from app.user.models.user_database_model import User
from app.project.models.project_database_model import Project
from app.auth.constants import DENIED_USER_STATUSES

logger = LogsManager().get_logger()

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

JWT_ALGORITHM = "HS256"
JWT_EXPIRES_IN = 3600 # 1 hour


async def refresh_access_token(
    request: RefreshTokenRequest, 
    x_exosphere_request_id: str
) -> Union[TokenResponse, JSONResponse]:
    """
    New endpoint that takes refresh token and returns new access token
    """
    if not JWT_SECRET_KEY:
        logger.error("JWT secret missing", x_exosphere_request_id=x_exosphere_request_id)
        return JSONResponse(status_code=500, content={"success": False, "detail": "Internal server error"})
    try:
        # Decode refresh token
        payload = jwt.decode(
            request.refresh_token, 
            JWT_SECRET_KEY, 
            algorithms=[JWT_ALGORITHM]
        )
        
        # Verify it's a refresh token
        if payload.get("token_type") != TokenType.refresh.value:
            return JSONResponse(
                status_code=401, 
                content={"success": False, "detail": "Invalid token type"}
            )
        
        # Get user and check if denied
        user = await User.get(ObjectId(payload["user_id"]))
        
        if not user:
            return JSONResponse(
                status_code=401,
                content={"success": False, "detail": "User not found"}
            )
            
        # Deny users with statuses in DENIED_USER_STATUSES
        status = getattr(user, "status", None)
        status_value = getattr(status, "value", status)
        if status_value in DENIED_USER_STATUSES:
            logger.warning(
                f"Inactive or blocked user attempted token refresh: {user.id}",
                x_exosphere_request_id=x_exosphere_request_id
            )
            return JSONResponse(
                status_code=403,
                content={"success": False, "detail": "User account is inactive or blocked"}
            )
        previlage = None
        project_id = payload.get("project")
        if project_id:
            try:
                project = await Project.get(ObjectId(project_id))
            except InvalidId:
                logger.error("Invalid project id", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=400, content={"success": False, "detail": "Invalid project id"})
            if not project:
                logger.error("Project not found", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=404, content={"success": False, "detail": "Project not found"})
            logger.info("Project found", x_exosphere_request_id=x_exosphere_request_id)
            if project.super_admin.ref.id == user.id:
                previlage = "super_admin"
            for project_user in project.users:
                if project_user.user.ref.id == user.id:
                    previlage = project_user.permission.value
                    break
            if not previlage:
                logger.error("User does not have access to the project", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=403, content={"success": False, "detail": "User does not have access to the project"})
        # Create new access token with fresh user data
        token_claims = TokenClaims(
            user_id=str(user.id),
            user_name=user.name,
            user_type=user.type,
            verification_status=user.verification_status,
            status=status_value,
            project=project_id,  
            previlage=previlage,  
            satellites=payload.get("satellites"),
            exp=int((datetime.now() + timedelta(seconds=JWT_EXPIRES_IN)).timestamp()),
            token_type=TokenType.access.value
        )
        
        new_access_token = jwt.encode(
            token_claims.model_dump(), 
            JWT_SECRET_KEY, 
            algorithm=JWT_ALGORITHM
        )
        
        # Return ONLY new access token (not a new refresh token)
        return TokenResponse(
            access_token=new_access_token
        )
        
    except jwt.ExpiredSignatureError:
        return JSONResponse(
            status_code=401,
            content={"detail": "Refresh token expired"}
        )
    except Exception as e:
        logger.error(
            "Error refreshing token", 
            error=e, 
            x_exosphere_request_id=x_exosphere_request_id
        )
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )