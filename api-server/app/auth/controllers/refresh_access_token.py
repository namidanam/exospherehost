import os
import jwt
from datetime import datetime, timedelta
from starlette.responses import JSONResponse
from bson import ObjectId
from typing import Union
from bson.errors import InvalidId
from typing import Union,Optional 


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
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY environment variable is not set or is empty")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_IN = 3600 # 1 hour


async def refresh_access_token(
    request: RefreshTokenRequest, 
    x_exosphere_request_id: Optional[str]
) -> Union[TokenResponse, JSONResponse]:
    """
    New endpoint that takes refresh token and returns new access token
    """
    try:
        secret = os.getenv("JWT_SECRET_KEY") or JWT_SECRET_KEY
        payload = jwt.decode(request.refresh_token, secret, algorithms=[JWT_ALGORITHM])
        
        # Verify it's a refresh token
        if payload.get("token_type") != TokenType.refresh.value:
            return JSONResponse(
                status_code=401, 
                content={"success": False, "detail": "Invalid token type"}
            )
        
        # Get user and check if denied
        try:
            user_oid = ObjectId(payload["user_id"])
        except (InvalidId, KeyError, TypeError):
            return JSONResponse(status_code=401, content={"success": False, "detail": "Invalid token"})
        user = await User.get(user_oid)

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
        project = None
        if payload.get("project"):
            try:
                project = await Project.get(ObjectId(payload.get("project")))
            except InvalidId:
                logger.error("Invalid project id", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=400, content={"success": False, "detail": "Invalid project id"})
            except Exception as e:
                logger.error("Error loading project", error=e, x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=500, content={"success": False, "detail": "Internal server error"})
            if not project:
                logger.error("Project not found", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=404, content={"success": False, "detail": "Project not found"})

        privilage = None
        if project:
            if project.super_admin.ref.id == user.id:
                privilage = "super_admin"
            else:
                for project_user in getattr(project, "users", []):
                    if getattr(getattr(project_user, "user", None), "ref", None) and getattr(project_user.user.ref, "id", None) == user.id:
                        perm = getattr(project_user, "permission", None)
                        previlage = getattr(perm, "value", perm)
                        break
            if not privilage:
                logger.error("User does not have access to the project", x_exosphere_request_id=x_exosphere_request_id)
                return JSONResponse(status_code=403, content={"success": False, "detail": "User does not have access to the project"})
        # Create new access token with fresh user data
        vstatus = getattr(user, "verification_status", None)
        vstatus_value = getattr(vstatus, "value", vstatus)
        token_claims = TokenClaims(
            user_id=str(user.id),
            user_name=user.name,
            user_type=user.type,
            verification_status=vstatus_value,
            status=status_value,
            project=payload.get("project"),
            privilage=privilage,
            satellites=payload.get("satellites"),
            exp=int((datetime.now() + timedelta(seconds=JWT_EXPIRES_IN)).timestamp()),
            token_type=TokenType.access.value
            )

        new_access_token = jwt.encode(token_claims.model_dump(), secret, algorithm=JWT_ALGORITHM)

        # Return ONLY new access token (not a new refresh token)
        return TokenResponse(
            access_token=new_access_token
        )
        
    except jwt.ExpiredSignatureError:
        return JSONResponse(
            status_code=401,
            content={"success": False, "detail": "Refresh token expired"}
        )
    except jwt.InvalidTokenError:
        return JSONResponse(
            status_code=401,
            content={"success": False, "detail": "Invalid token"}
        )
    except Exception as e:
        logger.error(
            "Error refreshing token", 
            error=e, 
            x_exosphere_request_id=x_exosphere_request_id
        )
        return JSONResponse(
            status_code=500,
            content={'success': False, 'detail': 'Internal server error'}
        )