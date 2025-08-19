import types
import pytest
import os
import jwt
import datetime
from starlette.responses import JSONResponse
from bson.errors import InvalidId

from app.auth.controllers.refresh_access_token import (
    refresh_access_token,
    JWT_ALGORITHM,
    JWT_EXPIRES_IN
)
from app.auth.models.refresh_token_request import RefreshTokenRequest
from app.auth.models.token_response import TokenResponse
from app.auth.models.token_type_enum import TokenType
from app.user.models.verification_status_enum import VerificationStatusEnum
from app.user.models.user_status_enum import UserStatusEnum


@pytest.fixture
def dummy_user_cls():
    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def __init__(self, **overrides):
            for k, v in overrides.items():
                setattr(self, k, v)
    return DummyUser

def patch_user_get(monkeypatch, user_obj):
    async def mock_get(_):
        return user_obj
    MockUser = types.SimpleNamespace(get=staticmethod(mock_get))
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)


@pytest.mark.asyncio
async def test_refresh_access_token_success(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    class DummyProject:
        super_admin = type("SuperAdmin", (), {"ref": type("Ref", (), {"id": user.id})})()
        users = []
    class MockProject:
        @staticmethod
        async def get(_id):
            return DummyProject()
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, TokenResponse)


@pytest.mark.asyncio
async def test_refresh_access_token_invalid_project_id(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    class MockProject:
        @staticmethod
        async def get(_id):
            raise InvalidId("bad id")
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "badid",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 400
    assert "invalid project id" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_project_no_privilege(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    class DummyProject:
        super_admin = type("SuperAdmin", (), {"ref": type("Ref", (), {"id": "otherid"})})()
        users = []
    class MockProject:
        @staticmethod
        async def get(_id):
            return DummyProject()
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "does not have access" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_invalid_token_type(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    payload = {
        "user_id": user.id,
        "token_type": "access",  # Invalid type
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert "invalid token type" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_expired_token(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() - datetime.timedelta(seconds=10)).timestamp())  # Expired
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert "expired" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_user_not_found(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    async def mock_get(_):
        return None
    MockUser = types.SimpleNamespace(get=staticmethod(mock_get))
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)
    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert "user not found" in res.body.decode().lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["INACTIVE", "BLOCKED"])
async def test_refresh_access_token_denied_user_status(monkeypatch, dummy_user_cls, status):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls(status=status)
    patch_user_get(monkeypatch, user)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "inactive or blocked" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_project_not_found(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    class MockProject:
        @staticmethod
        async def get(_id):
            return None
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 404
    assert "project not found" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_project_load_exception(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    user = dummy_user_cls()
    patch_user_get(monkeypatch, user)
    class MockProject:
        @staticmethod
        async def get(_id):
            raise Exception("db error")
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": user.id,
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 500
    assert "internal server error" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_unhandled_exception(monkeypatch, dummy_user_cls):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    async def mock_get(_):
        raise Exception("unexpected error")
    MockUser = types.SimpleNamespace(get=staticmethod(mock_get))
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)
    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "project": "507f1f77bcf86cd799439012",
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 500
    assert "internal server error" in res.body.decode().lower()
