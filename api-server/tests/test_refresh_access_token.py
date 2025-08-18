import os
import jwt
import pytest
import datetime
from starlette.responses import JSONResponse

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


@pytest.mark.asyncio
async def test_refresh_access_token_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = "ACTIVE"

    class MockUser:
        @staticmethod
        async def get(_id):
            return DummyUser()

    class MockProject:
        @staticmethod
        async def get(_id):
            return None

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)
    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")

    assert isinstance(res, TokenResponse)
    decoded = jwt.decode(res.access_token, os.getenv("JWT_SECRET_KEY"), algorithms=[JWT_ALGORITHM])
    assert decoded["user_id"] == "507f1f77bcf86cd799439011"
    assert decoded["token_type"] == "access"


@pytest.mark.asyncio
async def test_refresh_access_token_invalid_token(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    bad_token = jwt.encode({"token_type": "wrong"}, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=bad_token)
    res = await refresh_access_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_refresh_access_token_expired(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    expired_time = int((datetime.datetime.now() - datetime.timedelta(seconds=10)).timestamp())
    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "exp": expired_time
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)

    class MockUser:
        @staticmethod
        async def get(_id):
            pytest.fail("Should not call User.get for expired token")

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)

    res = await refresh_access_token(req, "req-id")
    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert "expired" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_user_not_found(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class MockUser:
        @staticmethod
        async def get(_id):
            return None

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)

    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 401
    assert "not found" in res.body.decode().lower()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["INACTIVE", "BLOCKED"])
async def test_refresh_access_token_inactive_blocked_user(monkeypatch, status):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        def __init__(self, status):
            self.status = status

    class MockUser:
        @staticmethod
        async def get(_id):
            return DummyUser(status)

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)

    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    res = await refresh_access_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "inactive or blocked" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_project_not_found(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value

    class MockUser:
        @staticmethod
        async def get(_id):
            return DummyUser()

    class MockProject:
        @staticmethod
        async def get(_id):
            return None

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)

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
    assert res.status_code == 404
    assert "project not found" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_project_no_privilege(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value

    class MockUser:
        @staticmethod
        async def get(_id):
            return DummyUser()

    class DummyProject:
        super_admin = type("SuperAdmin", (), {"ref": type("Ref", (), {"id": "otherid"})})()
        users = []

    class MockProject:
        @staticmethod
        async def get(_id):
            return DummyProject()

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.Project", MockProject)

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
    assert res.status_code == 403
    assert "does not have access" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_refresh_access_token_unhandled_exception(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    monkeypatch.setattr("app.auth.controllers.refresh_access_token.JWT_SECRET_KEY", "test_secret")

    class MockUser:
        @staticmethod
        async def get(_id):
            raise Exception("Some DB error")

    monkeypatch.setattr("app.auth.controllers.refresh_access_token.User", MockUser)

    payload = {
        "user_id": "507f1f77bcf86cd799439011",
        "token_type": TokenType.refresh.value,
        "exp": int((datetime.datetime.now() + datetime.timedelta(seconds=JWT_EXPIRES_IN)).timestamp())
    }
    token = jwt.encode(payload, os.getenv("JWT_SECRET_KEY"), algorithm=JWT_ALGORITHM)
    req = RefreshTokenRequest(refresh_token=token)
    try:
        res = await refresh_access_token(req, "req-id")
    except Exception as e:
        assert str(e) == "Some DB error"
    else:
        # If no exception, should return None (for coverage)
        assert res is None