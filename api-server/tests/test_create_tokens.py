import os
import jwt
import pytest
from starlette.responses import JSONResponse

from app.auth.controllers.create_token import create_token, JWT_SECRET_KEY, JWT_ALGORITHM
from app.auth.models.token_request import TokenRequest
from app.auth.models.token_response import TokenResponse
from app.user.models.user_status_enum import UserStatusEnum
from app.user.models.verification_status_enum import VerificationStatusEnum


@pytest.mark.asyncio
async def test_create_token_success(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    # Patch the module variable directly
    monkeypatch.setattr("app.auth.controllers.create_token.JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="user", credential="pass", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, TokenResponse)
    decoded = jwt.decode(res.access_token, os.getenv("JWT_SECRET_KEY"), algorithms=[JWT_ALGORITHM])
    assert decoded["user_id"] == "507f1f77bcf86cd799439011"
    assert decoded["token_type"] == "access"


@pytest.mark.asyncio
async def test_create_token_invalid_user(monkeypatch):
    async def mock_find_one(_query):
        return None

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="bad", credential="pass", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_create_token_invalid_credential(monkeypatch):
    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return False

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="user", credential="wrong", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("status_value", ["INACTIVE", "BLOCKED"])
async def test_create_token_inactive_blocked_user(monkeypatch, status_value):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    monkeypatch.setattr("app.auth.controllers.create_token.JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        def __init__(self, status):
            self.status = status
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser(status_value)

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="user", credential="pass", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "inactive or blocked" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_create_token_unverified_user(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")
    monkeypatch.setattr("app.auth.controllers.create_token.JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = "NOT_VERIFIED"
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="user", credential="pass", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "not verified" in res.body.decode().lower()


@pytest.mark.asyncio
async def test_create_token_missing_jwt_secret(monkeypatch):
    # Patch the module variable directly to None
    monkeypatch.setattr("app.auth.controllers.create_token.JWT_SECRET_KEY", None)

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)

    req = TokenRequest(identifier="user", credential="pass", project=None, satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 500


@pytest.mark.asyncio
async def test_create_token_invalid_project_id(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    class MockProject:
        @staticmethod
        async def get(_id):
            raise Exception("InvalidId")

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.create_token.Project", MockProject)

    req = TokenRequest(identifier="user", credential="pass", project="badid", satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code in (400, 500)


@pytest.mark.asyncio
async def test_create_token_project_not_found(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    class MockProject:
        @staticmethod
        async def get(_id):
            return None

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.create_token.Project", MockProject)

    req = TokenRequest(identifier="user", credential="pass", project="507f1f77bcf86cd799439012", satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_create_token_project_no_privilege(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", "test_secret")

    class DummyUser:
        id = "507f1f77bcf86cd799439011"
        name = "John"
        type = "admin"
        verification_status = VerificationStatusEnum.VERIFIED.value
        status = UserStatusEnum.ACTIVE.value
        def verify_credential(self, cred):
            return True

    async def mock_find_one(_query):
        return DummyUser()

    class MockUser:
        identifier = "identifier"
        find_one = staticmethod(mock_find_one)

    class DummyProject:
        super_admin = type("SuperAdmin", (), {"ref": type("Ref", (), {"id": "otherid"})})()
        users = []

    class MockProject:
        @staticmethod
        async def get(_id):
            return DummyProject()

    monkeypatch.setattr("app.auth.controllers.create_token.User", MockUser)
    monkeypatch.setattr("app.auth.controllers.create_token.Project", MockProject)

    req = TokenRequest(identifier="user", credential="pass", project="507f1f77bcf86cd799439012", satellites=None)
    res = await create_token(req, "req-id")

    assert isinstance(res, JSONResponse)
    assert res.status_code == 403
    assert "does not have access" in res.body.decode().lower()
