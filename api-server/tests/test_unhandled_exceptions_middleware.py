import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from app.middlewares.unhandled_exceptions_middleware import UnhandledExceptionsMiddleware

# Exception handlers to trigger different exceptions

async def fail(request: Request):
    raise RuntimeError("boom")

async def fail_value_error(request: Request):
    raise ValueError("Invalid value test")

async def fail_key_error(request: Request):
    raise KeyError("Missing key test")

async def ok(request: Request):
    return JSONResponse({"ok": True})

@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(UnhandledExceptionsMiddleware)
    app.add_api_route("/fail", fail, methods=["GET"])
    app.add_api_route("/fail_value_error", fail_value_error, methods=["GET"])
    app.add_api_route("/fail_key_error", fail_key_error, methods=["GET"])
    app.add_api_route("/ok", ok, methods=["GET"])
    return TestClient(app)

ERROR_RESPONSE = {
    "success": False,
    "detail": "internal server error, please reach out to support team at nivedit@exosphere.host"
}

def test_runtime_error_returns_expected_json(client):
    resp = client.get("/fail")
    assert resp.status_code == 500
    assert resp.json() == ERROR_RESPONSE

def test_value_error_returns_expected_json(client):
    resp = client.get("/fail_value_error")
    assert resp.status_code == 500
    assert resp.json() == ERROR_RESPONSE

def test_key_error_returns_expected_json(client):
    resp = client.get("/fail_key_error")
    assert resp.status_code == 500
    assert resp.json() == ERROR_RESPONSE

def test_normal_request_passes_through(client):
    resp = client.get("/ok")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
