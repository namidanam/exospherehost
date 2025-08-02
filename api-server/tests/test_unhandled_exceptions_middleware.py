import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from app.middlewares.unhandled_exceptions_middleware import UnhandledExceptionsMiddleware

# Endpoint that will always raise an error to test error handling
async def fail(request: Request):
    raise RuntimeError("boom")

# Endpoint for a healthy request
async def ok(request: Request):
    return JSONResponse({"ok": True})

@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(UnhandledExceptionsMiddleware)      # Only exception middleware
    app.add_api_route("/fail", fail, methods=["GET"])
    app.add_api_route("/ok", ok, methods=["GET"])
    return TestClient(app)

def test_exception_returns_expected_json(client):
    resp = client.get("/fail")
    assert resp.status_code == 500
    expected = {
        "detail": "Internal server error. Please contact the admin if this persists."
    }
    assert resp.json() == expected

def test_normal_request_passes_through(client):
    resp = client.get("/ok")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
