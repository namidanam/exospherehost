import uuid
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from app.middlewares.request_id_middleware import RequestIdMiddleware

# Minimal endpoint to test request ID logic
async def handler(request: Request):
    return JSONResponse({"msg": "ok"})

@pytest.fixture
def client():
    app = FastAPI()
    app.add_middleware(RequestIdMiddleware)      # Only the request ID middleware
    app.add_api_route("/test", handler, methods=["GET"])
    return TestClient(app)

def test_generates_uuid_when_missing(client):
    resp = client.get("/test")
    assert resp.status_code == 200
    rid = resp.headers["x-exosphere-request-id"]
    # Validate that a proper UUID was generated
    parsed_uuid = uuid.UUID(rid)
    assert str(parsed_uuid) == rid
    assert resp.json() == {"msg": "ok"}

def test_preserves_valid_id(client):
    valid_id = str(uuid.uuid4())
    resp = client.get("/test", headers={"x-exosphere-request-id": valid_id})
    assert resp.status_code == 200
    assert resp.headers["x-exosphere-request-id"] == valid_id

def test_replaces_invalid_id(client):
    resp = client.get("/test", headers={"x-exosphere-request-id": "bad-id"})
    assert resp.status_code == 200
    new_id = resp.headers["x-exosphere-request-id"]
    assert new_id != "bad-id"
    uuid.UUID(new_id)
