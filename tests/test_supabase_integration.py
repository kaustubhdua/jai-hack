import json

from fastapi.testclient import TestClient
from starlette.requests import Request

from api import index


def test_private_history_requires_supabase_auth_when_configured(monkeypatch):
    monkeypatch.setattr(index, "_supabase_public_key", lambda: "sb_publishable_test")
    monkeypatch.setattr(index, "_supabase_user_id", lambda request: (None, "not_authenticated"))

    response = TestClient(index.app).get("/api/history")

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_REQUIRED"


def test_supabase_insert_uses_verified_user_and_user_jwt(monkeypatch):
    calls = []

    class FakeResponse:
        status = 201

        def read(self):
            return b""

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, body=None, headers=None):
            calls.append({"method": method, "path": path, "body": body, "headers": headers})

        def getresponse(self):
            return FakeResponse()

        def close(self):
            pass

    monkeypatch.setattr(index, "_supabase_public_key", lambda: "sb_publishable_test")
    monkeypatch.setattr(index, "_supabase_user_id", lambda request: ("00000000-0000-4000-8000-000000000001", None))
    monkeypatch.setattr(index.http.client, "HTTPSConnection", FakeConnection)
    request = Request({
        "type": "http",
        "headers": [(b"authorization", b"Bearer signed-user-jwt")],
        "method": "POST",
        "path": "/api/analyze",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 123),
        "scheme": "http",
        "http_version": "1.1",
    })

    result = index._supabase_insert_rows("flow_analysis_events", [{"source": "single_flow", "action": "ALLOW"}], request)

    assert result == {"stored": True, "backend": "supabase", "rows": 1}
    assert len(calls) == 1
    assert calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/rest/v1/flow_analysis_events"
    assert calls[0]["headers"]["apikey"] == "sb_publishable_test"
    assert calls[0]["headers"]["Authorization"] == "Bearer signed-user-jwt"
    assert json.loads(calls[0]["body"])[0]["user_id"] == "00000000-0000-4000-8000-000000000001"
