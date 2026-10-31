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


def test_replay_artifacts_include_policies_and_correlation_groups(monkeypatch):
    writes = []

    def fake_insert(table, rows, request):
        writes.append((table, rows))
        return {"stored": True, "rows": len(rows)}

    monkeypatch.setattr(index, "_supabase_insert_rows", fake_insert)
    request = Request({
        "type": "http",
        "headers": [(b"authorization", b"Bearer signed-user-jwt")],
        "method": "POST",
        "path": "/api/replay/simulate",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 123),
        "scheme": "http",
        "http_version": "1.1",
    })
    results = {
        "classification_rows": [{
            "record_id": "flow-001", "predicted_class": "DOS",
            "anomaly_score": 0.91, "evidence_status": "AGREE",
        }],
        "replay_rows": [{"action": "BLOCK", "active_policy_id": "POL-001"}],
        "policy_rows": [{
            "policy_id": "POL-001", "activated_after_record_id": "flow-001",
            "scope_type": "SOURCE_IP", "scope_value": "192.0.2.1",
            "expires_after_record_id": "flow-010",
        }],
    }
    groups = [{
        "group_id": "GRP-001", "attack_type": "DOS", "source_identity": "192.0.2.1",
        "target_endpoints": ["198.51.100.4:443"], "member_record_ids": ["flow-001"],
        "flow_count": 1, "start_record_id": "flow-001", "end_record_id": "flow-001",
        "confidence": 0.88, "evidence": ["repeated_source"],
    }]

    outcome = index._persist_replay_artifacts(results, "RUN-TEST", request, groups)

    assert outcome["stored"] is True
    assert outcome["decisions_saved"] == 1
    assert outcome["policies_saved"] == 1
    assert outcome["correlation_groups_saved"] == 1
    assert [table for table, _ in writes] == [
        "replay_decisions", "replay_policies", "replay_correlation_groups"
    ]


def test_supabase_select_rows_uses_user_jwt_and_allowlisted_table(monkeypatch):
    calls = []

    class FakeResponse:
        status = 200

        def read(self):
            return b'[{"group_id":"GRP-001"}]'

    class FakeConnection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, method, path, body=None, headers=None):
            calls.append({"method": method, "path": path, "headers": headers})

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
        "method": "GET",
        "path": "/api/correlation/groups",
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 123),
        "scheme": "http",
        "http_version": "1.1",
    })

    result = index._supabase_select_rows("replay_correlation_groups", "select=group_id&limit=5", request)
    denied = index._supabase_select_rows("users", "select=*", request)

    assert result == {"stored": True, "rows": [{"group_id": "GRP-001"}]}
    assert denied["stored"] is False
    assert denied["reason"] == "table_not_allowed"
    assert calls[0]["method"] == "GET"
    assert calls[0]["path"] == "/rest/v1/replay_correlation_groups?select=group_id&limit=5"
    assert calls[0]["headers"]["Authorization"] == "Bearer signed-user-jwt"
