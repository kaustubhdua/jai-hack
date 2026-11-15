from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api import database


class FakeConnection:
    def __init__(self, row=None):
        self.row = row or {"id": "00000000-0000-0000-0000-000000000001", "email": "analyst@example.com", "created_at": datetime.now(timezone.utc)}
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        class Result:
            def __init__(self, row): self.row = row
            def fetchone(self): return self.row
            def fetchall(self): return [self.row] if self.row else []
        return Result(self.row)


def test_password_hash_is_salted_and_verified():
    first = database._hash_password("correct horse battery staple")
    second = database._hash_password("correct horse battery staple")
    assert first != second
    assert database._password_matches("correct horse battery staple", first)
    assert not database._password_matches("wrong password", first)


def test_signed_token_resolves_database_user(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "unit-test-secret-that-is-long-enough-123456")
    fake = FakeConnection()
    monkeypatch.setattr(database, "connect", lambda: fake)
    token = database._sign_token({"id": fake.row["id"], "email": fake.row["email"]})
    user = database.verify_token(token)
    assert user["id"] == fake.row["id"]
    assert user["email"] == fake.row["email"]
    assert "password_hash" not in user


def test_tampered_token_is_rejected_before_database_access(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "unit-test-secret-that-is-long-enough-123456")
    token = database._sign_token({"id": "00000000-0000-0000-0000-000000000001", "email": "a@example.com"})
    with pytest.raises(database.AuthError):
        database.verify_token(token + "tampered")


def test_missing_bearer_token_is_rejected():
    class Request:
        headers = {}
    with pytest.raises(database.AuthError):
        database.current_user_from_request(Request())


def test_insert_rows_uses_server_resolved_tenant(monkeypatch):
    fake = FakeConnection()
    monkeypatch.setattr(database, "connect", lambda: fake)
    result = database.insert_rows("flow_analysis_events", [{"source": "single_flow", "action": "ALLOW"}], "00000000-0000-0000-0000-000000000001")
    assert result["stored"] is True
    assert result["backend"] == "neon_postgres"
    sql, params = fake.calls[0]
    assert "audit_events" in sql
    assert params[0] == "00000000-0000-0000-0000-000000000001"
    assert params[1] == "flow_analysis_events"


def test_insert_rows_rejects_unknown_table():
    result = database.insert_rows("users", [{"email": "attacker@example.com"}], "00000000-0000-0000-0000-000000000001")
    assert result == {"stored": False, "reason": "table_not_allowed"}
