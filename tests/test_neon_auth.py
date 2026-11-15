from __future__ import annotations

from datetime import datetime, timezone

import pytest

from api import database


class FakeConnection:
    def __init__(self, row=None, attempts=0):
        self.row = row or {
            "id": "00000000-0000-4000-8000-000000000001",
            "email": "analyst@example.com",
            "created_at": datetime.now(timezone.utc),
        }
        self.attempts = attempts
        self.calls = []
        self.exit_count = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.exit_count += 1
        return False

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "count(*) AS attempts" in sql:
            row = {"attempts": self.attempts}
        elif "SELECT id,email,password_hash" in sql:
            row = self.row
        else:
            row = self.row
        class Result:
            def __init__(self, value):
                self.row = value
            def fetchone(self):
                return self.row
            def fetchall(self):
                return [self.row] if self.row else []
        return Result(row)


def test_password_hash_is_salted_and_verified():
    first = database._hash_password("correct horse battery staple")
    second = database._hash_password("correct horse battery staple")
    assert first != second
    assert database._password_matches("correct horse battery staple", first)
    assert not database._password_matches("wrong password", first)


def test_signup_accepts_normal_email_and_normalizes_case(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "unit-test-secret-that-is-long-enough-123456")
    fake = FakeConnection()
    monkeypatch.setattr(database, "connect", lambda: fake)

    result = database.register_user("Analyst@example.com", "strong-password-123")

    assert result["user"]["email"] == "analyst@example.com"
    assert result["token_type"] == "bearer"
    sql, params = fake.calls[0]
    assert "INSERT INTO users" in sql
    assert params[0] == "analyst@example.com"
    assert params[1].startswith("pbkdf2_sha256$600000$")
    assert params[1] != "strong-password-123"


@pytest.mark.parametrize("email", ["not-an-email", "analyst @example.com", "analyst@example .com", "analyst@example"])
def test_signup_rejects_invalid_email(email):
    with pytest.raises(ValueError, match="valid email"):
        database.register_user(email, "strong-password-123")


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
    token = database._sign_token({"id": "00000000-0000-4000-8000-000000000001", "email": "a@example.com"})
    with pytest.raises(database.AuthError):
        database.verify_token(token + "tampered")


def test_missing_bearer_token_is_rejected():
    class Request:
        headers = {}
    with pytest.raises(database.AuthError):
        database.current_user_from_request(Request())


def test_failed_login_attempt_is_committed_before_error(monkeypatch):
    row = {
        "id": "00000000-0000-4000-8000-000000000001",
        "email": "analyst@example.com",
        "password_hash": database._hash_password("correct-password"),
        "created_at": datetime.now(timezone.utc),
    }
    fake = FakeConnection(row=row)
    monkeypatch.setattr(database, "connect", lambda: fake)

    with pytest.raises(database.AuthError, match="incorrect"):
        database.login_user("analyst@example.com", "wrong-password")

    sql = [statement for statement, _ in fake.calls]
    assert any("INSERT INTO auth_rate_limits" in statement for statement in sql)
    assert fake.exit_count == 1  # The transaction exits normally before AuthError is raised.


def test_login_rate_limit_stops_after_ten_attempts(monkeypatch):
    fake = FakeConnection(attempts=10)
    monkeypatch.setattr(database, "connect", lambda: fake)

    with pytest.raises(database.AuthError, match="Too many"):
        database.login_user("analyst@example.com", "wrong-password")

    assert not any("INSERT INTO auth_rate_limits" in statement for statement, _ in fake.calls)


def test_successful_login_clears_failed_attempts_and_returns_token(monkeypatch):
    monkeypatch.setenv("AUTH_SECRET", "unit-test-secret-that-is-long-enough-123456")
    row = {
        "id": "00000000-0000-4000-8000-000000000001",
        "email": "analyst@example.com",
        "password_hash": database._hash_password("correct-password"),
        "created_at": datetime.now(timezone.utc),
    }
    fake = FakeConnection(row=row)
    monkeypatch.setattr(database, "connect", lambda: fake)

    result = database.login_user("analyst@example.com", "correct-password")

    assert result["user"]["email"] == "analyst@example.com"
    assert result["token_type"] == "bearer"
    assert sum("DELETE FROM auth_rate_limits WHERE email_hash" in sql for sql, _ in fake.calls) == 1
    assert fake.exit_count == 2


def test_insert_rows_uses_server_resolved_tenant(monkeypatch):
    fake = FakeConnection()
    monkeypatch.setattr(database, "connect", lambda: fake)
    result = database.insert_rows("flow_analysis_events", [{"source": "single_flow", "action": "ALLOW"}], "00000000-0000-4000-8000-000000000001")
    assert result["stored"] is True
    assert result["backend"] == "neon_postgres"
    sql, params = fake.calls[0]
    assert "audit_events" in sql
    assert params[0] == "00000000-0000-4000-8000-000000000001"
    assert params[1] == "flow_analysis_events"


def test_insert_rows_rejects_unknown_table():
    result = database.insert_rows("users", [{"email": "attacker@example.com"}], "00000000-0000-4000-8000-000000000001")
    assert result == {"stored": False, "reason": "table_not_allowed"}
