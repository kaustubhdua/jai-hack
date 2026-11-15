from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "database" / "cybersentinel"


def test_replay_child_tables_are_bound_to_their_run_owner():
    migration = (MIGRATIONS / "002_replay_owner_integrity.sql").read_text(
        encoding="utf-8"
    )

    assert "UNIQUE (run_id, user_id)" in migration
    for table in (
        "replay_decisions",
        "replay_policies",
        "replay_correlation_groups",
    ):
        assert f"ALTER TABLE cybersentinel.{table}" in migration
        assert "FOREIGN KEY (run_id, user_id)" in migration
        assert "REFERENCES cybersentinel.replay_runs (run_id, user_id)" in migration

    assert "bharatsim." not in migration
    assert "genomeguard." not in migration


def test_replay_child_tenant_foreign_keys_have_covering_indexes():
    migration = (MIGRATIONS / "003_replay_fk_indexes.sql").read_text(
        encoding="utf-8"
    )

    expected = {
        "replay_decisions": "replay_decisions_run_user_fk_idx",
        "replay_policies": "replay_policies_run_user_fk_idx",
        "replay_correlation_groups": "replay_correlation_groups_run_user_fk_idx",
    }
    for table, index in expected.items():
        assert f"CREATE INDEX IF NOT EXISTS {index}" in migration
        assert f"ON cybersentinel.{table} (run_id, user_id)" in migration

    assert "bharatsim." not in migration
    assert "genomeguard." not in migration
