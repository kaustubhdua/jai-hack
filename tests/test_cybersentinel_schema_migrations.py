from pathlib import Path


def test_replay_child_tables_are_bound_to_their_run_owner():
    migration = (
        Path(__file__).resolve().parents[1]
        / "database"
        / "cybersentinel"
        / "002_replay_owner_integrity.sql"
    ).read_text(encoding="utf-8")

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
