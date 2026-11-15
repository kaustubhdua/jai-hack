-- Cover the composite tenant-ownership foreign keys added in 002.
-- Leading with run_id supports FK checks when a parent replay run is deleted.
CREATE INDEX IF NOT EXISTS replay_decisions_run_user_fk_idx
  ON cybersentinel.replay_decisions (run_id, user_id);
CREATE INDEX IF NOT EXISTS replay_policies_run_user_fk_idx
  ON cybersentinel.replay_policies (run_id, user_id);
CREATE INDEX IF NOT EXISTS replay_correlation_groups_run_user_fk_idx
  ON cybersentinel.replay_correlation_groups (run_id, user_id);

INSERT INTO cybersentinel.schema_migrations (version, name)
VALUES ('20261115013000', 'index_replay_child_tenant_foreign_keys')
ON CONFLICT (version) DO NOTHING;
