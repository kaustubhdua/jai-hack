-- Ensure replay child records can only reference a run owned by the same user.
-- RLS already scopes each row by user_id; composite foreign keys also prevent
-- cross-tenant references if a caller guesses another tenant's run_id.

BEGIN;

ALTER TABLE cybersentinel.replay_runs
  ADD CONSTRAINT replay_runs_run_user_unique UNIQUE (run_id, user_id);

ALTER TABLE cybersentinel.replay_decisions
  ADD CONSTRAINT replay_decisions_run_user_fkey
  FOREIGN KEY (run_id, user_id)
  REFERENCES cybersentinel.replay_runs (run_id, user_id)
  ON DELETE CASCADE;

ALTER TABLE cybersentinel.replay_policies
  ADD CONSTRAINT replay_policies_run_user_fkey
  FOREIGN KEY (run_id, user_id)
  REFERENCES cybersentinel.replay_runs (run_id, user_id)
  ON DELETE CASCADE;

ALTER TABLE cybersentinel.replay_correlation_groups
  ADD CONSTRAINT replay_correlation_groups_run_user_fkey
  FOREIGN KEY (run_id, user_id)
  REFERENCES cybersentinel.replay_runs (run_id, user_id)
  ON DELETE CASCADE;

ALTER TABLE cybersentinel.replay_decisions
  DROP CONSTRAINT replay_decisions_run_id_fkey;
ALTER TABLE cybersentinel.replay_policies
  DROP CONSTRAINT replay_policies_run_id_fkey;
ALTER TABLE cybersentinel.replay_correlation_groups
  DROP CONSTRAINT replay_correlation_groups_run_id_fkey;

INSERT INTO cybersentinel.schema_migrations (version, name)
VALUES ('20261115010413', 'replay_child_records_require_matching_run_owner')
ON CONFLICT (version) DO NOTHING;

COMMIT;
