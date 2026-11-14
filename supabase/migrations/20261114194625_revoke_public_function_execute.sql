-- PostgreSQL grants EXECUTE on new functions to PUBLIC globally by default.
-- Revoke that global default for the migration role; per-schema revokes cannot
-- remove a privilege inherited from the global default ACL.
ALTER DEFAULT PRIVILEGES
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
