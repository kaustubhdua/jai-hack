"""Guardrails for the public, Supabase-free CyberSentinel distribution."""
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_distribution_has_no_supabase_project_or_environment_template():
    assert not (ROOT / "supabase").exists()
    assert not (ROOT / ".env.example").exists()


def test_frontend_dependencies_do_not_include_supabase():
    package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    dependencies = {
        **package.get("dependencies", {}),
        **package.get("devDependencies", {}),
    }
    assert not any(name.lower().startswith("@supabase/") for name in dependencies)


def test_browser_api_client_does_not_require_identity_or_backend_tokens():
    client = (ROOT / "src" / "lib" / "api.ts").read_text(encoding="utf-8").lower()
    assert "authorization" not in client
    assert "supabase" not in client
