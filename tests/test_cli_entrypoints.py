"""Smoke tests for documented Python command-line entry points."""
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def test_combined_training_script_help_runs_from_repository_root():
    result = subprocess.run(
        [sys.executable, "scripts/train_models.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "--train" in result.stdout
    assert "--model-dir" in result.stdout
