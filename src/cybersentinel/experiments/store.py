"""Local-only experiment history; no hosted database is used."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class ExperimentStore:
    def __init__(self, database: str | Path = "data/experiments.sqlite3"):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS experiments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    manifest_json TEXT NOT NULL
                )
            """)

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def add(self, name: str, status: str, manifest: dict[str, Any]) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT INTO experiments(name,status,manifest_json) VALUES(?,?,?)",
                (name, status, json.dumps(manifest, default=str)),
            )
            return int(cursor.lastrowid)

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        if not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id,created_at,name,status,manifest_json FROM experiments ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [{**dict(row), "manifest": json.loads(row["manifest_json"])} for row in rows]
