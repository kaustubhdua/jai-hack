"""Offline parsers for Zeek TSV, Suricata EVE JSONL, and Wazuh alerts JSON."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pandas as pd


def load_zeek_conn(path: str | Path) -> pd.DataFrame:
    """Read Zeek conn.log using its #fields metadata (tab-separated)."""
    fields: list[str] | None = None
    rows: list[list[str]] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#") or not line:
                continue
            else:
                if fields is None:
                    raise ValueError("Zeek log is missing its #fields header.")
                rows.append(line.split("\t"))
    if fields is None:
        raise ValueError("Zeek log is missing its #fields header.")
    if any(len(row) != len(fields) for row in rows):
        raise ValueError("Zeek log contains rows that do not match the #fields schema.")
    return pd.DataFrame(rows, columns=fields).replace("-", pd.NA)


def load_suricata_eve(path: str | Path) -> pd.DataFrame:
    """Load Suricata EVE JSON Lines; retain event type and alert metadata."""
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid Suricata JSON on line {line_number}.") from exc
            alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
            rows.append({
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "source_ip": event.get("src_ip"),
                "source_port": event.get("src_port"),
                "destination_ip": event.get("dest_ip"),
                "destination_port": event.get("dest_port"),
                "protocol": event.get("proto"),
                "signature": alert.get("signature"),
                "signature_id": alert.get("signature_id"),
                "severity": alert.get("severity"),
                "category": alert.get("category"),
            })
    return pd.DataFrame(rows)


def load_wazuh_alerts(path: str | Path) -> pd.DataFrame:
    """Load Wazuh JSON alert export; supports a single object or an alerts list."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Wazuh export must be valid JSON.") from exc
    alerts = (payload.get("alerts") if "alerts" in payload else [payload]) if isinstance(payload, dict) else payload
    if not isinstance(alerts, list):
        raise ValueError("Wazuh JSON must be an array or an object with an alerts array.")
    rows = []
    for alert in alerts:
        if not isinstance(alert, dict):
            continue
        agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
        rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
        data = alert.get("data") if isinstance(alert.get("data"), dict) else {}
        rows.append({
            "timestamp": alert.get("timestamp"),
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "source_ip": data.get("srcip"),
            "destination_ip": data.get("dstip"),
            "full_log": alert.get("full_log"),
        })
    return pd.DataFrame(rows)


def load_sigma_rule(path: str | Path) -> dict[str, Any]:
    """Parse one Sigma YAML rule as structured metadata; no rule execution occurs."""
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Install optional YAML support: pip install .[integrations]") from exc
    payload = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("detection"), dict):
        raise ValueError("Sigma rule must contain a detection mapping.")
    return {
        "title": payload.get("title"),
        "id": payload.get("id"),
        "status": payload.get("status"),
        "level": payload.get("level"),
        "description": payload.get("description"),
        "logsource": payload.get("logsource", {}),
        "detection": payload["detection"],
        "tags": payload.get("tags", []),
        "source_path": str(Path(path)),
        "execution": "not_executed",
    }
