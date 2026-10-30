"""Temporal Correlation Agent (Agent 4).

Groups related suspicious flows using observed endpoints and time windows.
Emits group IDs, member records, and explicit supporting evidence.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
import hashlib
from datetime import datetime
from typing import Any
import pandas as pd

from cybersentinel.contracts import CorrelationGroup, CorrelationResult


class TemporalCorrelationAgent:
    """Correlate suspicious network flows across sliding time or sequence windows."""

    def __init__(self, window_size: int = 150, window_seconds: int = 300):
        if window_size < 1 or window_seconds < 1:
            raise ValueError("window_size and window_seconds must be positive")
        self.window_size = window_size
        self.window_seconds = window_seconds
        self.history: deque[dict[str, Any]] = deque()
        self.source_port_counts: defaultdict[str, Counter[int]] = defaultdict(Counter)
        self.dest_source_counts: defaultdict[str, Counter[str]] = defaultdict(Counter)
        self.active_groups: dict[str, CorrelationGroup] = {}
        self.group_counter = 0

    def reset(self) -> None:
        """Reset historical sliding window."""
        self.history.clear()
        self.source_port_counts.clear()
        self.dest_source_counts.clear()
        self.active_groups.clear()
        self.group_counter = 0

    @property
    def source_port_map(self) -> dict[str, set[int]]:
        """Active window source-to-ports mapping for inspection."""
        return {k: set(v.keys()) for k, v in self.source_port_counts.items()}

    @property
    def dest_source_map(self) -> dict[str, set[str]]:
        """Active window dest-to-sources mapping for inspection."""
        return {k: set(v.keys()) for k, v in self.dest_source_counts.items()}

    @staticmethod
    def derive_source_identity(flow: dict[str, Any]) -> str:
        """Return a native source IP or a disclosed stable TCP-stack-derived identity.

        No identity is invented from destination ports or per-flow counters. If the
        required fingerprint fields are unavailable, return an empty string so the
        defense agent cannot create an over-broad policy.
        """
        for key in ("source_ip", "Source IP", "src_ip", "src", "Source_IP"):
            value = flow.get(key)
            if value is not None and str(value).strip():
                return str(value).strip()

        fingerprint_fields = ("Init_Win_bytes_forward", "min_seg_size_forward", "Fwd Header Length")
        values = [flow.get(key) for key in fingerprint_fields]
        if any(value is None or str(value).strip() in {"", "nan", "None"} for value in values):
            return ""
        seed = "|".join(str(value).strip() for value in values)
        digest = hashlib.sha256(seed.encode("utf-8")).digest()
        # RFC1918-shaped synthetic identity, not a native or observed IP address.
        return f"10.{digest[0]}.{digest[1]}.{digest[2]}"

    @staticmethod
    def extract_endpoints(flow: dict[str, Any]) -> tuple[str, str, int]:
        """Extract observed endpoints; only source identity may be derived."""
        src_ip = TemporalCorrelationAgent.derive_source_identity(flow)

        dst_ip = None
        for key in ("destination_ip", "Destination IP", "dst_ip", "dst", "Destination_IP"):
            value = flow.get(key)
            if value is not None and str(value).strip():
                dst_ip = str(value).strip()
                break
        # Destination is intentionally left unknown when the dataset omits it.
        dport_value = flow.get("Destination Port", 0)
        try:
            dport = int(dport_value)
        except (TypeError, ValueError):
            dport = 0
        return src_ip, dst_ip or "", dport

    @staticmethod
    def _parse_timestamp(flow: dict[str, Any]) -> datetime | None:
        for key in ("Timestamp", "timestamp", "Flow Start", "flow_start", "start_time"):
            value = flow.get(key)
            if value is None or str(value).strip() == "":
                continue
            try:
                parsed = pd.to_datetime(value, utc=True, errors="coerce")
                if pd.isna(parsed):
                    continue
                return parsed.to_pydatetime()
            except (TypeError, ValueError, OverflowError):
                continue
        return None

    def _evict_oldest(self) -> None:
        old = self.history.popleft()
        old_src, old_dst, old_dport = old["src_ip"], old["dst_ip"], old["dport"]
        self.source_port_counts[old_src][old_dport] -= 1
        if self.source_port_counts[old_src][old_dport] <= 0:
            del self.source_port_counts[old_src][old_dport]
        if not self.source_port_counts[old_src]:
            del self.source_port_counts[old_src]
        if old_dst:
            self.dest_source_counts[old_dst][old_src] -= 1
            if self.dest_source_counts[old_dst][old_src] <= 0:
                del self.dest_source_counts[old_dst][old_src]
            if not self.dest_source_counts[old_dst]:
                del self.dest_source_counts[old_dst]

    def correlate(
        self,
        record_id: str | int,
        flow: dict[str, Any],
        threat_class: str | None = None,
        confidence: float | None = None,
    ) -> CorrelationResult:
        """Analyze a flow in sequence and correlate with recent sliding-window activity."""
        src_ip, dst_ip, dport = self.extract_endpoints(flow)
        event_time = self._parse_timestamp(flow)
        if not src_ip:
            return CorrelationResult(
                correlated=False,
                status="not_ready",
                message="No native source IP or complete TCP-stack fingerprint is available for endpoint correlation.",
            )

        # Prefer an elapsed-time window when timestamps are present; retain a hard
        # record-count cap as a memory bound and fallback for timestamp-less datasets.
        if event_time is not None:
            while self.history:
                oldest_time = self.history[0].get("timestamp")
                if oldest_time is None:
                    break
                age = (event_time - oldest_time).total_seconds()
                if age <= self.window_seconds:
                    break
                self._evict_oldest()
        while len(self.history) >= self.window_size:
            self._evict_oldest()

        # Track in sliding window structures
        self.history.append({
            "record_id": record_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dport": dport,
            "threat_class": threat_class,
            "confidence": confidence if confidence is not None else 0.0,
            "timestamp": event_time,
        })
        self.source_port_counts[src_ip][dport] += 1
        if dst_ip:
            self.dest_source_counts[dst_ip][src_ip] += 1

        # Bound group lifecycle to the active replay window. Groups with no
        # surviving member in the window are no longer considered active.
        live_record_ids = {item["record_id"] for item in self.history}
        stale_groups = [
            key for key, group in self.active_groups.items()
            if group.end_record_id not in live_record_ids
        ]
        for key in stale_groups:
            del self.active_groups[key]

        evidence: list[str] = []
        attack_type: str | None = None
        correlated = False
        group_id: str | None = None

        # Check Pattern 1: Horizontal Port Scanning (single source querying >= 5 distinct ports within window)
        target_ports = self.source_port_counts[src_ip]
        if len(target_ports) >= 5 and threat_class != "BENIGN":
            correlated = True
            attack_type = "PORT_SCAN"
            evidence.append(
                f"Source {src_ip} probed {len(target_ports)} distinct ports within configured correlation window ({self.window_seconds}s when timestamps are present; otherwise {self.window_size} records)."
            )

        # Check Pattern 2: Distributed Denial of Service (many sources targeting single destination)
        sources_targeting_dest = self.dest_source_counts[dst_ip] if dst_ip else {}
        if dst_ip and len(sources_targeting_dest) >= 8 and (threat_class in ("DDOS", "DOS") or dport in (80, 443, 8080)):
            correlated = True
            attack_type = "DDOS"
            evidence.append(
                f"Destination {dst_ip}:{dport} targeted by {len(sources_targeting_dest)} distinct source endpoints."
            )

        # Check Pattern 3: Authentication Brute Force (repeated hits to SSH/FTP/RDP)
        recent_auth_flows = [
            f for f in self.history
            if f["src_ip"] == src_ip and f["dport"] in (21, 22, 23, 3389)
        ]
        if len(recent_auth_flows) >= 4:
            correlated = True
            attack_type = "BRUTE_FORCE"
            evidence.append(
                f"Source {src_ip} executed {len(recent_auth_flows)} rapid auth attempts on port {recent_auth_flows[-1]['dport']}."
            )

        # Check Pattern 4: Volumetric DoS Surge from single source
        recent_same_src = [f for f in self.history if f["src_ip"] == src_ip]
        if len(recent_same_src) >= 12 and threat_class in ("DOS", "DDOS"):
            correlated = True
            attack_type = attack_type or "DOS"
            evidence.append(
                f"Source {src_ip} emitted {len(recent_same_src)} clustered attack flows."
            )

        # Fallback to model threat classification if consistent with recent history
        if not attack_type and threat_class and threat_class != "BENIGN":
            matching_class_count = sum(1 for f in self.history if f["src_ip"] == src_ip and f["threat_class"] == threat_class)
            if matching_class_count >= 2:
                correlated = True
                attack_type = threat_class
                evidence.append(
                    f"Recurrent {threat_class} detected ({matching_class_count} flows from {src_ip})."
                )

        if correlated:
            # Assign deterministic group ID per source IP & attack type
            group_key = f"{src_ip}_{attack_type}"
            if group_key not in self.active_groups:
                self.group_counter += 1
                new_group_id = f"GRP-{self.group_counter:04d}"
                self.active_groups[group_key] = CorrelationGroup(
                    group_id=new_group_id,
                    attack_type=attack_type,
                    source_ip=src_ip,
                    target_endpoints=[f"{dst_ip}:{dport}"] if dst_ip else [],
                    member_record_ids=[record_id],
                    flow_count=1,
                    start_record_id=record_id,
                    end_record_id=record_id,
                    confidence=confidence or 0.85,
                    evidence=evidence,
                )
            else:
                existing = self.active_groups[group_key]
                existing.flow_count += 1
                existing.end_record_id = record_id
                if record_id not in existing.member_record_ids:
                    existing.member_record_ids.append(record_id)
                # Keep explanations inspectable without allowing a long-running
                # source to grow group state without bound.
                existing.member_record_ids = existing.member_record_ids[-500:]
                target_str = f"{dst_ip}:{dport}" if dst_ip else ""
                if target_str and target_str not in existing.target_endpoints:
                    existing.target_endpoints.append(target_str)
                existing.target_endpoints = existing.target_endpoints[-100:]
                existing.evidence = evidence

            group = self.active_groups[group_key]
            group_id = group.group_id
            group_size = group.flow_count
        else:
            group_size = 1

        return CorrelationResult(
            correlated=correlated,
            group_id=group_id,
            attack_type=attack_type,
            group_size=group_size,
            evidence=evidence,
            status="success",
        )

