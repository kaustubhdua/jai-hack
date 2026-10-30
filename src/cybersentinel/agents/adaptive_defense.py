"""Adaptive Defense Agent (Agent 5).

Manages stateful, temporary simulated ALLOW/BLOCK firewall policies.
Implements pre-filtering against active policies, policy generation on confirmed
attack signals, and automatic policy expiry based on record offsets.
"""
from __future__ import annotations

import logging
import ipaddress
from typing import Any, Literal

from cybersentinel.contracts import DefenseDecision, DefensePolicy

logger = logging.getLogger("cybersentinel.agents.adaptive_defense")


class AdaptiveDefenseAgent:
    """Stateful agent creating and evaluating temporary firewall policies."""

    def __init__(self, default_duration: int = 150):
        self.default_duration = default_duration
        self.active_policies: dict[str, DefensePolicy] = {}  # scope_value -> DefensePolicy
        self.all_policies: list[DefensePolicy] = []
        self.policy_counter = 0

    def reset(self) -> None:
        """Reset all active and logged policies."""
        self.active_policies.clear()
        self.all_policies.clear()
        self.policy_counter = 0

    def evaluate_pre_filter(
        self,
        record_id: str | int,
        source_ip: str,
        current_step: int,
    ) -> DefenseDecision | None:
        """Evaluate incoming flow against currently active policies BEFORE analysis.

        Returns DefenseDecision with action=BLOCK if an active policy matches,
        or None if no applicable active policy exists.
        """
        # Expire any outdated policies
        self._prune_expired_policies(current_step)

        policy = self.active_policies.get(source_ip)
        if policy is not None:
            # Policy is active and matches
            return DefenseDecision(
                record_id=record_id,
                action="BLOCK",
                applied_policy_id=policy.policy_id,
                is_pre_filtered=True,
                new_policy_created=None,
                rationale=f"Mitigated by active policy {policy.policy_id} on {source_ip}.",
            )
        return None

    def handle_post_analysis(
        self,
        record_id: str | int,
        source_ip: str,
        current_step: int,
        attack_detected: bool,
        attack_type: str | None = None,
        confidence: float | None = None,
        duration: int | None = None,
    ) -> DefenseDecision:
        """Decide flow action and optionally generate a forward-looking policy for later records."""
        # Expire any outdated policies
        self._prune_expired_policies(current_step)

        new_policy: DefensePolicy | None = None

        if attack_detected and attack_type and attack_type != "BENIGN" and self._is_observed_ip(source_ip):
            # Generate a new policy for subsequent matching records if one isn't already active
            if source_ip not in self.active_policies:
                self.policy_counter += 1
                pol_id = f"POL-{self.policy_counter:05d}"
                pol_duration = duration or self.default_duration
                expires_step = current_step + pol_duration

                new_policy = DefensePolicy(
                    policy_id=pol_id,
                    activated_after_record_id=record_id,
                    scope_type="SOURCE_IP",
                    scope_value=source_ip,
                    expires_after_record_id=expires_step,
                    policy_action="BLOCK",
                    reason=f"{attack_type} detected (confidence: {confidence or 1.0:.3f})",
                    created_at_step=current_step,
                )
                self.active_policies[source_ip] = new_policy
                self.all_policies.append(new_policy)

        return DefenseDecision(
            record_id=record_id,
            action="ALLOW",
            applied_policy_id="",
            is_pre_filtered=False,
            new_policy_created=new_policy,
            rationale="Flow permitted for analysis; policy created for future traffic." if new_policy else "Flow allowed.",
        )

    @staticmethod
    def _is_observed_ip(value: str) -> bool:
        """Accept only literal IP addresses; derived fingerprints are never policy scopes."""
        try:
            ipaddress.ip_address(str(value).strip())
            return True
        except (ValueError, TypeError):
            return False

    def _prune_expired_policies(self, current_step: int) -> None:
        """Remove policies whose expiry step has passed."""
        expired = [
            src for src, pol in self.active_policies.items()
            if current_step > pol.expires_after_record_id
        ]
        for src in expired:
            del self.active_policies[src]

