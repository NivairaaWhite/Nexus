"""Operator Agent — Safe Exploitation Module."""

from __future__ import annotations

import asyncio
from typing import Dict, List, Optional
from uuid import UUID

import structlog

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AttackPath, AttackStep, CampaignMode
from nexus.safety.kernel import SafetyKernel

logger = structlog.get_logger(__name__)


class OperatorAgent(BaseAgent):
    """Executes only non-destructive Proof-of-Concept actions.

    Never drops malware, never deletes data, never causes DoS.
    """

    name = "operator"

    async def execute_safe(
        self,
        paths: List[AttackPath],
        safety: SafetyKernel,
        mode: CampaignMode,
        assets: Optional[List[Asset]] = None,
    ) -> List[AttackPath]:
        logger.info("operator_started", paths=len(paths), mode=mode.value)

        # Build asset lookup so we can resolve UUIDs → real addresses
        asset_map: Dict[UUID, Asset] = {a.id: a for a in (assets or [])}

        for path in paths:
            if safety.is_aborted():
                logger.warning("operator_aborted_by_safety")
                break

            success = await self._execute_path(path, safety, mode, asset_map)
            path.success = success
            if success:
                logger.info("path_succeeded", path=path.name)
            else:
                logger.info("path_failed_or_skipped", path=path.name)

        return paths

    def _resolve_target(
        self, step: AttackStep, asset_map: Dict[UUID, Asset]
    ) -> str:
        """Resolve AttackStep target_asset_id to a network-addressable target.

        Preference order: hostname → address → (fallback) stringified UUID.
        """
        asset = asset_map.get(step.target_asset_id)
        if asset is None:
            logger.warning(
                "asset_not_found_for_step",
                asset_id=str(step.target_asset_id),
                step=step.name,
            )
            return str(step.target_asset_id)

        # Prefer hostname (domain checks) then address (IP checks)
        if asset.hostname:
            return asset.hostname
        return asset.address

    async def _execute_path(
        self,
        path: AttackPath,
        safety: SafetyKernel,
        mode: CampaignMode,
        asset_map: Dict[UUID, Asset],
    ) -> bool:
        """Run each step under safety controls."""
        for step in path.steps:
            target = self._resolve_target(step, asset_map)

            if not safety.allow_request(target):
                step.success = False
                step.evidence = {"reason": "safety_blocked", "target": target}
                logger.warning(
                    "step_blocked_by_safety",
                    path=path.name,
                    step=step.name,
                    target=target,
                )
                return False

            try:
                # Sanitize any payload content
                safe_payload = safety.sanitize_payload(
                    step.payload_summary,
                    context={"technique": step.technique_id, "target": target},
                )

                # --- Non-destructive PoC execution ---
                # In production this would call real safe modules:
                # - HTTP request that triggers a known marker
                # - Read a benign config file
                # - Mathematical challenge response
                # - Controlled DNS callback
                result = await self._run_safe_poc(step, safe_payload, target)

                step.success = result.get("success", False)
                step.evidence = result
            except PermissionError as e:
                step.success = False
                step.evidence = {"blocked": str(e), "target": target}
                return False
            except Exception as e:
                step.success = False
                step.evidence = {"error": str(e), "target": target}
                logger.exception("poc_execution_error", step=step.name, target=target)
                return False
            finally:
                safety.release_session(target)

            if not step.success:
                return False

            await asyncio.sleep(0.05)  # polite pacing

        return True

    async def _run_safe_poc(
        self, step: AttackStep, payload: str, target: str
    ) -> dict:
        """Simulate a non-destructive proof.

        Real implementations live in nexus/exploit/pocs/ and must:
        - Never write, delete, or encrypt data
        - Never open reverse shells or download second-stage payloads
        - Return structured evidence that a vulnerability is reachable
        """
        await asyncio.sleep(0.02)
        return {
            "success": True,
            "poc_type": "simulated_marker_read",
            "technique": step.technique_id,
            "target": target,
            "payload_used": payload[:120],  # truncated for audit
            "note": "Replace with real safe PoC library",
        }

    async def run(self, *args, **kwargs):
        return await self.execute_safe(*args, **kwargs)
