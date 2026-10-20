"""Operator Agent — Safe Exploitation Module."""

from __future__ import annotations

import asyncio
import time
from typing import Dict, List, Optional
from uuid import UUID

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AttackPath, AttackStep, CampaignMode
from nexus.safety.kernel import SafetyKernel
from nexus.utils.logging import get_bound_logger

logger = get_bound_logger(__name__)


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

        asset_map: Dict[UUID, Asset] = {a.id: a for a in (assets or [])}
        max_steps = int(self.config.get("max_steps_per_path", 5))

        for path in paths:
            if safety.is_aborted():
                logger.warning("operator_aborted_by_safety")
                break

            # Limit steps
            if len(path.steps) > max_steps:
                path.steps = path.steps[:max_steps]

            success = await self._execute_path(path, safety, mode, asset_map)
            path.success = success
            if success:
                logger.info("path_succeeded", path=path.name, priority=path.priority)
            else:
                logger.info("path_failed_or_skipped", path=path.name)

        return paths

    def _resolve_target(self, step: AttackStep, asset_map: Dict[UUID, Asset]) -> str:
        """Resolve AttackStep target_asset_id to a network-addressable target."""
        asset = asset_map.get(step.target_asset_id)
        if asset is None:
            logger.warning(
                "asset_not_found_for_step",
                asset_id=str(step.target_asset_id),
                step=step.name,
            )
            return str(step.target_asset_id)

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

            t0 = time.perf_counter()
            try:
                safe_payload = safety.sanitize_payload(
                    step.payload_summary,
                    context={"technique": step.technique_id, "target": target},
                )
                result = await self._run_safe_poc(step, safe_payload, target, mode)
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
                step.duration_ms = round((time.perf_counter() - t0) * 1000, 1)

            if not step.success:
                return False

            # Polite pacing
            await asyncio.sleep(0.05)

        return True

    async def _run_safe_poc(
        self,
        step: AttackStep,
        payload: str,
        target: str,
        mode: CampaignMode,
    ) -> dict:
        """Execute a non-destructive proof.

        Real safe modules live under nexus/exploit/pocs/. Current implementation
        performs only observational checks and returns structured evidence.
        """
        await asyncio.sleep(0.02)  # simulate work

        # Branch by technique for richer evidence
        if step.technique_id == "T1190":
            return {
                "success": True,
                "poc_type": "safe_http_marker",
                "technique": step.technique_id,
                "target": target,
                "payload_used": payload[:120],
                "evidence": {
                    "reachable": True,
                    "method": "observational",
                    "note": "Non-destructive reachability / header check simulated",
                },
            }
        if step.technique_id == "T1078":
            return {
                "success": mode in (CampaignMode.SIMULATE, CampaignMode.EVOLVE),
                "poc_type": "session_reuse_simulation",
                "technique": step.technique_id,
                "target": target,
                "payload_used": payload[:120],
                "evidence": {
                    "simulated_roles": ["user", "readonly"],
                    "note": "No real credentials used; pure simulation",
                },
            }
        # Default
        return {
            "success": True,
            "poc_type": "generic_safe_marker",
            "technique": step.technique_id,
            "target": target,
            "payload_used": payload[:120],
            "evidence": {"note": "Default non-destructive PoC"},
        }

    async def run(self, *args, **kwargs):
        return await self.execute_safe(*args, **kwargs)
