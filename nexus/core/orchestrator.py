"""Nexus Orchestrator — Central coordinator of all agents."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import structlog

from nexus.core.types import (
    AgentMessage,
    Asset,
    AttackPath,
    CampaignMode,
    CampaignResult,
    Scope,
    Vulnerability,
)
from nexus.safety.kernel import SafetyKernel

logger = structlog.get_logger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Orchestrator:
    """High-level campaign orchestrator.

    Coordinates Scout → Analyst → Operator → Chronicler → Evolutor
    while the Guardian (SafetyKernel) runs as a continuous constraint.
    """

    def __init__(
        self,
        scope: Scope,
        mode: CampaignMode = CampaignMode.OBSERVE,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.campaign_id = uuid4()
        self.scope = scope
        self.mode = mode
        self.config = config or {}
        self.safety = SafetyKernel(scope, mode)

        # Agent registries (lazy-loaded / injected)
        self.scout = None
        self.analyst = None
        self.operator = None
        self.chronicler = None
        self.evolutor = None

        self._assets: List[Asset] = []
        self._vulns: List[Vulnerability] = []
        self._paths: List[AttackPath] = []
        self._started_at: Optional[datetime] = None

        logger.info(
            "orchestrator_created",
            campaign_id=str(self.campaign_id),
            mode=mode.value,
            scope=scope.name,
        )

    def register_agents(
        self,
        scout=None,
        analyst=None,
        operator=None,
        chronicler=None,
        evolutor=None,
    ) -> None:
        """Inject agent instances."""
        self.scout = scout
        self.analyst = analyst
        self.operator = operator
        self.chronicler = chronicler
        self.evolutor = evolutor

    async def run(self) -> CampaignResult:
        """Execute a full campaign under safety constraints."""
        self._started_at = _utcnow()
        logger.info("campaign_started", campaign_id=str(self.campaign_id), mode=self.mode.value)

        try:
            # Phase 1: Reconnaissance
            if self.scout:
                logger.info("phase_recon_start")
                self._assets = await self.scout.discover(self.scope, self.safety)
                logger.info("phase_recon_done", assets=len(self._assets))

            if self.safety.is_aborted():
                return self._finalize(success=False, summary="Aborted during recon")

            # Phase 2: Vulnerability Analysis & Attack Graph
            if self.analyst and self._assets:
                logger.info("phase_analysis_start")
                self._vulns, self._paths = await self.analyst.analyze(
                    self._assets, self.safety, self.mode
                )
                logger.info(
                    "phase_analysis_done",
                    vulns=len(self._vulns),
                    paths=len(self._paths),
                )

            if self.safety.is_aborted():
                return self._finalize(success=False, summary="Aborted during analysis")

            # Phase 3: Safe Exploitation (only in PROVE / SIMULATE / EVOLVE)
            if self.mode in (CampaignMode.PROVE, CampaignMode.SIMULATE, CampaignMode.EVOLVE):
                if self.operator and self._paths:
                    logger.info("phase_exploit_start")
                    self._paths = await self.operator.execute_safe(
                        self._paths,
                        self.safety,
                        self.mode,
                        assets=self._assets,  # required for target resolution
                    )
                    logger.info("phase_exploit_done")

            if self.safety.is_aborted():
                return self._finalize(success=False, summary="Aborted during exploitation")

            # Phase 4: Telemetry & Remediation
            if self.chronicler:
                await self.chronicler.record(
                    campaign_id=self.campaign_id,
                    assets=self._assets,
                    vulns=self._vulns,
                    paths=self._paths,
                    safety_events=self.safety.get_safety_events(),
                )

            # Phase 5: Evolution / Learning
            if self.evolutor and self.mode == CampaignMode.EVOLVE:
                await self.evolutor.learn(
                    assets=self._assets,
                    vulns=self._vulns,
                    paths=self._paths,
                    safety_events=self.safety.get_safety_events(),
                )

            success = any(p.success for p in self._paths) if self._paths else False
            summary = (
                f"Discovered {len(self._assets)} assets, "
                f"{len(self._vulns)} vulns, "
                f"{sum(1 for p in self._paths if p.success)} successful paths"
            )
            return self._finalize(success=success, summary=summary)

        except Exception as exc:
            logger.exception("campaign_failed", error=str(exc))
            return self._finalize(success=False, summary=f"Exception: {exc}")

    def _finalize(self, success: bool, summary: str) -> CampaignResult:
        result = CampaignResult(
            campaign_id=self.campaign_id,
            mode=self.mode,
            scope_name=self.scope.name,
            started_at=self._started_at or _utcnow(),
            finished_at=_utcnow(),
            assets_discovered=len(self._assets),
            vulnerabilities_found=len(self._vulns),
            attack_paths=self._paths,
            safety_events=self.safety.get_safety_events(),
            success=success,
            summary=summary,
        )
        logger.info(
            "campaign_finished",
            campaign_id=str(self.campaign_id),
            success=success,
            summary=summary,
        )
        return result
