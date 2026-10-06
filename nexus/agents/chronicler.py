"""Chronicler Agent — Telemetry, Logging, Reporting & Remediation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

import structlog

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AttackPath, SafetyEvent, Vulnerability

logger = structlog.get_logger(__name__)


class ChroniclerAgent(BaseAgent):
    """Records everything and produces actionable output."""

    name = "chronicler"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.output_dir = Path(self.config.get("output_dir", "./data/campaigns"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def record(
        self,
        campaign_id: UUID,
        assets: List[Asset],
        vulns: List[Vulnerability],
        paths: List[AttackPath],
        safety_events: List[SafetyEvent],
    ) -> Dict[str, Any]:
        logger.info("chronicler_recording", campaign_id=str(campaign_id))

        report = {
            "campaign_id": str(campaign_id),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assets": [a.model_dump(mode="json") for a in assets],
            "vulnerabilities": [v.model_dump(mode="json") for v in vulns],
            "attack_paths": [p.model_dump(mode="json") for p in paths],
            "safety_events": [e.model_dump(mode="json") for e in safety_events],
            "summary": {
                "assets_discovered": len(assets),
                "vulnerabilities": len(vulns),
                "successful_paths": sum(1 for p in paths if p.success),
                "safety_interventions": len(safety_events),
            },
            "remediation": self._build_remediation(paths),
        }

        # Write JSON report
        out_file = self.output_dir / f"{campaign_id}.json"
        out_file.write_text(json.dumps(report, indent=2, default=str))
        logger.info("report_written", path=str(out_file))

        # In production: also push to Jira / Slack / SIEM / etc.
        await self._notify_integrations(report)

        return report

    def _build_remediation(self, paths: List[AttackPath]) -> List[Dict[str, Any]]:
        items = []
        for p in paths:
            if p.success or p.remediation:
                items.append(
                    {
                        "path": p.name,
                        "impact": p.impact.value,
                        "actions": p.remediation,
                        "root_cause": p.root_cause,
                    }
                )
        return items

    async def _notify_integrations(self, report: Dict[str, Any]) -> None:
        """Placeholder for ticketing / chat / SIEM hooks."""
        # Example: create Jira issue, post to Slack webhook, send to SIEM
        logger.debug("integrations_placeholder", campaign=report["campaign_id"])

    async def run(self, *args, **kwargs):
        return await self.record(*args, **kwargs)
