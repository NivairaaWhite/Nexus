"""Chronicler Agent — Telemetry, Logging, Reporting & Remediation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AttackPath, SafetyEvent, Vulnerability
from nexus.utils.logging import get_bound_logger

logger = get_bound_logger(__name__)


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
                "high_priority_paths": sum(1 for p in paths if p.priority >= 6.0),
            },
            "remediation": self._build_remediation(paths),
            "top_risks": self._top_risks(assets, vulns),
        }

        # JSON report
        out_file = self.output_dir / f"{campaign_id}.json"
        out_file.write_text(json.dumps(report, indent=2, default=str))
        logger.info("report_written", path=str(out_file))

        # Human-readable Markdown summary
        md_file = self.output_dir / f"{campaign_id}.md"
        md_file.write_text(self._to_markdown(report))
        logger.info("markdown_report_written", path=str(md_file))

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
                        "priority": p.priority,
                        "actions": p.remediation,
                        "root_cause": p.root_cause,
                    }
                )
        items.sort(key=lambda x: x.get("priority", 0), reverse=True)
        return items

    def _top_risks(self, assets: List[Asset], vulns: List[Vulnerability]) -> List[Dict]:
        ranked = sorted(assets, key=lambda a: a.risk_score, reverse=True)[:5]
        return [
            {
                "address": a.address,
                "risk_score": a.risk_score,
                "type": a.type.value,
                "technologies": a.technologies,
            }
            for a in ranked
            if a.risk_score > 0
        ]

    def _to_markdown(self, report: Dict[str, Any]) -> str:
        s = report["summary"]
        lines = [
            f"# Nexus Campaign Report",
            f"",
            f"**Campaign ID:** `{report['campaign_id']}`  ",
            f"**Timestamp:** {report['timestamp']}",
            f"",
            f"## Summary",
            f"- Assets discovered: **{s['assets_discovered']}**",
            f"- Vulnerabilities: **{s['vulnerabilities']}**",
            f"- Successful paths: **{s['successful_paths']}**",
            f"- Safety interventions: **{s['safety_interventions']}**",
            f"",
            f"## Top Risks",
        ]
        for r in report.get("top_risks", []):
            lines.append(f"- `{r['address']}` (score {r['risk_score']}) — {r['type']}")
        lines.append("")
        lines.append("## Remediation Priorities")
        for item in report.get("remediation", [])[:10]:
            lines.append(f"### {item['path']} (priority {item.get('priority', 0)})")
            lines.append(f"- Impact: {item['impact']}")
            for a in item.get("actions", []):
                lines.append(f"  - {a}")
            lines.append("")
        return "\n".join(lines)

    async def _notify_integrations(self, report: Dict[str, Any]) -> None:
        """Placeholder for ticketing / chat / SIEM hooks."""
        logger.debug("integrations_placeholder", campaign=report["campaign_id"])

    async def run(self, *args, **kwargs):
        return await self.record(*args, **kwargs)
