"""Analyst Agent — Vulnerability Analysis & Attack Graph Generation."""

from __future__ import annotations

from typing import List, Tuple
from uuid import uuid4

import networkx as nx
import structlog

from nexus.agents.base import BaseAgent
from nexus.core.types import (
    Asset,
    AttackPath,
    AttackStep,
    CampaignMode,
    Severity,
    Vulnerability,
)
from nexus.safety.kernel import SafetyKernel

logger = structlog.get_logger(__name__)


class AnalystAgent(BaseAgent):
    """Builds vulnerability inventory and attack graphs."""

    name = "analyst"

    async def analyze(
        self,
        assets: List[Asset],
        safety: SafetyKernel,
        mode: CampaignMode,
    ) -> Tuple[List[Vulnerability], List[AttackPath]]:
        logger.info("analyst_started", assets=len(assets))

        vulns = await self._match_cves(assets)
        paths = await self._build_attack_graphs(assets, vulns, mode)

        logger.info("analyst_finished", vulns=len(vulns), paths=len(paths))
        return vulns, paths

    async def _match_cves(self, assets: List[Asset]) -> List[Vulnerability]:
        """Placeholder CVE matching. Integrate with NVD / EPSS / KEV in production."""
        vulns = []
        for asset in assets:
            # Simulated findings based on open ports / tech
            if 80 in asset.ports or 443 in asset.ports:
                vulns.append(
                    Vulnerability(
                        cve_id="CVE-2023-EXAMPLE",
                        title="Simulated Web Application Vulnerability",
                        description="Placeholder for real CVE matching against banners/tech.",
                        severity=Severity.MEDIUM,
                        cvss_score=6.5,
                        affected_asset_id=asset.id,
                        evidence={"ports": asset.ports, "tech": asset.technologies},
                    )
                )
            if 22 in asset.ports:
                vulns.append(
                    Vulnerability(
                        cve_id=None,
                        title="SSH Service Exposed",
                        description="SSH listening; potential for credential or key attacks.",
                        severity=Severity.LOW,
                        affected_asset_id=asset.id,
                        evidence={"port": 22},
                    )
                )
        return vulns

    async def _build_attack_graphs(
        self,
        assets: List[Asset],
        vulns: List[Vulnerability],
        mode: CampaignMode,
    ) -> List[AttackPath]:
        """Construct simple attack paths using NetworkX.

        In production this would use a richer graph (Neo4j) + LLM reasoning
        + reinforcement-learning scoring.
        """
        G = nx.DiGraph()
        asset_map = {a.id: a for a in assets}

        for a in assets:
            G.add_node(str(a.id), type="asset", label=a.address)

        for v in vulns:
            vid = str(v.id)
            G.add_node(vid, type="vuln", label=v.title, severity=v.severity.value)
            G.add_edge(str(v.affected_asset_id), vid, relation="has_vuln")

        paths: List[AttackPath] = []
        # Generate simple single-step paths for demonstration
        for v in vulns:
            asset = asset_map.get(v.affected_asset_id)
            if not asset:
                continue
            step = AttackStep(
                technique_id="T1190",  # example ATT&CK
                name=f"Exploit {v.title}",
                description=v.description,
                target_asset_id=asset.id,
                payload_summary="Non-destructive PoC (config read / math challenge)",
            )
            path = AttackPath(
                name=f"Path to {asset.address} via {v.title}",
                steps=[step],
                root_cause=v.cve_id or v.title,
                impact=v.severity,
                remediation=[
                    "Apply latest vendor patch",
                    "Restrict network exposure",
                    "Enable WAF / IPS rules",
                ],
            )
            paths.append(path)

        return paths

    async def run(self, *args, **kwargs):
        return await self.analyze(*args, **kwargs)
