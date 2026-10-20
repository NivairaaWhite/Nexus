"""Analyst Agent — Vulnerability Analysis & Attack Graph Generation."""

from __future__ import annotations

from typing import Dict, List, Tuple
from uuid import UUID

import networkx as nx

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
from nexus.utils.logging import get_bound_logger

logger = get_bound_logger(__name__)

# Simple technology → known issue mapping (placeholder for real NVD/EPSS integration)
_TECH_ISSUES: Dict[str, List[Dict]] = {
    "Apache": [
        {
            "title": "Apache HTTP Server Information Disclosure",
            "severity": Severity.LOW,
            "cvss": 5.3,
            "cwe": "CWE-200",
            "technique": "T1190",
        }
    ],
    "nginx": [
        {
            "title": "nginx Misconfiguration / Version Disclosure",
            "severity": Severity.INFO,
            "cvss": 3.7,
            "cwe": "CWE-200",
            "technique": "T1190",
        }
    ],
    "WordPress": [
        {
            "title": "WordPress Plugin / Theme Vulnerability Surface",
            "severity": Severity.MEDIUM,
            "cvss": 6.5,
            "cwe": "CWE-79",
            "technique": "T1190",
        }
    ],
    "ASP.NET": [
        {
            "title": "ASP.NET ViewState / Debug Endpoint Exposure",
            "severity": Severity.MEDIUM,
            "cvss": 5.9,
            "cwe": "CWE-502",
            "technique": "T1190",
        }
    ],
}


class AnalystAgent(BaseAgent):
    """Builds vulnerability inventory and prioritized attack graphs."""

    name = "analyst"

    async def analyze(
        self,
        assets: List[Asset],
        safety: SafetyKernel,
        mode: CampaignMode,
    ) -> Tuple[List[Vulnerability], List[AttackPath]]:
        logger.info("analyst_started", assets=len(assets))

        vulns = await self._match_findings(assets)
        # Enrich asset risk scores
        self._score_assets(assets, vulns)
        paths = await self._build_attack_graphs(assets, vulns, mode)

        # Sort paths by priority descending
        paths.sort(key=lambda p: p.priority, reverse=True)

        logger.info("analyst_finished", vulns=len(vulns), paths=len(paths))
        return vulns, paths

    async def _match_findings(self, assets: List[Asset]) -> List[Vulnerability]:
        """Heuristic matching based on open ports / technologies.

        Production systems would integrate NVD, EPSS, KEV, and banner analysis.
        """
        vulns: List[Vulnerability] = []
        for asset in assets:
            # Port-based heuristics
            if 80 in asset.ports or 443 in asset.ports or asset.type == AssetType.WEB_APP:
                vulns.append(
                    Vulnerability(
                        cve_id=None,
                        title="Web Application Attack Surface",
                        description="HTTP(S) service exposed; potential for injection, auth bypass, or info disclosure.",
                        severity=Severity.MEDIUM,
                        cvss_score=5.5,
                        affected_asset_id=asset.id,
                        evidence={"ports": asset.ports, "tech": asset.technologies},
                        exploitability=0.6,
                    )
                )
            if 22 in asset.ports:
                vulns.append(
                    Vulnerability(
                        cve_id=None,
                        title="SSH Service Exposed",
                        description="SSH listening; potential for credential stuffing or key-based attacks.",
                        severity=Severity.LOW,
                        cvss_score=4.0,
                        affected_asset_id=asset.id,
                        evidence={"port": 22},
                        exploitability=0.3,
                    )
                )

            # Technology-specific findings
            for tech in asset.technologies:
                for issue in _TECH_ISSUES.get(tech, []):
                    vulns.append(
                        Vulnerability(
                            cve_id=None,
                            cwe_id=issue.get("cwe"),
                            title=issue["title"],
                            description=f"Detected technology '{tech}' associated with known issue class.",
                            severity=issue["severity"],
                            cvss_score=issue.get("cvss"),
                            affected_asset_id=asset.id,
                            evidence={"technology": tech},
                            exploitability=0.5,
                        )
                    )

            # Missing security headers (from probe metadata)
            meta = asset.metadata or {}
            if meta.get("status_code") and not any(
                t.lower() in ("cloudflare", "akamai") for t in asset.technologies
            ):
                # Simulated missing header finding
                vulns.append(
                    Vulnerability(
                        title="Potential Missing Security Headers",
                        description="No strong CDN/WAF fingerprint; verify CSP, HSTS, X-Frame-Options.",
                        severity=Severity.LOW,
                        cvss_score=3.1,
                        affected_asset_id=asset.id,
                        evidence={"status": meta.get("status_code")},
                        exploitability=0.2,
                    )
                )
        return vulns

    def _score_assets(self, assets: List[Asset], vulns: List[Vulnerability]) -> None:
        """Compute simple risk_score (0-10) per asset."""
        by_asset: Dict[UUID, List[Vulnerability]] = {}
        for v in vulns:
            by_asset.setdefault(v.affected_asset_id, []).append(v)

        severity_weight = {
            Severity.INFO: 0.5,
            Severity.LOW: 2.0,
            Severity.MEDIUM: 5.0,
            Severity.HIGH: 8.0,
            Severity.CRITICAL: 10.0,
        }
        for asset in assets:
            related = by_asset.get(asset.id, [])
            if not related:
                asset.risk_score = 0.5
                continue
            score = max(severity_weight.get(v.severity, 3.0) * (v.exploitability or 0.5) for v in related)
            asset.risk_score = min(10.0, round(score, 2))

    async def _build_attack_graphs(
        self,
        assets: List[Asset],
        vulns: List[Vulnerability],
        mode: CampaignMode,
    ) -> List[AttackPath]:
        """Construct prioritized attack paths using NetworkX."""
        G = nx.DiGraph()
        asset_map = {a.id: a for a in assets}

        for a in assets:
            G.add_node(str(a.id), type="asset", label=a.address, risk=a.risk_score)

        for v in vulns:
            vid = str(v.id)
            G.add_node(
                vid,
                type="vuln",
                label=v.title,
                severity=v.severity.value,
                cvss=v.cvss_score or 0,
            )
            G.add_edge(str(v.affected_asset_id), vid, relation="has_vuln")

        paths: List[AttackPath] = []
        for v in vulns:
            asset = asset_map.get(v.affected_asset_id)
            if not asset:
                continue

            # Single-step path
            step = AttackStep(
                technique_id="T1190",
                name=f"Exploit {v.title}",
                description=v.description,
                target_asset_id=asset.id,
                payload_summary="Non-destructive PoC (safe marker / header / config read)",
            )
            priority = (v.cvss_score or 5.0) * (v.exploitability or 0.5) + asset.risk_score * 0.3
            path = AttackPath(
                name=f"Path to {asset.address} via {v.title}",
                steps=[step],
                root_cause=v.cve_id or v.title,
                impact=v.severity,
                remediation=[
                    "Apply latest vendor patches / updates",
                    "Restrict network exposure (firewall / SG)",
                    "Enable WAF / IPS / rate-limiting rules",
                    "Review and harden configuration",
                ],
                priority=round(priority, 2),
            )
            paths.append(path)

            # Multi-step simulation for higher modes
            if mode in (CampaignMode.SIMULATE, CampaignMode.EVOLVE) and asset.risk_score >= 4.0:
                step2 = AttackStep(
                    technique_id="T1078",
                    name="Credential / Session Reuse Simulation",
                    description="Simulate lateral movement using obtained session context (non-destructive).",
                    target_asset_id=asset.id,
                    payload_summary="Simulated session token validation / role enumeration",
                )
                multi = AttackPath(
                    name=f"Multi-step to {asset.address}",
                    steps=[step, step2],
                    root_cause=v.title,
                    impact=Severity.HIGH if v.severity in (Severity.HIGH, Severity.CRITICAL) else Severity.MEDIUM,
                    remediation=path.remediation + ["Implement least-privilege session management"],
                    priority=round(priority + 1.5, 2),
                )
                paths.append(multi)

        return paths

    async def run(self, *args, **kwargs):
        return await self.analyze(*args, **kwargs)


# Local import to avoid circularity at module level
from nexus.core.types import AssetType  # noqa: E402
