"""Scout Agent — Reconnaissance & Discovery Engine."""

from __future__ import annotations

import asyncio
from typing import List, Optional, Set
from uuid import uuid4

import httpx

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AssetType, Scope
from nexus.safety.kernel import HealthSnapshot, SafetyKernel
from nexus.utils.logging import get_bound_logger

logger = get_bound_logger(__name__)


class ScoutAgent(BaseAgent):
    """Discovers assets within the authorized scope.

    Performs:
    - Passive OSINT (domain seeding)
    - Safe active probing (HTTP HEAD/GET only, rate-limited)
    - Basic technology fingerprinting via headers
    - Environment classification
    """

    name = "scout"

    async def discover(self, scope: Scope, safety: SafetyKernel) -> List[Asset]:
        """Main discovery entry point."""
        logger.info("scout_discovery_started", scope=scope.name)
        assets: List[Asset] = []

        # --- Passive discovery (safe) ---
        passive = await self._passive_osint(scope)
        assets.extend(passive)

        # --- Active discovery (gated by safety) ---
        if not safety.is_aborted():
            active = await self._active_probe(scope, safety)
            assets.extend(active)

        # Deduplicate by address
        seen: Set[str] = set()
        unique: List[Asset] = []
        for a in assets:
            key = a.address.lower()
            if key not in seen:
                seen.add(key)
                unique.append(a)

        logger.info("scout_discovery_finished", total=len(unique))
        return unique

    async def _passive_osint(self, scope: Scope) -> List[Asset]:
        """Seed assets from configured domains / hostnames."""
        assets: List[Asset] = []
        for domain in list(scope.domains) + list(scope.hostnames):
            assets.append(
                Asset(
                    type=AssetType.WEB_APP,
                    address=domain,
                    hostname=domain,
                    technologies=[],
                    metadata={"source": "passive_seed", "simulated": False},
                )
            )
            logger.debug("passive_seeded", domain=domain)
        return assets

    async def _active_probe(self, scope: Scope, safety: SafetyKernel) -> List[Asset]:
        """Safe concurrent HTTP probing of in-scope targets.

        Only HEAD/GET requests with short timeouts. No port scanning of arbitrary ranges
        to avoid accidental DoS; only probes known seeds + a couple of example IPs from ranges.
        """
        assets: List[Asset] = []
        targets: List[str] = []

        # Probe domains
        for d in scope.domains + scope.hostnames:
            targets.append(d)

        # Very limited IP examples (first usable in each range) — still gated by safety
        for net in scope.ip_ranges:
            try:
                # Avoid network/broadcast
                hosts = list(net.hosts())
                if hosts:
                    targets.append(str(hosts[0]))
            except Exception:
                continue

        # Cap concurrency via safety + asyncio
        sem = asyncio.Semaphore(max(1, min(scope.max_concurrent, 5)))

        async def probe_one(target: str) -> Optional[Asset]:
            if safety.is_aborted() or not safety.allow_request(target):
                return None
            try:
                async with sem:
                    return await self._http_fingerprint(target, safety)
            finally:
                safety.release_session(target)

        tasks = [probe_one(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Asset):
                assets.append(r)
            elif isinstance(r, Exception):
                logger.debug("probe_error", error=str(r))

        return assets

    async def _http_fingerprint(self, target: str, safety: SafetyKernel) -> Optional[Asset]:
        """Perform a single safe HTTP probe and extract technology hints."""
        url = target if target.startswith("http") else f"https://{target}"
        start = asyncio.get_event_loop().time()
        tech: List[str] = []
        status = None
        server = None
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(3.0, connect=2.0),
                follow_redirects=True,
                verify=False,  # lab environments often use self-signed
            ) as client:
                # Prefer HEAD, fall back to GET
                try:
                    resp = await client.head(url)
                except Exception:
                    resp = await client.get(url)
                status = resp.status_code
                server = resp.headers.get("server")
                powered = resp.headers.get("x-powered-by")
                if server:
                    tech.append(server.split("/")[0])
                if powered:
                    tech.append(powered.split("/")[0])
                # Common framework hints
                for h, v in resp.headers.items():
                    hl = h.lower()
                    if "x-aspnet" in hl or "aspnet" in v.lower():
                        tech.append("ASP.NET")
                    if "x-drupal" in hl:
                        tech.append("Drupal")
                    if "x-generator" in hl and "wordpress" in v.lower():
                        tech.append("WordPress")
        except Exception as exc:
            latency = (asyncio.get_event_loop().time() - start) * 1000
            safety.record_health(
                HealthSnapshot(target=target, latency_ms=latency, error_rate=1.0)
            )
            logger.debug("http_probe_failed", target=target, error=str(exc))
            # Still return a host asset so Analyst can consider it
            return Asset(
                type=AssetType.HOST,
                address=target,
                hostname=target if not target.replace(".", "").isdigit() else None,
                ports=[],
                technologies=[],
                metadata={"source": "active_probe", "error": str(exc)[:120]},
            )

        latency = (asyncio.get_event_loop().time() - start) * 1000
        safety.record_health(
            HealthSnapshot(
                target=target,
                latency_ms=latency,
                error_rate=0.0 if status and status < 500 else 0.5,
                status_code=status,
            )
        )

        asset_type = AssetType.WEB_APP if status else AssetType.HOST
        ports = [443] if url.startswith("https") else [80]
        return Asset(
            type=asset_type,
            address=target,
            hostname=target if not target.replace(".", "").isdigit() else None,
            ports=ports,
            services={ports[0]: "https" if ports[0] == 443 else "http"},
            technologies=list(dict.fromkeys(tech)),  # dedupe preserve order
            metadata={
                "source": "active_probe",
                "status_code": status,
                "server": server,
                "latency_ms": round(latency, 1),
            },
        )

    async def run(self, *args, **kwargs):
        return await self.discover(*args, **kwargs)
