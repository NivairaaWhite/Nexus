"""Safety Kernel — Non-negotiable safety invariants for Nexus.

Every action that can affect a target MUST pass through this kernel.
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

import structlog
from pydantic import BaseModel

from nexus.core.types import (
    Asset,
    CampaignMode,
    SafetyEvent,
    Scope,
    Severity,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Destructive patterns (never allowed)
# ---------------------------------------------------------------------------
DESTRUCTIVE_PATTERNS = [
    re.compile(r"\b(rm\s+-rf|del\s+/[fq]|format\s+|mkfs|dd\s+if=)", re.I),
    re.compile(r"\b(DROP\s+TABLE|TRUNCATE\s+|DELETE\s+FROM\s+\w+\s*;)", re.I),
    re.compile(r"\b(shutdown|reboot|halt|poweroff)\b", re.I),
    re.compile(r"\b(passwd|chpasswd|net\s+user\s+\w+\s+\w+)", re.I),
    re.compile(r"\b(fork\s*bomb|: \(\)\s*\{\s*:\|:\s*&\s*\})", re.I),
    re.compile(r"(wget|curl).*\|\s*(ba)?sh", re.I),
    re.compile(r"\b(ransomware|encrypt_files|wipe)\b", re.I),
]

# High-risk but sometimes necessary patterns that require extra scrutiny
HIGH_RISK_PATTERNS = [
    re.compile(r"\b(sudo|su\s+-|runas)\b", re.I),
    re.compile(r"\b(chmod\s+777|chown\s+)", re.I),
]


class HealthSnapshot(BaseModel):
    """Lightweight health observation of a target."""
    target: str
    latency_ms: float
    error_rate: float = 0.0
    status_code: Optional[int] = None
    timestamp: float = time.time()


class SafetyKernel:
    """Central safety enforcement point.

    Responsibilities:
    - Scope enforcement (IP, domain, endpoint)
    - Destructive payload blocking
    - Rate limiting & concurrency control
    - Target health monitoring & auto-abort
    - Blast-radius estimation (basic)
    """

    def __init__(self, scope: Scope, mode: CampaignMode = CampaignMode.OBSERVE):
        self.scope = scope
        self.mode = mode
        self._allowed_networks = [ipaddress.ip_network(n) for n in scope.ip_ranges]
        self._excluded_ips = {ipaddress.ip_address(ip) for ip in scope.excluded_ips}
        self._health_history: Dict[str, List[HealthSnapshot]] = {}
        self._request_timestamps: List[float] = []
        self._active_sessions: Set[str] = set()
        self._safety_events: List[SafetyEvent] = []
        self._aborted = False
        self._abort_reason: Optional[str] = None

        logger.info(
            "safety_kernel_initialized",
            scope_name=scope.name,
            mode=mode.value,
            ip_ranges=len(scope.ip_ranges),
            domains=len(scope.domains),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_aborted(self) -> bool:
        return self._aborted

    def get_abort_reason(self) -> Optional[str]:
        return self._abort_reason

    def get_safety_events(self) -> List[SafetyEvent]:
        return list(self._safety_events)

    def check_scope(self, target: str) -> bool:
        """Return True if target is within authorized scope.

        Accepts bare IPs, host:port, hostnames, and FQDNs.
        """
        if self._aborted:
            return False

        # Strip optional port / scheme noise for IP parsing
        host_part = target.split("://")[-1].split("/")[0].split(":")[0].strip()

        # IP check
        try:
            ip = ipaddress.ip_address(host_part)
            if ip in self._excluded_ips:
                self._record_event(
                    "scope_violation",
                    Severity.HIGH,
                    f"Target {target} is explicitly excluded",
                )
                return False
            if self._allowed_networks:
                if not any(ip in net for net in self._allowed_networks):
                    self._record_event(
                        "scope_violation",
                        Severity.HIGH,
                        f"Target {target} not in any allowed IP range",
                    )
                    return False
            return True
        except ValueError:
            pass  # Not an IP, fall through to domain / hostname check

        # Domain / hostname check (exact or subdomain)
        target_lower = host_part.lower().rstrip(".")
        for d in self.scope.domains:
            d_lower = d.lower().rstrip(".")
            if target_lower == d_lower or target_lower.endswith("." + d_lower):
                return True
        for h in self.scope.hostnames:
            if target_lower == h.lower().rstrip("."):
                return True

        # Also honour excluded domains
        for ed in getattr(self.scope, "excluded_domains", []) or []:
            ed_lower = ed.lower().rstrip(".")
            if target_lower == ed_lower or target_lower.endswith("." + ed_lower):
                self._record_event(
                    "scope_violation",
                    Severity.HIGH,
                    f"Target {target} matches excluded domain {ed}",
                )
                return False

        self._record_event(
            "scope_violation",
            Severity.HIGH,
            f"Target {target} not in authorized domains/hostnames",
        )
        return False

    def sanitize_payload(self, payload: str, context: Optional[Dict[str, Any]] = None) -> str:
        """Strip or reject destructive content. Returns sanitized payload or raises."""
        if self.mode == CampaignMode.OBSERVE:
            raise PermissionError("Payload execution not allowed in OBSERVE mode")

        for pattern in DESTRUCTIVE_PATTERNS:
            if pattern.search(payload):
                self._record_event(
                    "payload_blocked",
                    Severity.CRITICAL,
                    f"Destructive pattern matched: {pattern.pattern}",
                    context or {},
                )
                raise PermissionError(f"Destructive payload blocked by Safety Kernel")

        # Soft warning for high-risk patterns
        for pattern in HIGH_RISK_PATTERNS:
            if pattern.search(payload):
                logger.warning("high_risk_payload_detected", pattern=pattern.pattern)
                self._record_event(
                    "high_risk_payload",
                    Severity.MEDIUM,
                    f"High-risk pattern present: {pattern.pattern}",
                    context or {},
                )

        return payload

    def allow_request(self, target: str) -> bool:
        """Rate-limit + concurrency + health gate."""
        if self._aborted:
            return False
        if not self.check_scope(target):
            return False

        now = time.time()
        # Sliding-window rate limit (requests per second)
        window = 1.0
        self._request_timestamps = [
            t for t in self._request_timestamps if now - t < window
        ]
        # Compare against float rate limit safely
        if len(self._request_timestamps) >= max(1, int(self.scope.rate_limit_rps)):
            logger.debug("rate_limit_hit", target=target, rps=self.scope.rate_limit_rps)
            return False

        if len(self._active_sessions) >= self.scope.max_concurrent:
            logger.debug("concurrency_limit_hit", target=target)
            return False

        # Health check
        if self._is_unhealthy(target):
            self._abort(f"Target {target} appears unstable")
            return False

        self._request_timestamps.append(now)
        self._active_sessions.add(target)
        return True

    def release_session(self, target: str) -> None:
        self._active_sessions.discard(target)

    def record_health(self, snapshot: HealthSnapshot) -> None:
        """Ingest a health observation. May trigger abort."""
        history = self._health_history.setdefault(snapshot.target, [])
        history.append(snapshot)
        # Keep last 20 observations
        if len(history) > 20:
            history.pop(0)

        if self._is_unhealthy(snapshot.target):
            self._abort(f"Health degradation detected on {snapshot.target}")

    def estimate_blast_radius(self, asset: Asset, action: str) -> Severity:
        """Very basic blast-radius heuristic."""
        # In a real system this would use the knowledge graph
        if asset.type in ("host", "cloud_resource") and "admin" in action.lower():
            return Severity.HIGH
        if asset.type == "web_app":
            return Severity.MEDIUM
        return Severity.LOW

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _is_unhealthy(self, target: str) -> bool:
        history = self._health_history.get(target, [])
        if len(history) < 3:
            return False
        recent = history[-5:]
        avg_latency = sum(h.latency_ms for h in recent) / len(recent)
        avg_error = sum(h.error_rate for h in recent) / len(recent)
        # Thresholds (configurable in production)
        if avg_latency > 2000 or avg_error > 0.4:
            return True
        return False

    def _abort(self, reason: str) -> None:
        if not self._aborted:
            self._aborted = True
            self._abort_reason = reason
            self._record_event("health_abort", Severity.CRITICAL, reason)
            logger.critical("campaign_aborted_by_safety_kernel", reason=reason)

    def _record_event(
        self,
        event_type: str,
        severity: Severity,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = SafetyEvent(
            event_type=event_type,
            severity=severity,
            message=message,
            context=context or {},
        )
        self._safety_events.append(event)
        # Map Severity enum → structlog / stdlib numeric level
        _LEVEL_MAP = {
            Severity.INFO: 20,      # INFO
            Severity.LOW: 20,       # INFO
            Severity.MEDIUM: 30,    # WARNING
            Severity.HIGH: 40,      # ERROR
            Severity.CRITICAL: 50,  # CRITICAL
        }
        level = _LEVEL_MAP.get(severity, 30)
        logger.log(
            level,
            "safety_event",
            event_type=event_type,
            severity=severity.value,
            message=message,
        )
