"""Shared types, enums, and data models for Nexus."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, IPvAnyAddress, IPvAnyNetwork


def _utcnow() -> datetime:
    """Timezone-aware UTC now (replaces deprecated datetime.utcnow)."""
    return datetime.now(timezone.utc)


class CampaignMode(str, Enum):
    """Operating modes of a Nexus campaign."""
    OBSERVE = "observe"          # Recon + analysis only, no exploitation
    PROVE = "prove"              # Safe non-destructive PoCs allowed
    SIMULATE = "simulate"        # Full lateral movement simulation (still non-destructive)
    EVOLVE = "evolve"            # Learning-focused run (may explore more)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetType(str, Enum):
    HOST = "host"
    SERVICE = "service"
    WEB_APP = "web_app"
    API = "api"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    UNKNOWN = "unknown"


class Scope(BaseModel):
    """Authorized attack surface definition."""
    name: str = "default"
    ip_ranges: List[IPvAnyNetwork] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    endpoints: List[str] = Field(default_factory=list)
    cloud_accounts: List[str] = Field(default_factory=list)
    excluded_ips: List[IPvAnyAddress] = Field(default_factory=list)
    excluded_domains: List[str] = Field(default_factory=list)
    max_concurrent: int = 10
    rate_limit_rps: float = 5.0
    allow_destructive: bool = False  # Always False in production


class Asset(BaseModel):
    """Discovered asset."""
    id: UUID = Field(default_factory=uuid4)
    type: AssetType = AssetType.UNKNOWN
    address: str
    hostname: Optional[str] = None
    ports: List[int] = Field(default_factory=list)
    services: Dict[int, str] = Field(default_factory=dict)  # port -> service banner
    os_guess: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    in_scope: bool = True


class Vulnerability(BaseModel):
    """Matched vulnerability."""
    id: UUID = Field(default_factory=uuid4)
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    title: str
    description: str
    severity: Severity = Severity.MEDIUM
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    affected_asset_id: UUID
    evidence: Dict[str, Any] = Field(default_factory=dict)
    references: List[str] = Field(default_factory=list)


class AttackStep(BaseModel):
    """Single step in an attack path."""
    id: UUID = Field(default_factory=uuid4)
    technique_id: str  # MITRE ATT&CK or custom
    name: str
    description: str
    target_asset_id: UUID
    payload_summary: str  # Never the full destructive payload
    success: Optional[bool] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)


class AttackPath(BaseModel):
    """Complete attack chain."""
    id: UUID = Field(default_factory=uuid4)
    name: str
    steps: List[AttackStep] = Field(default_factory=list)
    root_cause: Optional[str] = None
    impact: Severity = Severity.MEDIUM
    remediation: List[str] = Field(default_factory=list)
    success: bool = False
    created_at: datetime = Field(default_factory=_utcnow)


class SafetyEvent(BaseModel):
    """Record of a safety decision or intervention."""
    id: UUID = Field(default_factory=uuid4)
    event_type: str  # e.g. "scope_violation", "health_abort", "payload_blocked"
    severity: Severity
    message: str
    context: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)


class CampaignResult(BaseModel):
    """Outcome of a full campaign."""
    campaign_id: UUID = Field(default_factory=uuid4)
    mode: CampaignMode
    scope_name: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    assets_discovered: int = 0
    vulnerabilities_found: int = 0
    attack_paths: List[AttackPath] = Field(default_factory=list)
    safety_events: List[SafetyEvent] = Field(default_factory=list)
    success: bool = False
    summary: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentMessage(BaseModel):
    """Inter-agent communication message."""
    id: UUID = Field(default_factory=uuid4)
    sender: str
    recipient: str  # or "broadcast"
    msg_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_utcnow)
    correlation_id: Optional[UUID] = None
