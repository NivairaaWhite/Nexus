"""Nexus — Advanced Self-Evolving CART / BAS Platform."""

__version__ = "0.2.0"
__author__ = "Nexus Contributors"

from nexus.core.orchestrator import Orchestrator
from nexus.core.types import CampaignMode, CampaignResult, Scope

__all__ = [
    "Orchestrator",
    "CampaignMode",
    "CampaignResult",
    "Scope",
    "__version__",
]
