"""Base agent interface for Nexus multi-agent system."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import structlog

from nexus.core.types import AgentMessage

logger = structlog.get_logger(__name__)


class BaseAgent(ABC):
    """Abstract base class for all Nexus agents."""

    name: str = "base"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self._message_queue: list[AgentMessage] = []
        logger.info("agent_initialized", agent=self.name)

    async def send(self, recipient: str, msg_type: str, payload: Dict[str, Any]) -> None:
        """Send a message to another agent (or broadcast)."""
        msg = AgentMessage(
            sender=self.name,
            recipient=recipient,
            msg_type=msg_type,
            payload=payload,
        )
        self._message_queue.append(msg)
        logger.debug("message_sent", from_agent=self.name, to=recipient, type=msg_type)

    async def receive(self) -> list[AgentMessage]:
        """Drain pending messages."""
        msgs = self._message_queue[:]
        self._message_queue.clear()
        return msgs

    @abstractmethod
    async def run(self, *args, **kwargs) -> Any:
        """Main entry point for the agent."""
        ...
