"""Evolutor Agent — Self-Evolution & Adaptation Engine."""

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


class EvolutorAgent(BaseAgent):
    """Learns from campaign outcomes and improves future behavior.

    Mechanisms (scaffolded):
    - Experience replay buffer
    - Simple success-rate tracking per technique
    - Environment profile updates
    - Policy suggestions for the Orchestrator / Analyst
    """

    name = "evolutor"

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.memory_dir = Path(self.config.get("memory_dir", "./data/evolution"))
        self.memory_dir.mkdir(parents=True, exist_ok=True)
        self.experience_file = self.memory_dir / "experience.jsonl"
        self.policy_file = self.memory_dir / "policy.json"

    async def learn(
        self,
        assets: List[Asset],
        vulns: List[Vulnerability],
        paths: List[AttackPath],
        safety_events: List[SafetyEvent],
    ) -> Dict[str, Any]:
        logger.info("evolutor_learning_started")

        experience = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assets_count": len(assets),
            "vulns_count": len(vulns),
            "paths": [
                {
                    "name": p.name,
                    "success": p.success,
                    "impact": p.impact.value,
                    "techniques": [s.technique_id for s in p.steps],
                }
                for p in paths
            ],
            "safety_events_count": len(safety_events),
            "environment_hints": self._extract_env_hints(assets),
        }

        # Append to experience replay
        with self.experience_file.open("a") as f:
            f.write(json.dumps(experience) + "\n")

        # Update simple policy statistics
        policy = self._load_policy()
        for p in paths:
            for step in p.steps:
                tech = step.technique_id
                stats = policy.setdefault("techniques", {}).setdefault(
                    tech, {"attempts": 0, "successes": 0}
                )
                stats["attempts"] += 1
                if p.success:
                    stats["successes"] += 1

        policy["last_updated"] = datetime.now(timezone.utc).isoformat()
        policy["total_campaigns"] = policy.get("total_campaigns", 0) + 1
        self._save_policy(policy)

        # Generate adaptation suggestions
        suggestions = self._generate_suggestions(policy, experience)

        logger.info(
            "evolutor_learning_finished",
            campaigns=policy["total_campaigns"],
            suggestions=len(suggestions),
        )
        return {"policy": policy, "suggestions": suggestions}

    def _extract_env_hints(self, assets: List[Asset]) -> Dict[str, Any]:
        techs = set()
        for a in assets:
            techs.update(a.technologies)
        return {
            "technologies": list(techs),
            "asset_types": list({a.type.value for a in assets}),
        }

    def _load_policy(self) -> Dict[str, Any]:
        if self.policy_file.exists():
            return json.loads(self.policy_file.read_text())
        return {"techniques": {}, "total_campaigns": 0}

    def _save_policy(self, policy: Dict[str, Any]) -> None:
        self.policy_file.write_text(json.dumps(policy, indent=2))

    def _generate_suggestions(
        self, policy: Dict[str, Any], experience: Dict[str, Any]
    ) -> List[str]:
        suggestions = []
        techs = policy.get("techniques", {})
        for tech, stats in techs.items():
            if stats["attempts"] >= 3:
                rate = stats["successes"] / stats["attempts"]
                if rate < 0.3:
                    suggestions.append(
                        f"Technique {tech} has low success rate ({rate:.0%}). "
                        "Consider alternative paths or improved evasion."
                    )
                elif rate > 0.8:
                    suggestions.append(
                        f"Technique {tech} is highly effective ({rate:.0%}). "
                        "Prioritize in future attack graphs."
                    )
        if experience.get("safety_events_count", 0) > 5:
            suggestions.append(
                "High number of safety interventions. "
                "Tighten scope or reduce aggressiveness."
            )
        return suggestions

    async def run(self, *args, **kwargs):
        return await self.learn(*args, **kwargs)
