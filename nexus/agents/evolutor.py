"""Evolutor Agent — Self-Evolution & Adaptation Engine."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from nexus.agents.base import BaseAgent
from nexus.core.types import Asset, AttackPath, SafetyEvent, Vulnerability
from nexus.utils.logging import get_bound_logger

logger = get_bound_logger(__name__)


class EvolutorAgent(BaseAgent):
    """Learns from campaign outcomes and improves future behavior.

    Mechanisms:
    - Experience replay buffer (JSONL)
    - Technique success-rate tracking
    - Environment profile updates
    - Policy suggestions for Orchestrator / Analyst
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
                    "priority": p.priority,
                    "techniques": [s.technique_id for s in p.steps],
                }
                for p in paths
            ],
            "safety_events_count": len(safety_events),
            "environment_hints": self._extract_env_hints(assets),
        }

        with self.experience_file.open("a") as f:
            f.write(json.dumps(experience, default=str) + "\n")

        policy = self._load_policy()
        for p in paths:
            for step in p.steps:
                tech = step.technique_id
                stats = policy.setdefault("techniques", {}).setdefault(
                    tech, {"attempts": 0, "successes": 0, "avg_priority": 0.0}
                )
                stats["attempts"] += 1
                if p.success:
                    stats["successes"] += 1
                # Running average of path priority
                n = stats["attempts"]
                stats["avg_priority"] = ((stats["avg_priority"] * (n - 1)) + p.priority) / n

        policy["last_updated"] = datetime.now(timezone.utc).isoformat()
        policy["total_campaigns"] = policy.get("total_campaigns", 0) + 1

        # Environment profile
        env = policy.setdefault("environments", {})
        for hint_tech in experience["environment_hints"].get("technologies", []):
            env[hint_tech] = env.get(hint_tech, 0) + 1

        self._save_policy(policy)
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
            "avg_risk": round(sum(a.risk_score for a in assets) / max(1, len(assets)), 2),
        }

    def _load_policy(self) -> Dict[str, Any]:
        if self.policy_file.exists():
            try:
                return json.loads(self.policy_file.read_text())
            except json.JSONDecodeError:
                logger.warning("corrupt_policy_file_reset")
        return {"techniques": {}, "total_campaigns": 0, "environments": {}}

    def _save_policy(self, policy: Dict[str, Any]) -> None:
        self.policy_file.write_text(json.dumps(policy, indent=2, default=str))

    def _generate_suggestions(
        self, policy: Dict[str, Any], experience: Dict[str, Any]
    ) -> List[str]:
        suggestions: List[str] = []
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
        avg_risk = experience.get("environment_hints", {}).get("avg_risk", 0)
        if avg_risk > 6.0:
            suggestions.append(
                f"Environment average risk score is high ({avg_risk}). "
                "Focus next campaigns on high-value paths."
            )
        return suggestions

    async def run(self, *args, **kwargs):
        return await self.learn(*args, **kwargs)
