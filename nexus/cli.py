"""Nexus command-line interface."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from nexus.agents import (
    AnalystAgent,
    ChroniclerAgent,
    EvolutorAgent,
    OperatorAgent,
    ScoutAgent,
)
from nexus.core.orchestrator import Orchestrator
from nexus.core.types import CampaignMode, Scope

app = typer.Typer(name="nexus", help="Nexus — Self-Evolving CART / BAS Platform")
console = Console()


def load_config(path: Path) -> dict:
    if not path.exists():
        console.print(f"[red]Config not found: {path}[/red]")
        raise typer.Exit(1)
    with path.open() as f:
        return yaml.safe_load(f) or {}


def build_scope(cfg: dict) -> Scope:
    scope_cfg = cfg.get("scope", {})
    return Scope(
        name=scope_cfg.get("name", "default"),
        ip_ranges=scope_cfg.get("ip_ranges", []),
        domains=scope_cfg.get("domains", []),
        hostnames=scope_cfg.get("hostnames", []),
        endpoints=scope_cfg.get("endpoints", []),
        max_concurrent=scope_cfg.get("max_concurrent", 5),
        rate_limit_rps=scope_cfg.get("rate_limit_rps", 2.0),
    )


@app.command()
def run(
    config: Path = typer.Option("config.yaml", "--config", "-c", help="Path to config YAML"),
    mode: str = typer.Option("observe", "--mode", "-m", help="observe | prove | simulate | evolve"),
):
    """Run a Nexus campaign."""
    cfg = load_config(config)
    try:
        campaign_mode = CampaignMode(mode.lower())
    except ValueError:
        console.print(f"[red]Invalid mode: {mode}[/red]")
        raise typer.Exit(1)

    scope = build_scope(cfg)
    console.print(f"[bold green]Nexus[/bold green] starting campaign in [cyan]{campaign_mode.value}[/cyan] mode")
    console.print(f"Scope: {scope.name} | Domains: {scope.domains} | IP ranges: {len(scope.ip_ranges)}")

    orchestrator = Orchestrator(scope=scope, mode=campaign_mode, config=cfg)

    # Wire agents
    scout = ScoutAgent(cfg.get("scout", {}))
    analyst = AnalystAgent(cfg.get("analyst", {}))
    operator = OperatorAgent(cfg.get("operator", {}))
    chronicler = ChroniclerAgent(cfg.get("chronicler", {}))
    evolutor = EvolutorAgent(cfg.get("evolutor", {}))

    orchestrator.register_agents(
        scout=scout,
        analyst=analyst,
        operator=operator,
        chronicler=chronicler,
        evolutor=evolutor,
    )

    result = asyncio.run(orchestrator.run())

    # Pretty print summary
    table = Table(title="Campaign Result")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Campaign ID", str(result.campaign_id))
    table.add_row("Mode", result.mode.value)
    table.add_row("Success", str(result.success))
    table.add_row("Assets", str(result.assets_discovered))
    table.add_row("Vulnerabilities", str(result.vulnerabilities_found))
    table.add_row("Attack Paths", str(len(result.attack_paths)))
    table.add_row("Successful Paths", str(sum(1 for p in result.attack_paths if p.success)))
    table.add_row("Safety Events", str(len(result.safety_events)))
    table.add_row("Summary", result.summary)
    console.print(table)

    if result.safety_events:
        console.print("\n[yellow]Safety Events:[/yellow]")
        for e in result.safety_events:
            console.print(f"  • [{e.severity.value}] {e.event_type}: {e.message}")


@app.command()
def version():
    """Show Nexus version."""
    from nexus import __version__
    console.print(f"Nexus v{__version__}")


if __name__ == "__main__":
    app()
