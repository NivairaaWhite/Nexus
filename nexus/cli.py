"""Nexus command-line interface (click-based)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from nexus.agents import (
    AnalystAgent,
    ChroniclerAgent,
    EvolutorAgent,
    OperatorAgent,
    ScoutAgent,
)
from nexus.core.orchestrator import Orchestrator
from nexus.core.types import CampaignMode, Scope
from nexus.utils.logging import setup_logging

console = Console()


def load_config(path: Path) -> dict:
    if not path.exists():
        console.print(f"[red]Config not found: {path}[/red]")
        raise SystemExit(1)
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


@click.group()
@click.version_option(package_name="nexus-cart", prog_name="nexus")
def app():
    """Nexus — Self-Evolving CART / BAS Platform"""
    pass


@app.command()
@click.option("--config", "-c", "config_path", default="config.yaml", type=click.Path(), help="Path to config YAML")
@click.option(
    "--mode",
    "-m",
    default="observe",
    type=click.Choice(["observe", "prove", "simulate", "evolve"], case_sensitive=False),
    help="Campaign mode",
)
@click.option("--log-level", default="INFO", help="Logging level")
def run(config_path: str, mode: str, log_level: str):
    """Run a Nexus campaign."""
    setup_logging(level=log_level)
    cfg = load_config(Path(config_path))
    campaign_mode = CampaignMode(mode.lower())

    scope = build_scope(cfg)
    console.print(
        Panel.fit(
            f"[bold green]Nexus[/bold green] starting campaign in [cyan]{campaign_mode.value}[/cyan] mode\n"
            f"Scope: [yellow]{scope.name}[/yellow] | Domains: {scope.domains} | IP ranges: {len(scope.ip_ranges)}",
            title="Campaign Launch",
        )
    )

    orchestrator = Orchestrator(scope=scope, mode=campaign_mode, config=cfg)

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
    table = Table(title="Campaign Result", show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Campaign ID", str(result.campaign_id))
    table.add_row("Mode", result.mode.value)
    table.add_row("Success", str(result.success))
    table.add_row("Duration (s)", str(result.duration_seconds or "n/a"))
    table.add_row("Assets", str(result.assets_discovered))
    table.add_row("Vulnerabilities", str(result.vulnerabilities_found))
    table.add_row("Attack Paths", str(len(result.attack_paths)))
    table.add_row("Successful Paths", str(sum(1 for p in result.attack_paths if p.success)))
    table.add_row("Safety Events", str(len(result.safety_events)))
    table.add_row("Summary", result.summary)
    console.print(table)

    if result.safety_events:
        console.print("\n[yellow]Safety Events:[/yellow]")
        for e in result.safety_events[:15]:
            console.print(f"  • [{e.severity.value}] {e.event_type}: {e.message}")
        if len(result.safety_events) > 15:
            console.print(f"  … and {len(result.safety_events) - 15} more")


@app.command()
def version():
    """Show Nexus version."""
    from nexus import __version__
    console.print(f"[bold]Nexus[/bold] v{__version__}")


@app.command()
@click.option("--config", "-c", "config_path", default="config.yaml", type=click.Path())
def validate(config_path: str):
    """Validate a configuration file."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        raise SystemExit(1)
    try:
        cfg = load_config(path)
        scope = build_scope(cfg)
        console.print(f"[green]Config OK[/green] — scope '{scope.name}'")
        console.print(f"  IP ranges : {len(scope.ip_ranges)}")
        console.print(f"  Domains   : {scope.domains}")
        console.print(f"  Max concurrent: {scope.max_concurrent}")
        console.print(f"  Rate limit RPS: {scope.rate_limit_rps}")
    except Exception as e:
        console.print(f"[red]Validation failed: {e}[/red]")
        raise SystemExit(1)


if __name__ == "__main__":
    app()
