# Nexus — Advanced Self-Evolving Continuous Automated Red Teaming (CART) / Breach & Attack Simulation (BAS) Platform

**Nexus v0.2.0** is a multi-agent, safety-first, self-evolving red-teaming platform.  
It continuously discovers assets, builds attack graphs, executes **non-destructive** proof-of-concept exploits, learns from every campaign, and adapts to the target environment and defensive posture.

## What's New in 0.2.0

- Concurrent safe HTTP fingerprinting (httpx) in Scout
- Asset risk scoring + prioritized multi-step attack paths
- Configurable safety thresholds (latency / error-rate)
- Markdown + JSON campaign reports
- Richer Evolutor policy (technique success + environment profiles)
- Click-based CLI with `validate` command
- Removed hard dependency on structlog / typer / aiohttp for core
- Expanded tests and cleaner package layout
- Duration tracking, better logging adapter

## Key Features

- **Strict Safety Kernel**: Whitelisting, destructive-payload blocking (incl. reverse shells), real-time health monitoring, blast-radius estimation.
- **Multi-Agent Architecture**: Scout → Analyst → Operator → Chronicler → Evolutor, coordinated by an Orchestrator.
- **Self-Evolution**: Experience replay, policy improvement, threat-intel fusion, environment-specific adaptation profiles.
- **Non-Destructive PoCs**: Only safe, reversible, or purely observational actions are allowed.
- **Full Auditability**: Immutable attack-path logging + automated remediation mapping + Markdown reports.
- **Cloud-Native Ready**: Docker support, extensible for Kubernetes.

## Quick Start

```bash
# 1. Create virtual environment
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows

# 2. Install
pip install -e .

# 3. Copy and edit configuration
cp nexus/config/default.yaml config.yaml
# Edit scope, credentials, safety thresholds, etc.

# 4. Validate config
nexus validate -c config.yaml

# 5. Run a dry-run campaign (safe mode)
nexus run --config config.yaml --mode observe

# 6. Run with safe exploitation (still non-destructive)
nexus run --config config.yaml --mode prove

# 7. Full simulation + learning
nexus run --config config.yaml --mode evolve
```

## Architecture Overview

```
Control Plane
├── Orchestrator (coordination + lifecycle)
├── Knowledge (in-memory / future Neo4j)
└── Safety Kernel (Guardian)

Agents
├── Scout          – Passive seeding + concurrent safe HTTP probing
├── Analyst        – Heuristic findings, risk scoring, NetworkX attack graphs
├── Operator       – Technique-aware non-destructive PoCs
├── Chronicler     – JSON + Markdown reports, remediation
└── Evolutor       – Experience replay, technique stats, suggestions
```

See `docs/architecture.md` for detailed design.

## Safety Guarantees (Non-Negotiable)

1. Destructive primitives are stripped / blocked at payload generation time.
2. Scope is enforced at both network and application layers.
3. Any detected target instability automatically freezes the campaign (configurable).
4. Every action is logged with full decision rationale.
5. Observe mode never executes payloads.

## Project Layout

```
nexus/
├── agents/          # Multi-agent implementations
├── core/            # Orchestrator, shared types
├── safety/          # Safety Kernel, Guardian
├── recon/           # (future) Discovery engines
├── analysis/        # (future) Advanced analysis
├── exploit/         # (future) PoC library
├── telemetry/       # (future) OpenTelemetry hooks
├── evolution/       # (future) RL / advanced learning
├── knowledge/       # (future) Graph store
├── config/          # Default configuration
└── utils/           # Logging & helpers
```

## License

Apache-2.0 (see LICENSE)

---
Built for continuous, safe, and progressively more powerful automated red teaming.
