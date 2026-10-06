# Nexus — Advanced Self-Evolving Continuous Automated Red Teaming (CART) / Breach & Attack Simulation (BAS) Platform

**Nexus** is a multi-agent, safety-first, self-evolving red-teaming platform.  
It continuously discovers assets, builds attack graphs, executes **non-destructive** proof-of-concept exploits, learns from every campaign, and adapts to the target environment and defensive posture.

## Key Features

- **Strict Safety Kernel**: Whitelisting, destructive-payload blocking, real-time health monitoring, blast-radius estimation.
- **Multi-Agent Architecture**: Scout → Analyst → Operator → Guardian → Chronicler → Evolutor, coordinated by an Orchestrator.
- **Self-Evolution**: Experience replay, policy improvement, threat-intel fusion, environment-specific adaptation profiles.
- **Non-Destructive PoCs**: Only safe, reversible, or purely observational actions are allowed.
- **Full Auditability**: Immutable attack-path logging + automated remediation mapping.
- **Cloud-Native Ready**: Kubernetes manifests, Docker Compose, OpenTelemetry, policy-as-code.

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

# 4. Run a dry-run campaign (safe mode)
nexus run --config config.yaml --mode observe

# 5. Run with safe exploitation (still non-destructive)
nexus run --config config.yaml --mode prove
```

## Architecture Overview

```
Control Plane
├── Orchestrator (LLM + Policy Engine)
├── Knowledge Graph (Neo4j / in-memory)
└── Safety Kernel (Guardian)

Agents
├── Scout          – Passive + Active Recon
├── Analyst        – CVE matching, Attack Graph, Decision
├── Operator       – Safe Exploitation & Lateral Movement Simulation
├── Guardian       – Scope & Health enforcement (always-on)
├── Chronicler     – Telemetry, Logging, Remediation, Ticketing
└── Evolutor       – Learning, Adaptation, Policy Improvement
```

See `docs/architecture.md` for detailed design.

## Safety Guarantees (Non-Negotiable)

1. Destructive primitives are stripped at payload generation time.
2. Scope is enforced at both network and application layers.
3. Any detected target instability automatically freezes the campaign.
4. Every action is logged immutably with full decision rationale.

## Project Layout

```
nexus/
├── agents/          # Multi-agent implementations
├── core/            # Orchestrator, message bus, shared types
├── safety/          # Safety Kernel, Guardian, Policy Engine
├── recon/           # Discovery engines
├── analysis/        # Vulnerability analysis & attack graphs
├── exploit/         # Safe PoC library & Operator
├── telemetry/       # Logging, reporting, integrations
├── evolution/       # Self-evolution / learning loop
├── knowledge/       # Knowledge graph schemas & stores
├── config/          # Default configuration
└── utils/           # Shared helpers
```

## License

Apache-2.0 (see LICENSE)

---
Built for continuous, safe, and progressively more powerful automated red teaming.
