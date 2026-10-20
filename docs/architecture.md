# Nexus Architecture (v0.2.0)

## Design Goals

1. **Safety first** — No destructive actions can ever leave the platform.
2. **Self-evolving** — Every campaign improves future performance.
3. **Environment adaptive** — Detects and adapts to observed technologies.
4. **Fully auditable** — Immutable logs + JSON/Markdown reports of every decision.
5. **Multi-agent** — Clear separation of concerns with coordinated phases.

## Component Responsibilities

### Safety Kernel (Guardian)
- Scope enforcement (IP / domain / endpoint allow-lists)
- Destructive payload sanitization / rejection (incl. reverse-shell patterns)
- Rate limiting & concurrency control
- Real-time target health monitoring → automatic abort (configurable thresholds)
- Blast-radius estimation

### Scout Agent
- Passive seeding from configured domains/hostnames
- Concurrent safe HTTP probing (HEAD/GET only, short timeouts) via httpx
- Technology fingerprinting from response headers
- Health snapshot feedback into Safety Kernel

### Analyst Agent
- Heuristic CVE / CWE style findings from ports + technologies
- Asset risk scoring (0-10)
- Attack-graph construction with NetworkX
- Path prioritization; multi-step paths in SIMULATE/EVOLVE modes

### Operator Agent
- Technique-aware non-destructive PoC execution only
- Target resolution via asset map
- Duration tracking per step
- Strict Safety Kernel gating on every request

### Chronicler Agent
- Immutable JSON reports
- Human-readable Markdown summaries with top risks & remediation
- Placeholder hooks for Jira / Slack / SIEM

### Evolutor Agent
- Experience replay buffer (JSONL)
- Technique success-rate + average priority tracking
- Environment technology profiles
- Actionable policy suggestions

### Orchestrator
- Campaign lifecycle management
- Sequential phase coordination under safety constraints
- Duration measurement
- Mode enforcement (observe / prove / simulate / evolve)

## Data Flow

```
Scope → Safety Kernel
         ↓
Scout → Assets → Analyst → Vulns + Prioritized Attack Paths
                              ↓
                         Operator (safe PoCs)
                              ↓
                         Chronicler (JSON + MD report)
                              ↓
                         Evolutor (learn & adapt)
```

## Future Extensions

- Full Neo4j knowledge graph
- LLM-powered planning (with safety filter)
- Reinforcement learning for path selection
- Digital-twin validation before live execution
- eBPF-based runtime enforcement
- Multi-tenant control plane
- Real NVD / EPSS / KEV integration
