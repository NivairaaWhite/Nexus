# Nexus Architecture

## Design Goals

1. **Safety first** — No destructive actions can ever leave the platform.
2. **Self-evolving** — Every campaign improves future performance.
3. **Environment adaptive** — Detects and adapts to cloud, K8s, on-prem, etc.
4. **Fully auditable** — Immutable logs of every decision and action.
5. **Multi-agent** — Clear separation of concerns with message-passing.

## Component Responsibilities

### Safety Kernel (Guardian)
- Scope enforcement (IP / domain / endpoint allow-lists)
- Destructive payload sanitization / rejection
- Rate limiting & concurrency control
- Real-time target health monitoring → automatic abort
- Blast-radius estimation

### Scout Agent
- Passive OSINT (CT logs, DNS, public sources)
- Active scanning (ports, services, web crawling) under safety gates
- Environment classification

### Analyst Agent
- CVE / CWE / EPSS matching
- Attack-graph construction (NetworkX today, Neo4j + GNN later)
- Path prioritization and decision logic

### Operator Agent
- Non-destructive Proof-of-Concept execution only
- Lateral-movement simulation with reversible artifacts
- Adaptive evasion (jitter, header mutation) with feedback to Evolutor

### Chronicler Agent
- Immutable attack-path logging
- Automated remediation mapping
- Integrations (Jira, Slack, SIEM, CI/CD)

### Evolutor Agent
- Experience replay buffer
- Technique success-rate tracking
- Policy improvement suggestions
- Environment-specific adaptation profiles

### Orchestrator
- Campaign lifecycle management
- Agent coordination
- Mode enforcement (observe / prove / simulate / evolve)

## Data Flow

```
Scope → Safety Kernel
         ↓
Scout → Assets → Analyst → Vulns + Attack Paths
                              ↓
                         Operator (safe PoCs)
                              ↓
                         Chronicler (report + tickets)
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
