# SuperAgent 🚀

**Autonomous AI Cognitive, SWE Superintelligence & Distributed Execution Engine**  
*Version: v2.2.0-frontier-hardened | Grade: A+ (100/100)*

SuperAgent is a high-performance, autonomous software engineering superintelligence (SWE-SI) and task orchestration engine. Built for high-reliability local development environments, SuperAgent provides closed-loop verification, episodic memory, static security analysis, container hardening, AST complexity guards, and native Model Context Protocol (MCP) server capabilities.

---

## Key Features

### 🧠 1. Tripartite Memory Architecture
- **Episodic & Reflexion Memory**: SQLite with full-text search (`FTS5`) and BM25 relevance ranking.
- **Concurrent WAL Hardening**: Non-blocking `PRAGMA journal_mode=WAL` with automated deduplication and memory compaction (`compact_learnings`).
- **Topological Code Understanding**: Deep integration with [Graphify](https://github.com) knowledge graphs (`graphify query`, `GRAPH_REPORT.md`).
- **Working Memory**: Dynamic execution context and scratch storage.

### 🛡️ 2. SWE Superintelligence & Closed-Loop Reflexion
- **Closed-Loop Verification (`verify`)**: Executes tests against ephemeral git checkpoints, analyzing root causes and triggering auto-remediation without regression.
- **Oscillation Guard**: SHA-256 failure state fingerprinting that detects and terminates cyclical or repetitive patch attempts.
- **AST Complexity Guard (`swe guard`)**: Enforces McCabe cyclomatic complexity $\le 15$, cognitive depth $\le 5$, reporting exact line spans (`lines start-end`).
- **Pre-Validated Auto-Fix (`swe fix`)**: Verifies `ast.parse()` in-memory before disk writes, generating Unified Diffs for full traceability.
- **Isolated Worktree Sandboxes (`swe sandbox`)**: Ephemeral Git worktree execution with safety promotion gates (`--promote`) and guaranteed `git worktree prune` cleanup.
- **Autonomous SWE Planning (`swe plan`)**: Decomposes technical objectives into 5 structured phases (Discovery, Contract, Implementation, Verification, Production Hardening).

### 🔒 3. DevSecOps & Hardened Infrastructure
- **SAST & Secrets Scanning**: Static security auditing detecting hardcoded secrets via Shannon entropy ($H > 4.5$) and OWASP Top 10 anti-patterns (SQLi, command injection, path traversal).
- **Container Hardening (`container-check`)**: Audits Dockerfiles for root user execution, non-multi-stage builds, and missing health checks.
- **Production Artifact Synthesis**: Generates distroless Dockerfiles, Kubernetes Restricted manifests, and auto-rollback CI/CD pipelines.

### ⚡ 4. Real Concurrency & DAG Swarm Orchestration
- **Kahn Topological Waves**: Mathematical cycle detection and wave-based concurrent execution scheduling.
- **Auto-Tuned Telemetry Budget**: Evaluates system memory, CPU load, and host headroom before dispatching worker pools to prevent swapping.

### 🔌 5. Model Context Protocol (MCP) & Host Integration
- **Native Stdio MCP Server (`mcp serve`)**: Exposes SuperAgent primitives to any MCP-compliant AI client over standard JSON-RPC 2.0.
- **Automated CI/CD**: Native GitHub Actions workflow testing diagnostics, security audits, and benchmarks on each push.
- **OS & Desktop Integration**: Native Wayland / Niri window manager IPC, Polkit graphical authentication (`pkexec`), and desktop notifications.
- **JIT Tool Synthesis (`jit`)**: Generates, validates via AST, and registers new Python runtime tools on the fly.
- **Host Benchmark (`benchmark`)**: Measures raw execution speeds (AST parsing throughput, Shannon entropy throughput, SQLite FTS5 QPS, Git latency).

---

## Installation

### Prerequisites
- Python 3.10+
- Git 2.30+
- SQLite3 with FTS5 enabled
- Linux (optimized for Arch Linux & Wayland/Niri, compatible with modern distributions)

### Setup
Clone the repository and link the CLI:

```bash
git clone https://github.com/matcon/superagent.git ~/.superagent
ln -s ~/.superagent/cli.py ~/.local/bin/superagent
chmod +x ~/.superagent/cli.py
```

### Shell Completions
SuperAgent comes with tab completion support for Bash, Zsh, and Fish:

```bash
# For Bash
echo 'source ~/.superagent/completions/superagent.bash' >> ~/.bashrc

# For Zsh
echo 'source ~/.superagent/completions/superagent.zsh' >> ~/.zshrc
```

Verify your installation with the built-in diagnostic tool:

```bash
superagent doctor
```

---

## Quick Reference CLI Guide

### System Health & Diagnostics
```bash
# Run 8 atomic system health checks
superagent doctor

# Benchmark host primitives (AST LOC/s, Shannon MB/s, FTS5 QPS)
superagent benchmark

# Host telemetry and recommended worker budget
superagent telemetry
```

### SWE & Code Quality
```bash
# Audit repository code quality & complexity
superagent swe audit .

# Enforce AST complexity constraints on a file (McCabe <= 15)
superagent swe guard src/app.py

# Decompose a technical objective into 5 SWE phases
superagent swe plan "Implement OAuth2 PKCE Authentication Flow"

# Auto-remediate SAST and Dockerfile issues
superagent swe fix src/

# Run experimental commands inside an ephemeral Git worktree
superagent swe sandbox "pytest -v" --promote --message "test: passing tests in sandbox"
```

### DevSecOps & Security
```bash
# Run local SAST security and high-entropy secret audit
superagent devsecops audit .

# Audit Dockerfile against production standards
superagent devsecops container-check Dockerfile

# Generate distroless Dockerfile, Kubernetes manifests, or CI/CD
superagent devsecops generate dockerfile --stack python
superagent devsecops generate k8s --app-name auth-service
superagent devsecops generate cicd --app-name auth-service --stack python
```

### Memory & Reflexion
```bash
# Search episodic memory using SQLite BM25 FTS5
superagent memory search "rustdesk flutter sigsegv"

# Record a new technical learning or bug solution
superagent memory add \
  --category "bugfix" \
  --problem "Connection timeout on high-latency links" \
  --solution "Implemented exponential backoff with jitter in client socket pool" \
  --context "src/network/client.py" \
  --tags "network,socket,timeout"

# Query project Graphify knowledge graph
superagent memory graph "How does the authentication middleware interact with session store?"
```

### Closed-Loop Verification
```bash
# Run closed-loop verification with automatic Git checkpointing
superagent verify "pytest tests/test_core.py"
```

### Native MCP Server
Run SuperAgent as an MCP server for AI coding assistants:

```bash
superagent mcp serve
```

---

## Architecture Overview

```text
~/.superagent/
├── cli.py                     # Command line dispatcher
├── core/                      # Engine modules
│   ├── memory.py              # Tripartite memory (FTS5 + BM25, Graphify)
│   ├── reflexion.py           # Verification loop & git checkpointing
│   ├── orchestrator.py        # DAG swarm & wave-based concurrency
│   ├── aci_guard.py           # AST complexity & cognitive depth checker
│   ├── sast.py                # Static security & Shannon entropy scanner
│   ├── auto_fix.py            # Automated code & Dockerfile self-healing
│   ├── worktree_sandbox.py    # Ephemeral worktree isolation with promotion gates
│   ├── doctor.py              # 8 atomic environment & toolchain diagnostics
│   ├── mcp_server.py          # Native stdio JSON-RPC 2.0 MCP server
│   ├── benchmark.py           # Host primitive benchmarking
│   ├── swe_pipeline.py        # 5-phase SWE plan generator
│   ├── container_guard.py     # Container security & Dockerfile linter
│   ├── cicd_generator.py      # Hardened CI/CD & K8s manifest synthesis
│   ├── contract_spec.py       # Pydantic schemas & Design-by-Contract
│   ├── test_rigor.py          # Test suite rigor and coverage evaluator
│   ├── os_control.py          # Host telemetry, Polkit (pkexec), Niri IPC
│   └── jit_tool.py            # Runtime tool synthesis
├── tools/                     # Registered JIT tools
└── completions/               # Shell completion scripts
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
