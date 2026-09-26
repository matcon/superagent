#compdef superagent

_superagent() {
    local -a subcommands
    subcommands=(
        'telemetry:System hardware & Niri state telemetry'
        'memory:Tripartite episodic and knowledge memory'
        'verify:Closed-loop test verification with git checkpoints'
        'dag:Parallel DAG task orchestration'
        'jit:Just-In-Time tool synthesizer'
        'notify:Desktop notification delivery'
        'swe:Autonomous SWE Superintelligence suite'
        'devsecops:DevSecOps, SAST, and hardened deployment suite'
        'doctor:System health & environment diagnostics'
        'version:Display engine version and build metadata'
        'benchmark:Computational throughput and latency benchmarks'
        'mcp:Native Model Context Protocol (MCP) server'
    )

    _arguments -C \
        '1: :->subcmd' \
        '*:: :->args'

    case $state in
        subcmd)
            _describe -t subcommands 'superagent subcommands' subcommands
            ;;
        args)
            case $line[1] in
                swe)
                    local -a swe_actions
                    swe_actions=(
                        'audit:Audit codebase for SAST and AST complexity'
                        'guard:Validate AST syntax and McCabe complexity'
                        'plan:Decompose technical objective into 5-phase SWE DAG'
                        'spec:Generate Design-by-Contract Pydantic specification'
                        'fix:Autonomous atomic remediation of SAST/Docker violations'
                        'sandbox:Execute command in ephemeral Git worktree sandbox'
                    )
                    _describe -t swe_actions 'swe actions' swe_actions
                    ;;
                devsecops)
                    local -a ds_actions
                    ds_actions=(
                        'audit:Static SAST audit with Shannon entropy and OWASP detection'
                        'container-check:Audit Dockerfile against non-root and distroless standards'
                        'generate:Generate hardened distroless Dockerfile, K8s, or CI/CD'
                    )
                    _describe -t ds_actions 'devsecops actions' ds_actions
                    ;;
                memory)
                    local -a mem_actions
                    mem_actions=(
                        'add:Record problem/solution learning'
                        'search:Query episodic memory with BM25 FTS5'
                        'graph:Query Graphify architecture knowledge'
                    )
                    _describe -t mem_actions 'memory actions' mem_actions
                    ;;
                mcp)
                    local -a mcp_actions
                    mcp_actions=('serve:Start stdio JSON-RPC 2.0 MCP server')
                    _describe -t mcp_actions 'mcp actions' mcp_actions
                    ;;
            esac
            ;;
    esac
}

_superagent "$@"
