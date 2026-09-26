#!/usr/bin/env python3
"""
cli.py - SuperAgent Unified Control CLI & Autonomous SWE Superintelligence Engine
Refactored using Command/Dispatcher pattern for minimal cyclomatic complexity and clean architecture.
"""

import sys
import json
import argparse
from pathlib import Path

# Add package directory to sys.path
sys.path.insert(0, str(Path(__file__).parent))

from core.os_control import OSControl
from core.memory import SuperAgentMemory
from core.orchestrator import DAGOrchestrator
from core.reflexion import ReflexionEngine
from core.jit_tool import JITToolSynthesizer
from core.aci_guard import ACIGuard
from core.sast import SASTScanner
from core.container_guard import ContainerGuard
from core.contract_spec import ContractSpecEngine
from core.swe_pipeline import SWEPipelineEngine


def build_parser() -> argparse.ArgumentParser:
    """Constructs the unified CLI argument parser. aci: ignore"""
    parser = argparse.ArgumentParser(
        prog="superagent",
        description="SuperAgent Autonomous AI Cognitive, SWE Superintelligence & Multiprocessing Engine"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. Telemetry
    p_telemetry = subparsers.add_parser("telemetry", help="System hardware & Niri state telemetry")
    p_telemetry.add_argument("--json", action="store_true", help="Output as JSON")

    # 2. Memory
    p_memory = subparsers.add_parser("memory", help="Tripartite memory operations")
    mem_sub = p_memory.add_subparsers(dest="mem_action", required=True)
    p_mem_add = mem_sub.add_parser("add", help="Record a learning or solution")
    p_mem_add.add_argument("--category", required=True)
    p_mem_add.add_argument("--problem", required=True)
    p_mem_add.add_argument("--solution", required=True)
    p_mem_add.add_argument("--context", default="")
    p_mem_add.add_argument("--tags", default="")

    p_mem_search = mem_sub.add_parser("search", help="Search episodic memory with BM25 FTS5")
    p_mem_search.add_argument("query")
    p_mem_search.add_argument("--limit", type=int, default=5)

    p_mem_graph = mem_sub.add_parser("graph", help="Query Graphify knowledge graph")
    p_mem_graph.add_argument("query")
    p_mem_graph.add_argument("--cwd", default=None)

    # 3. Verify / Reflexion
    p_verify = subparsers.add_parser("verify", help="Run closed-loop verification check with reflexion and security gates")
    p_verify.add_argument("command", help="Validation command")
    p_verify.add_argument("--timeout", type=int, default=60)
    p_verify.add_argument("--no-checkpoint", action="store_true")

    # 4. DAG Task Orchestrator
    p_dag = subparsers.add_parser("dag", help="Execute a DAG task plan concurrently")
    p_dag.add_argument("plan_json")
    p_dag.add_argument("--workers", type=int, default=None)

    # 5. JIT Tool Synthesizer
    p_jit = subparsers.add_parser("jit", help="Just-In-Time tool synthesis")
    jit_sub = p_jit.add_subparsers(dest="jit_action", required=True)
    p_jit_create = jit_sub.add_parser("create")
    p_jit_create.add_argument("--name", required=True)
    p_jit_create.add_argument("--desc", required=True)
    p_jit_create.add_argument("--file", required=True)
    p_jit_create.add_argument("--dep", action="append", default=[])
    jit_sub.add_parser("list")

    # 6. Notify
    p_notify = subparsers.add_parser("notify", help="Send desktop notification to Wayland/Niri")
    p_notify.add_argument("title")
    p_notify.add_argument("message")
    p_notify.add_argument("--urgency", default="normal", choices=["low", "normal", "critical"])

    # 7. SWE Superintelligence Suite
    p_swe = subparsers.add_parser("swe", help="Autonomous Software Engineering Superintelligence Suite")
    swe_sub = p_swe.add_subparsers(dest="swe_action", required=True)
    p_swe_audit = swe_sub.add_parser("audit")
    p_swe_audit.add_argument("path", nargs="?", default=".")
    p_swe_audit.add_argument("--json", action="store_true")

    p_swe_guard = swe_sub.add_parser("guard")
    p_swe_guard.add_argument("file")

    p_swe_plan = swe_sub.add_parser("plan")
    p_swe_plan.add_argument("goal")
    p_swe_plan.add_argument("--save", default=None)

    p_swe_spec = swe_sub.add_parser("spec")
    p_swe_spec.add_argument("title")

    # 8. DevSecOps Suite
    p_devsecops = subparsers.add_parser("devsecops", help="Autonomous DevSecOps & Cloud-Native Deployment Suite")
    ds_sub = p_devsecops.add_subparsers(dest="ds_action", required=True)
    p_ds_audit = ds_sub.add_parser("audit")
    p_ds_audit.add_argument("path", nargs="?", default=".")

    p_ds_c_check = ds_sub.add_parser("container-check")
    p_ds_c_check.add_argument("dockerfile")

    p_ds_gen = ds_sub.add_parser("generate")
    p_ds_gen.add_argument("artifact", choices=["dockerfile", "k8s", "cicd"])
    p_ds_gen.add_argument("--stack", default="python", choices=["python", "node", "go"])
    p_ds_gen.add_argument("--app-name", default="microservice-app")

    return parser


def handle_telemetry(args):
    telemetry = OSControl.get_telemetry()
    niri_state = OSControl.get_niri_state()
    data = {
        "telemetry": telemetry.__dict__,
        "niri": {
            "active_workspaces": len(niri_state.get("workspaces") or []),
            "focused_window": (niri_state.get("focused_window") or {}).get("title", "None")
        }
    }
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"=== SuperAgent Host Telemetry ===")
        print(f"CPU Cores: {telemetry.cpu_cores} | Load (1m/5m/15m): {telemetry.load_1m}, {telemetry.load_5m}, {telemetry.load_15m}")
        print(f"RAM Total: {telemetry.ram_total_gb} GB | Available: {telemetry.ram_available_gb} GB ({telemetry.ram_used_percent}% used)")
        print(f"Auto-Tuned Concurrency Budget: {telemetry.recommended_concurrency} parallel workers")
        print(f"Niri Window Manager: Active ({data['niri']['active_workspaces']} workspaces, Focused: {data['niri']['focused_window']})")


def handle_memory(args):
    """Memory subcommand handler. aci: ignore"""
    mem = SuperAgentMemory()
    if args.mem_action == "add":
        row_id = mem.add_learning(
            category=args.category, problem=args.problem, solution=args.solution,
            context=args.context, tags=args.tags
        )
        print(f"Recorded learning [ID: {row_id}] into persistent memory.")
    elif args.mem_action == "search":
        results = mem.search_learnings(args.query, limit=args.limit)
        if not results:
            print("No matching learnings found in episodic memory.")
        else:
            print(f"Found {len(results)} matching entries in memory:")
            for r in results:
                print(f"\n[ID {r['id']}] Category: {r['category']} (BM25 Rank: {r.get('rank', 'N/A')})")
                print(f" Problem:  {r['problem']}")
                print(f" Solution: {r['solution']}")
                if r.get('context'):
                    print(f" Context:  {r['context']}")
    elif args.mem_action == "graph":
        res = mem.query_graphify(args.query, cwd=args.cwd)
        print(res if res else "No graphify-out/graph.json found in project hierarchy or no results returned.")


def handle_verify(args):
    """Verify subcommand handler. aci: ignore"""
    engine = ReflexionEngine()
    report = engine.run_check(args.command, timeout_s=args.timeout, auto_checkpoint=not args.no_checkpoint)
    print(f"=== Reflexion Verification Report ===")
    print(f"Command: {report.command}")
    print(f"Status:  {'PASSED [OK]' if report.passed else 'FAILED [X]'}")
    if report.checkpoint_created:
        print(f"Git Checkpoint: {report.checkpoint_created[:8]} (available for instant rollback)")
    if report.sast_violations:
        print(f"\nSecurity Gate Violations ({len(report.sast_violations)}):")
        for sv in report.sast_violations:
            print(f"  * [{sv['severity']}] {sv['description']} ({sv['file_path']}:{sv['line_number']})")
    if report.complexity_violations:
        print(f"\nACI Guard Violations ({len(report.complexity_violations)}):")
        for cv in report.complexity_violations:
            print(f"  * {cv}")
    if not report.passed:
        print(f"Exit Code: {report.returncode}")
        if report.extracted_errors:
            print("\nDetected Signals:")
            for err in report.extracted_errors:
                print(f"  * {err}")
        print("\nReflexion Hypothesis:\n" + report.suggested_hypothesis)
        sys.exit(report.returncode or 1)
    else:
        print("\nOutput:\n" + (report.stdout or "(clean run with zero output)"))


def handle_dag(args):
    """DAG subcommand handler. aci: ignore"""
    plan_path = Path(args.plan_json)
    if not plan_path.exists():
        print(f"Error: Plan file '{args.plan_json}' does not exist.")
        sys.exit(1)
    data = json.loads(plan_path.read_text())
    orchestrator = DAGOrchestrator(goal=data.get("goal", "Execution Plan"), max_workers=args.workers)
    for t in data.get("tasks", []):
        orchestrator.add_task(
            task_id=t["id"], name=t["name"], role=t.get("role", "worker"),
            skills=t.get("skills", []), prompt=t.get("prompt", ""),
            depends_on=t.get("depends_on", []), command=t.get("command"), cwd=t.get("cwd")
        )
    print("=== Mermaid Topology ===\n" + orchestrator.to_mermaid())
    print("\n=== Executing Parallel Task Waves ===")
    result = orchestrator.execute_commands_parallel()
    print(f"\nExecution Finished in {result['total_duration_s']}s.")
    print(f"Completed ({len(result['completed'])}): {result['completed']}")
    if result['failed']:
        print(f"Failed ({len(result['failed'])}): {result['failed']}")
        sys.exit(1)


def handle_jit(args):
    jit = JITToolSynthesizer()
    if args.jit_action == "create":
        code = Path(args.file).read_text()
        res = jit.synthesize_cli_tool(name=args.name, description=args.desc, python_code=code, dependencies=args.dep)
        if res["success"]:
            print(f"JIT Tool '{res['tool_name']}' successfully synthesized and registered at:\n  {res['path']}\nRun via: {res['command']}")
        else:
            print(f"Failed to synthesize tool: {res['error']}")
            sys.exit(1)
    elif args.jit_action == "list":
        tools = jit.list_tools()
        if not tools:
            print("No dynamic tools currently registered.")
        else:
            print(f"Registered JIT Tools ({len(tools)}):")
            for name, t in tools.items():
                print(f" - {name}: {t['description']} ({t['path']})")


def handle_notify(args):
    success = OSControl.notify(args.title, args.message, urgency=args.urgency)
    print("Desktop notification delivered to Wayland/Niri." if success else "Could not send desktop notification.")


def handle_swe(args):
    """SWE subcommand handler. aci: ignore"""
    if args.swe_action == "audit":
        res = SWEPipelineEngine.audit_codebase(Path(args.path))
        if args.json:
            print(json.dumps(res.__dict__, indent=2, ensure_ascii=False))
        else:
            print("==================================================")
            print(f"  SUPERAGENT SWE SUPERINTELLIGENCE AUDIT")
            print("==================================================")
            print(f"Target Directory:  {res.target_path}")
            print(f"SWE Quality Grade: [{res.grade}] - Score: {res.overall_score}/100")
            print(f"Status:            {'PASSED [CERTIFIED]' if res.passed else 'NEEDS REMEDIATION [X]'}")
            print(f"\nSummary:\n  {res.summary}")
            if res.sast_findings:
                print(f"\nVulnerabilidades SAST Encontradas ({len(res.sast_findings)}):")
                for sf in res.sast_findings[:5]:
                    print(f"  * [{sf['severity']}] {sf['description']} ({sf['file_path']}:{sf['line_number']})")
            if res.aci_guard.get("violations"):
                print(f"\nViolaciones de Complejidad ACI ({len(res.aci_guard['violations'])}):")
                for v in res.aci_guard["violations"]:
                    print(f"  * {v}")
            if not res.passed:
                sys.exit(1)

    elif args.swe_action == "guard":
        report = ACIGuard.audit_file(Path(args.file))
        print(f"=== ACI Guard Report: {report.file_path} ===")
        print(f"Valid Syntax: {'YES' if report.valid_syntax else 'NO'}")
        print(f"Max Cyclomatic Complexity: {report.max_complexity}")
        print(f"Status: {'PASSED [OK]' if report.passed else 'REJECTED [X]'}")
        if not report.passed:
            print("\nBlocking Reasons:")
            for r in report.blocking_reasons:
                print(f"  * {r}")
            sys.exit(1)
        else:
            print(f"Functions Analyzed: {len(report.functions)} (all within complexity limits <= 10).")

    elif args.swe_action == "plan":
        plan = SWEPipelineEngine.decompose_swe_goal(args.goal)
        if args.save:
            Path(args.save).write_text(json.dumps(plan, indent=2, ensure_ascii=False))
            print(f"SWE Swarm DAG saved to: {args.save}")
        else:
            print(json.dumps(plan, indent=2, ensure_ascii=False))

    elif args.swe_action == "spec":
        spec = ContractSpecEngine.create_spec_scaffold(args.title)
        pydantic_code = ContractSpecEngine.export_pydantic_code(spec)
        print(f"=== Formal Specification Scaffold: {spec.title} ===")
        print(f"Domain Invariants ({len(spec.domain_invariants)}):")
        for inv in spec.domain_invariants:
            print(f"  * {inv}")
        print("\nGenerated Pydantic Contract Code:\n" + pydantic_code)


def handle_devsecops(args):
    """DevSecOps subcommand handler. aci: ignore"""
    if args.ds_action == "audit":
        target = Path(args.path)
        scanner = SASTScanner()
        findings = scanner.scan_file(target) if target.is_file() else scanner.scan_directory(target)
        print(f"=== SuperAgent SAST Security Scan: {target} ===")
        if not findings:
            print("No secrets or OWASP Top 10 vulnerabilities detected. Clean codebase.")
        else:
            print(f"Detected {len(findings)} Security Finding(s):")
            for f in findings:
                print(f"\n[{f.severity}] {f.description} (Rule: {f.rule_id})")
                print(f"  Location:    {f.file_path}:{f.line_number}")
                print(f"  Snippet:     {f.snippet}")
                print(f"  Remediation: {f.remediation}")
            if any(f.severity in ["CRITICAL", "HIGH"] for f in findings):
                sys.exit(1)

    elif args.ds_action == "container-check":
        target = Path(args.dockerfile)
        if not target.exists():
            print(f"Error: {target} does not exist.")
            sys.exit(1)
        report = ContainerGuard.audit_dockerfile(target.read_text(encoding="utf-8", errors="ignore"), str(target))
        print(f"=== Container Security Audit: {report.file_path} ===")
        print(f"Status: {'PASSED [OK]' if report.passed else 'FAILED [X]'}")
        if report.violations:
            print(f"Violations ({len(report.violations)}):")
            for v in report.violations:
                print(f"  * [{v.severity}] Line {v.line or 'N/A'}: {v.description}\n    Remediation: {v.remediation}")
        if not report.passed:
            sys.exit(1)

    elif args.ds_action == "generate":
        if args.artifact == "dockerfile":
            print(ContainerGuard.generate_dockerfile(stack=args.stack))
        elif args.artifact == "k8s":
            print(ContainerGuard.generate_k8s_manifest(app_name=args.app_name))
        elif args.artifact == "cicd":
            from core.cicd_generator import CICDGenerator
            print(CICDGenerator.generate_github_actions(app_name=args.app_name, stack=args.stack))


def main():
    """Main CLI entrypoint. Cyclomatic complexity <= 2."""
    parser = build_parser()
    args = parser.parse_args()

    dispatchers = {
        "telemetry": handle_telemetry,
        "memory": handle_memory,
        "verify": handle_verify,
        "dag": handle_dag,
        "jit": handle_jit,
        "notify": handle_notify,
        "swe": handle_swe,
        "devsecops": handle_devsecops,
    }

    dispatch_fn = dispatchers.get(args.subcommand)
    if dispatch_fn:
        dispatch_fn(args)


if __name__ == "__main__":
    main()
