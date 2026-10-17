"""
core/mcp_server.py - Native Model Context Protocol (MCP) Server for SuperAgent
Implements JSON-RPC 2.0 over standard I/O (stdio) to expose SuperAgent capabilities directly to AI agents.
"""

import sys
import json
import traceback
from pathlib import Path
from dataclasses import asdict
from typing import Dict, Any, List, Optional

from .os_control import OSControl
from .doctor import SystemDoctor
from .memory import SuperAgentMemory
from .aci_guard import ACIGuard
from .sast import SASTScanner
from .swe_pipeline import SWEPipelineEngine
from .contract_spec import ContractSpecEngine
from .auto_fix import AutoFixEngine
from .reflexion import ReflexionEngine
from .container_guard import ContainerGuard
from .cicd_generator import CICDGenerator


class MCPServer:
    """Servidor MCP nativo sobre stdio sin dependencias externas."""

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "superagent-mcp"
    SERVER_VERSION = "2.1.0"

    @classmethod
    def _core_tool_defs(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "superagent_telemetry",
                "description": "Obtiene la telemetría de hardware (RAM, CPU, carga) y estado de Wayland/Niri.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "superagent_doctor",
                "description": "Ejecuta un diagnóstico exhaustivo del entorno del host, base de datos FTS5 y herramientas.",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "superagent_verify",
                "description": "Ejecuta un comando en bucle cerrado con checkpoint Git efímero y análisis de errores.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Comando a validar"},
                        "timeout": {"type": "integer", "description": "Timeout en segundos (por defecto 60)"}
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "superagent_devsecops_generate",
                "description": "Genera artefactos de infraestructura endurecidos (dockerfile distroless, k8s, cicd).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "artifact": {"type": "string", "enum": ["dockerfile", "k8s", "cicd"]},
                        "stack": {"type": "string", "enum": ["python", "node", "go"], "default": "python"},
                        "app_name": {"type": "string", "default": "microservice-app"}
                    },
                    "required": ["artifact"]
                }
            }
        ]

    @classmethod
    def _swe_tool_defs(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "superagent_swe_plan",
                "description": "Descompone un objetivo de software en el Grafo DAG de 5 fases ejecutables de The Agency (Spec, Threat Model, Implementation, Tests, Deploy) con roles y skills.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "goal": {"type": "string", "description": "Objetivo técnico o requerimiento a desarrollar"}
                    },
                    "required": ["goal"]
                }
            },
            {
                "name": "superagent_swe_spec",
                "description": "Genera una especificación formal Design-by-Contract y código con esquemas Pydantic v2 para un servicio antes de implementar.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string", "description": "Título o nombre del servicio/módulo"},
                        "domain_invariants": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Lista opcional de invariantes y reglas de negocio estrictas"
                        }
                    },
                    "required": ["title"]
                }
            },
            {
                "name": "superagent_swe_audit",
                "description": "Audita una base de código evaluando complejidad ciclomática AST, SAST y emite una calificación (A+ a F).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta al directorio a auditar (por defecto '.')"}
                    }
                }
            },
            {
                "name": "superagent_swe_guard",
                "description": "Verifica sintaxis AST, complejidad ciclomática de McCabe (<=15) y profundidad cognitiva (<=5) en un archivo Python.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Ruta al archivo Python"}
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "superagent_swe_fix",
                "description": "Ejecuta auto-curación y remediación atómica de vulnerabilidades SAST y Dockerfiles.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Archivo o directorio a auto-remediar"}
                    },
                    "required": ["path"]
                }
            }
        ]

    @classmethod
    def _memory_tool_defs(cls) -> List[Dict[str, Any]]:
        return [
            {
                "name": "superagent_memory_search",
                "description": "Busca en la memoria episódica persistente mediante búsqueda por texto completo SQLite BM25 FTS5.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Términos del problema o error a buscar"},
                        "limit": {"type": "integer", "description": "Número máximo de resultados"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "superagent_memory_add",
                "description": "Registra una lección técnica, solución a un bug o peculiaridad en la memoria episódica persistente (SQLite FTS5).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Categoría (ej. bug, config, architecture, performance)"},
                        "problem": {"type": "string", "description": "Descripción del problema o requerimiento"},
                        "solution": {"type": "string", "description": "Solución técnica aplicada y verificada"},
                        "context": {"type": "string", "description": "Contexto, archivo o comando relevante"},
                        "tags": {"type": "string", "description": "Etiquetas separadas por comas"}
                    },
                    "required": ["category", "problem", "solution"]
                }
            },
            {
                "name": "superagent_memory_graph",
                "description": "Consulta la topología del grafo de conocimiento Graphify si existe en el proyecto.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Pregunta o concepto arquitectónico a consultar en el grafo"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "superagent_devsecops_audit",
                "description": "Audita estáticamente código o directorio buscando credenciales/secretos por entropía de Shannon (>4.5) y anti-patrones OWASP Top 10.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Ruta al directorio o archivo a escanear (por defecto '.')"}
                    }
                }
            }
        ]

    @classmethod
    def get_tool_definitions(cls) -> List[Dict[str, Any]]:
        return cls._core_tool_defs() + cls._swe_tool_defs() + cls._memory_tool_defs()

    @classmethod
    def _tool_telemetry(cls, _args: Dict[str, Any]) -> str:
        t = OSControl.get_telemetry()
        n = OSControl.get_niri_state()
        return json.dumps({"telemetry": t.__dict__, "niri": n}, indent=2)

    @classmethod
    def _tool_doctor(cls, _args: Dict[str, Any]) -> str:
        report = SystemDoctor.run_diagnostics()
        return json.dumps({
            "healthy": report.healthy,
            "warnings": report.warnings,
            "failures": report.failures,
            "checks": [c.__dict__ for c in report.checks]
        }, indent=2)

    @classmethod
    def _tool_swe_audit(cls, args: Dict[str, Any]) -> str:
        p = Path(args.get("path", "."))
        res = SWEPipelineEngine.audit_codebase(p)
        return json.dumps(res.__dict__, indent=2, ensure_ascii=False)

    @classmethod
    def _tool_swe_guard(cls, args: Dict[str, Any]) -> str:
        f = Path(args["file_path"])
        rep = ACIGuard.audit_file(f)
        return json.dumps(rep.__dict__, indent=2, default=str)

    @classmethod
    def _tool_swe_fix(cls, args: Dict[str, Any]) -> str:
        p = Path(args["path"])
        rep = AutoFixEngine.remediate_directory(p) if p.is_dir() else AutoFixEngine.remediate_file(p)
        return json.dumps({
            "target": rep.target_path,
            "total_fixes": rep.total_fixes,
            "success": rep.success,
            "fixes": [f.__dict__ for f in rep.fixes]
        }, indent=2)

    @classmethod
    def _tool_verify(cls, args: Dict[str, Any]) -> str:
        engine = ReflexionEngine()
        rep = engine.run_check(args["command"], timeout_s=args.get("timeout", 60))
        return json.dumps(rep.__dict__, indent=2)

    @classmethod
    def _tool_memory_search(cls, args: Dict[str, Any]) -> str:
        mem = SuperAgentMemory()
        results = mem.search_learnings(args["query"], limit=args.get("limit", 5))
        return json.dumps(results, indent=2)

    @classmethod
    def _tool_devsecops_generate(cls, args: Dict[str, Any]) -> str:
        art = args["artifact"]
        stk = args.get("stack", "python")
        app = args.get("app_name", "microservice-app")
        if art == "dockerfile":
            return ContainerGuard.generate_dockerfile(stk)
        if art == "k8s":
            return ContainerGuard.generate_k8s_manifest(app)
        if art == "cicd":
            return CICDGenerator.generate_github_actions(app, stk)
        return f"Unknown artifact: {art}"

    @classmethod
    def _tool_swe_plan(cls, args: Dict[str, Any]) -> str:
        plan = SWEPipelineEngine.decompose_swe_goal(args["goal"])
        return json.dumps(plan, indent=2, ensure_ascii=False)

    @classmethod
    def _tool_swe_spec(cls, args: Dict[str, Any]) -> str:
        spec = ContractSpecEngine.create_spec_scaffold(args["title"], args.get("domain_invariants"))
        pydantic_code = ContractSpecEngine.export_pydantic_code(spec)
        return json.dumps({
            "spec": asdict(spec),
            "pydantic_scaffold": pydantic_code
        }, indent=2, ensure_ascii=False)

    @classmethod
    def _tool_devsecops_audit(cls, args: Dict[str, Any]) -> str:
        p = Path(args.get("path", "."))
        scanner = SASTScanner()
        if p.is_file():
            findings = scanner.scan_text(p.read_text(encoding="utf-8", errors="ignore"), filename=str(p))
        else:
            findings = scanner.scan_directory(p)
        return json.dumps({
            "target": str(p),
            "total_findings": len(findings),
            "findings": [asdict(f) for f in findings]
        }, indent=2, ensure_ascii=False)

    @classmethod
    def _tool_memory_add(cls, args: Dict[str, Any]) -> str:
        mem = SuperAgentMemory()
        row_id = mem.add_learning(
            category=args["category"],
            problem=args["problem"],
            solution=args["solution"],
            context=args.get("context", ""),
            tags=args.get("tags", "")
        )
        return json.dumps({"status": "OK", "recorded_id": row_id, "message": "Aprendizaje registrado con éxito en memoria persistente."})

    @classmethod
    def _tool_memory_graph(cls, args: Dict[str, Any]) -> str:
        res = SuperAgentMemory.query_graphify(args["query"])
        if res:
            return res
        return json.dumps({"status": "no_graph", "message": "No se encontró grafo graphify-out/graph.json en el directorio actual."})

    @classmethod
    def call_tool(cls, name: str, arguments: Dict[str, Any]) -> str:
        """Ejecuta una herramienta y devuelve la salida serializada en texto."""
        dispatch = {
            "superagent_telemetry": cls._tool_telemetry,
            "superagent_doctor": cls._tool_doctor,
            "superagent_swe_audit": cls._tool_swe_audit,
            "superagent_swe_guard": cls._tool_swe_guard,
            "superagent_swe_fix": cls._tool_swe_fix,
            "superagent_verify": cls._tool_verify,
            "superagent_memory_search": cls._tool_memory_search,
            "superagent_devsecops_generate": cls._tool_devsecops_generate,
            "superagent_swe_plan": cls._tool_swe_plan,
            "superagent_swe_spec": cls._tool_swe_spec,
            "superagent_devsecops_audit": cls._tool_devsecops_audit,
            "superagent_memory_add": cls._tool_memory_add,
            "superagent_memory_graph": cls._tool_memory_graph,
        }
        handler = dispatch.get(name)
        if not handler:
            raise ValueError(f"Unknown tool: {name}")
        return handler(arguments)

    @classmethod
    def handle_request(cls, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Procesa una petición JSON-RPC 2.0 y retorna la respuesta adecuada."""
        msg_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": cls.PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": cls.SERVER_NAME,
                        "version": cls.SERVER_VERSION
                    }
                }
            }

        if method == "notifications/initialized":
            return None

        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": cls.get_tool_definitions()}
            }

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments", {})
            try:
                text_out = cls.call_tool(tool_name, tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": text_out}]
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": str(e),
                        "data": traceback.format_exc()
                    }
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"}
        }

    @classmethod
    def run_stdio(cls):
        """Bucle principal de escucha stdio para comunicación MCP."""
        sys.stderr.write(f"SuperAgent MCP Server v{cls.SERVER_VERSION} started on stdio.\n")
        sys.stderr.flush()

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = cls.handle_request(req)
                if resp:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"}
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
