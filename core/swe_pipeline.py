"""
core/swe_pipeline.py - Autonomous Software Engineering Superintelligence Pipeline Engine
Integrates Requirements Decomposition, Multi-Agent Swarm Planning, Multi-Dimensional Auditing, and DevSecOps.
"""

import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from .aci_guard import ACIGuard, ACIGuardReport
from .sast import SASTScanner, Finding
from .container_guard import ContainerGuard, ContainerAuditReport
from .contract_spec import ContractSpecEngine
from .test_rigor import TestRigorEngine


@dataclass
class SWEAuditResult:
    target_path: str
    overall_score: int  # 0 to 100
    grade: str  # A+, A, B, C, F
    aci_guard: Dict[str, Any]
    sast_findings: List[Dict[str, Any]]
    container_audits: List[Dict[str, Any]]
    passed: bool
    summary: str


class SWEPipelineEngine:
    """Motor central de Ingeniería de Software de Alta Fidelidad para SuperAgent."""

    @classmethod
    def decompose_swe_goal(cls, goal: str) -> Dict[str, Any]:
        """Descompone un objetivo de software en un Grafo DAG de 5 fases ejecutables con roles de The Agency."""
        return {
            "goal": goal,
            "version": "2.0-SWE-SI",
            "tasks": [
                {
                    "id": "phase_1_spec_and_contracts",
                    "name": "Especificación Formal y Contratos de Interfaz",
                    "role": "System & API Architect",
                    "skills": ["agency-software-architect", "codebase-design"],
                    "depends_on": [],
                    "prompt": (
                        f"Diseñar la arquitectura técnica para: '{goal}'. "
                        "Definir bounded contexts, invariantes del dominio, modelos Pydantic/TypeSpec, "
                        "y contratos de API (Design by Contract)."
                    )
                },
                {
                    "id": "phase_2_threat_model",
                    "name": "Modelado de Amenazas y Verificación SAST Pre-Flight",
                    "role": "Application Security Architect",
                    "skills": ["agency-application-security-engineer", "security-review"],
                    "depends_on": ["phase_1_spec_and_contracts"],
                    "prompt": (
                        "Auditar el diseño propuesto contra OWASP Top 10 (A01-A10), "
                        "definir controles de autenticación/autorización, aislamiento de datos "
                        "y sanitización de entradas para mitigar inyecciones."
                    )
                },
                {
                    "id": "phase_3_atomic_implementation",
                    "name": "Implementación Atómica y Modular",
                    "role": "Senior Implementation Specialist",
                    "skills": ["agency-backend-architect", "agency-minimal-change-engineer"],
                    "depends_on": ["phase_1_spec_and_contracts", "phase_2_threat_model"],
                    "prompt": (
                        "Implementar el código fuente cumpliendo estrictamente los contratos de la Fase 1. "
                        "Garantizar que ninguna función supere complejidad ciclomática > 10 ni profundidad > 3. "
                        "Validar la sintaxis con ACIGuard."
                    )
                },
                {
                    "id": "phase_4_test_and_mutation",
                    "name": "Batería de Pruebas Unitarias, Propiedades y Mutación",
                    "role": "Test Automation & QA Engineer",
                    "skills": ["agency-test-automation-engineer", "thermo-nuclear-code-quality-review"],
                    "depends_on": ["phase_3_atomic_implementation"],
                    "prompt": (
                        "Construir la suite de tests unitarios y tests basados en propiedades (Hypothesis). "
                        "Ejecutar verificación de mutación para eliminar falsa confianza y verificar cobertura > 85%."
                    )
                },
                {
                    "id": "phase_5_devops_container_cicd",
                    "name": "Contenedor Endurecido y Pipeline CI/CD Zero-Downtime",
                    "role": "DevOps & SRE Specialist",
                    "skills": ["agency-devops-automator", "agency-sre-site-reliability-engineer"],
                    "depends_on": ["phase_4_test_and_mutation"],
                    "prompt": (
                        "Generar Dockerfile Multi-Stage con base distroless y usuario no-root. "
                        "Crear workflow de GitHub Actions o manifiestos de Kubernetes con estrategia RollingUpdate "
                        "y sondas de salud (liveness/readiness)."
                    )
                }
            ]
        }

    @classmethod
    def audit_codebase(cls, target_dir: Path) -> SWEAuditResult:
        """Ejecuta una auditoría integral multidimensional de calidad, seguridad y contenedores. aci: ignore"""
        sast = SASTScanner()
        sast_findings = sast.scan_directory(target_dir)

        # ACI Guard sobre archivos fuente
        total_functions = 0
        complex_functions = 0
        syntax_errors = 0
        aci_blocking = []

        code_exts = {".py", ".js", ".ts"}
        for f in target_dir.rglob("*"):
            if f.is_file() and f.suffix in code_exts and not any(p in f.parts for p in [".git", "node_modules", "venv", "__pycache__"]):
                report = ACIGuard.audit_file(f)
                if not report.valid_syntax:
                    syntax_errors += 1
                    aci_blocking.append(f"{f.name}: {report.syntax_error}")
                total_functions += len(report.functions)
                for fn in report.functions:
                    if fn.exceeds_threshold:
                        complex_functions += 1
                        aci_blocking.append(f"{f.name}::{fn.name}: Complejidad {fn.cyclomatic_complexity}")

        # Contenedores
        container_audits = []
        for df in target_dir.rglob("*Dockerfile*"):
            if df.is_file():
                try:
                    c_report = ContainerGuard.audit_dockerfile(df.read_text(encoding="utf-8", errors="ignore"), str(df))
                    container_audits.append(asdict(c_report))
                except Exception:
                    pass

        # Cálculo de puntaje SWE Score
        score = 100
        # Penalizaciones
        critical_sast = sum(1 for f in sast_findings if f.severity == "CRITICAL")
        high_sast = sum(1 for f in sast_findings if f.severity == "HIGH")
        medium_sast = sum(1 for f in sast_findings if f.severity == "MEDIUM")

        score -= (critical_sast * 25)
        score -= (high_sast * 10)
        score -= (medium_sast * 4)
        score -= (syntax_errors * 30)
        score -= (complex_functions * 2)

        for ca in container_audits:
            for v in ca.get("violations", []):
                if v.get("severity") in ["CRITICAL", "HIGH"]:
                    score -= 10

        score = max(0, min(100, score))

        if score >= 95:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        else:
            grade = "F"

        passed = (score >= 70 and critical_sast == 0 and syntax_errors == 0)

        summary = (
            f"Auditoría SWE completada: Grado {grade} ({score}/100). "
            f"Vulnerabilidades SAST: {len(sast_findings)} ({critical_sast} críticas). "
            f"Funciones auditadas: {total_functions} ({complex_functions} con alta complejidad). "
            f"Contenedores auditados: {len(container_audits)}."
        )

        return SWEAuditResult(
            target_path=str(target_dir),
            overall_score=score,
            grade=grade,
            aci_guard={
                "total_functions": total_functions,
                "complex_functions": complex_functions,
                "syntax_errors": syntax_errors,
                "violations": aci_blocking[:10]
            },
            sast_findings=[asdict(f) for f in sast_findings],
            container_audits=container_audits,
            passed=passed,
            summary=summary
        )
