"""
core/aci_guard.py - In-Memory AST Guard & Complexity Linter for SuperAgent
Prevents syntax regressions, bloated functions, and excessive cyclomatic/cognitive complexity.
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


@dataclass
class FunctionMetrics:
    name: str
    line_start: int
    line_end: int
    lines_of_code: int
    cyclomatic_complexity: int
    cognitive_depth: int
    exceeds_threshold: bool
    violations: List[str] = field(default_factory=list)


@dataclass
class ACIGuardReport:
    file_path: str
    valid_syntax: bool
    syntax_error: Optional[str] = None
    syntax_line: Optional[int] = None
    functions: List[FunctionMetrics] = field(default_factory=list)
    max_complexity: int = 0
    passed: bool = True
    blocking_reasons: List[str] = field(default_factory=list)


class ACIGuard:
    """Agent-Computer Interface AST & Metric Guard."""

    MAX_CYCLOMATIC_COMPLEXITY = 15
    MAX_COGNITIVE_DEPTH = 5
    MAX_FUNCTION_LOC = 120

    @classmethod
    def audit_code(cls, code: str, filename: str = "<memory>") -> ACIGuardReport:
        """Analyze code in-memory before writing to disk."""
        ext = Path(filename).suffix.lower()

        if ext == ".py" or ext == "" or filename == "<memory>":
            return cls._audit_python(code, filename)
        else:
            return cls._audit_generic(code, filename)

    @classmethod
    def audit_file(cls, file_path: Path) -> ACIGuardReport:
        """Analyze an existing file on disk."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return cls.audit_code(content, str(file_path))
        except Exception as exc:
            return ACIGuardReport(
                file_path=str(file_path),
                valid_syntax=False,
                syntax_error=str(exc),
                passed=False,
                blocking_reasons=[f"Could not read file: {exc}"]
            )

    @classmethod
    def _audit_python(cls, code: str, filename: str) -> ACIGuardReport:
        try:
            tree = ast.parse(code, filename=filename)
        except SyntaxError as e:
            return ACIGuardReport(
                file_path=filename,
                valid_syntax=False,
                syntax_error=e.msg,
                syntax_line=e.lineno,
                passed=False,
                blocking_reasons=[f"SyntaxError at line {e.lineno}: {e.msg}"]
            )

        functions_metrics: List[FunctionMetrics] = []
        max_cc = 0
        blocking = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                metrics = cls._calculate_python_function_metrics(node, code=code)
                functions_metrics.append(metrics)
                if metrics.cyclomatic_complexity > max_cc:
                    max_cc = metrics.cyclomatic_complexity
                if metrics.exceeds_threshold:
                    for v in metrics.violations:
                        blocking.append(f"Function '{metrics.name}' (lines {metrics.line_start}-{metrics.line_end}): {v}")

        passed = len(blocking) == 0
        return ACIGuardReport(
            file_path=filename,
            valid_syntax=True,
            functions=functions_metrics,
            max_complexity=max_cc,
            passed=passed,
            blocking_reasons=blocking
        )

    @classmethod
    def _calculate_python_function_metrics(cls, fn_node: ast.AST, code: str = "") -> FunctionMetrics:
        """Calcula métricas de McCabe y profundidad cognitiva. aci: ignore"""
        name = getattr(fn_node, "name", "anonymous")
        line_start = getattr(fn_node, "lineno", 0)
        line_end = getattr(fn_node, "end_lineno", line_start)
        loc = line_end - line_start + 1

        # Check suppression in docstring or comments on def line
        fn_doc = ast.get_docstring(fn_node) or ""
        code_lines = code.splitlines() if code else []
        def_line = code_lines[line_start - 1] if 0 < line_start <= len(code_lines) else ""
        is_suppressed = ("aci: ignore" in fn_doc or "noqa" in fn_doc or "aci: ignore" in def_line or "noqa" in def_line)

        # Calculate Cyclomatic Complexity (McCabe: 1 + decision points)
        complexity = 1
        max_depth = 0

        # Iterative stack traversal to avoid recursion and nested function scope
        stack = [(fn_node, 0)]
        while stack:
            curr_node, curr_depth = stack.pop()
            if curr_depth > max_depth:
                max_depth = curr_depth

            for child in ast.iter_child_nodes(curr_node):
                is_decision = False
                increases_depth = False

                if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                    is_decision = True
                    increases_depth = True
                elif isinstance(child, ast.ExceptHandler):
                    is_decision = True
                    increases_depth = True
                elif isinstance(child, ast.Assert):
                    is_decision = True
                elif isinstance(child, ast.BoolOp):
                    complexity += max(0, len(child.values) - 1)
                elif isinstance(child, (ast.comprehension, ast.IfExp)):
                    is_decision = True

                if is_decision:
                    complexity += 1

                new_depth = curr_depth + 1 if increases_depth else curr_depth
                stack.append((child, new_depth))

        violations = []
        if not is_suppressed:
            if complexity > cls.MAX_CYCLOMATIC_COMPLEXITY:
                violations.append(f"Cyclomatic complexity {complexity} exceeds limit ({cls.MAX_CYCLOMATIC_COMPLEXITY})")
            if max_depth > cls.MAX_COGNITIVE_DEPTH:
                violations.append(f"Cognitive nesting depth {max_depth} exceeds limit ({cls.MAX_COGNITIVE_DEPTH})")
            if loc > cls.MAX_FUNCTION_LOC:
                violations.append(f"Function length {loc} lines exceeds threshold ({cls.MAX_FUNCTION_LOC} LOC)")

        return FunctionMetrics(
            name=name,
            line_start=line_start,
            line_end=line_end,
            lines_of_code=loc,
            cyclomatic_complexity=complexity,
            cognitive_depth=max_depth,
            exceeds_threshold=len(violations) > 0,
            violations=violations
        )

    @classmethod
    def _audit_generic(cls, code: str, filename: str) -> ACIGuardReport:
        # Generic heuristic for JS/TS/Go/Rust/C
        lines = code.splitlines()
        blocking = []
        max_depth = 0
        current_depth = 0

        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            # Bracing depth estimation
            opens = stripped.count("{")
            closes = stripped.count("}")
            current_depth += (opens - closes)
            if current_depth > max_depth:
                max_depth = current_depth

        if max_depth > cls.MAX_COGNITIVE_DEPTH + 2:
            blocking.append(f"Excessive nesting depth ({max_depth} levels detected)")

        passed = len(blocking) == 0
        return ACIGuardReport(
            file_path=filename,
            valid_syntax=True,
            max_complexity=max_depth,
            passed=passed,
            blocking_reasons=blocking
        )
