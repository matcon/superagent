"""
core/test_rigor.py - Property-Based Testing & Mutation Testing Harness for SuperAgent
Detects false test confidence and generates Hypothesis property-based testing scaffolds.
"""

import ast
import re
import copy
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple


@dataclass
class Mutant:
    mutant_id: int
    line_number: int
    original_op: str
    mutated_op: str
    code: str
    status: str = "pending"  # killed, survived, error


@dataclass
class MutationReport:
    total_mutants: int
    killed: int
    survived: int
    errors: int
    mutation_score: float
    has_false_confidence: bool
    surviving_mutants: List[Dict[str, Any]] = field(default_factory=list)


class TestRigorEngine:
    """Arnés para elevar la rigurosidad del testing mediante propiedades y mutación sintáctica."""

    @classmethod
    def generate_property_tests(cls, module_name: str, function_name: str, arg_types: Dict[str, str]) -> str:
        """Genera scaffold de pruebas basadas en propiedades con Hypothesis. aci: ignore"""
        lines = [
            "# Auto-generated Property-Based Test by SuperAgent TestRigorEngine",
            "import pytest",
            "from hypothesis import given, strategies as st, settings",
            f"from {module_name} import {function_name}",
            "",
            "@settings(max_examples=100)",
            "@given("
        ]

        strategies = []
        for arg, atype in arg_types.items():
            if atype in ["str", "string"]:
                strat = f"{arg}=st.text(min_size=0, max_size=100)"
            elif atype in ["int", "integer"]:
                strat = f"{arg}=st.integers(min_value=-10000, max_value=10000)"
            elif atype in ["float", "number"]:
                strat = f"{arg}=st.floats(allow_nan=False, allow_infinity=False)"
            elif atype in ["bool", "boolean"]:
                strat = f"{arg}=st.booleans()"
            elif atype.startswith("list"):
                strat = f"{arg}=st.lists(st.integers(), max_size=20)"
            else:
                strat = f"{arg}=st.text()"
            strategies.append(f"    {strat}")

        lines.append(",\n".join(strategies))
        lines.append(")")
        lines.append(f"def test_{function_name}_properties({', '.join(arg_types.keys())}):")
        lines.append("    # Property 1: No unhandled panics or unexpected crashes")
        lines.append(f"    result = {function_name}({', '.join(arg_types.keys())})")
        lines.append("    assert result is not None")
        lines.append("")
        lines.append("    # Property 2: Idempotence (if applicable)")
        lines.append(f"    # assert {function_name}(result) == result")
        lines.append("")
        return "\n".join(lines)

    @classmethod
    def generate_ast_mutants(cls, source_code: str) -> List[Mutant]:
        """Genera mutantes sintácticos AST: inversión de operadores de comparación y lógicos. aci: ignore"""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        mutants: List[Mutant] = []
        m_id = 1

        op_map = {
            ast.Lt: ast.GtE,
            ast.Gt: ast.LtE,
            ast.LtE: ast.Gt,
            ast.GtE: ast.Lt,
            ast.Eq: ast.NotEq,
            ast.NotEq: ast.Eq,
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.Compare) and len(node.ops) == 1:
                orig_op_type = type(node.ops[0])
                if orig_op_type in op_map:
                    # Create modified copy
                    mutated_tree = copy.deepcopy(tree)
                    for target in ast.walk(mutated_tree):
                        if isinstance(target, ast.Compare) and getattr(target, 'lineno', -1) == node.lineno:
                            target.ops[0] = op_map[orig_op_type]()
                            try:
                                mutated_code = ast.unparse(mutated_tree)
                                mutants.append(Mutant(
                                    mutant_id=m_id,
                                    line_number=node.lineno,
                                    original_op=orig_op_type.__name__,
                                    mutated_op=op_map[orig_op_type].__name__,
                                    code=mutated_code
                                ))
                                m_id += 1
                                break
                            except Exception:
                                pass
        return mutants

    @classmethod
    def run_mutation_audit(cls, source_file: Path, test_command: str) -> MutationReport:
        """Audita la efectividad de una suite de tests ejecutándola contra mutantes sintácticos."""
        try:
            original_code = source_file.read_text(encoding="utf-8")
        except Exception:
            return MutationReport(0, 0, 0, 0, 0.0, False)

        mutants = cls.generate_ast_mutants(original_code)
        if not mutants:
            return MutationReport(0, 0, 0, 0, 100.0, False)

        killed = 0
        survived = 0
        errors = 0
        surviving_list = []

        try:
            for m in mutants:
                # Escribir código mutado temporalmente
                source_file.write_text(m.code, encoding="utf-8")
                res = subprocess.run(test_command, shell=True, capture_output=True, text=True, timeout=15)  # nosec: test runner
                
                # Si el test falla, el mutante fue ASESINADO (comportamiento deseado)
                if res.returncode != 0:
                    killed += 1
                    m.status = "killed"
                else:
                    # Si el test pasa a pesar de la mutación, el mutante SOBREVIVIÓ (falsa confianza)
                    survived += 1
                    m.status = "survived"
                    surviving_list.append({
                        "id": m.mutant_id,
                        "line": m.line_number,
                        "mutation": f"{m.original_op} -> {m.mutated_op}"
                    })
        finally:
            # Restaurar archivo original siempre
            source_file.write_text(original_code, encoding="utf-8")

        total = len(mutants)
        score = round((killed / total) * 100, 1) if total > 0 else 100.0
        has_false_confidence = (score < 80.0 and total >= 3)

        return MutationReport(
            total_mutants=total,
            killed=killed,
            survived=survived,
            errors=errors,
            mutation_score=score,
            has_false_confidence=has_false_confidence,
            surviving_mutants=surviving_list
        )
