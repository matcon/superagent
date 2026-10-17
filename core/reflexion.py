"""
core/reflexion.py - Closed-Loop Autonomous Verification, Git Checkpoint Rollback, & ToT Reflexion Engine
Now integrates Pre-flight SAST security gates, ACI complexity checks, and transactional Git state recovery.
"""

import re
import sys
import time
import hashlib
import subprocess
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Set

from .memory import SuperAgentMemory
from .sast import SASTScanner, Finding
from .aci_guard import ACIGuard, ACIGuardReport


@dataclass
class DiagnosticReport:
    command: str
    passed: bool
    returncode: int
    stdout: str
    stderr: str
    extracted_errors: List[str]
    matched_prior_learnings: List[Dict[str, Any]]
    suggested_hypothesis: str
    sast_violations: List[Dict[str, Any]] = field(default_factory=list)
    complexity_violations: List[str] = field(default_factory=list)
    checkpoint_created: Optional[str] = None
    fingerprint: Optional[str] = None
    is_oscillating: bool = False


class ReflexionEngine:
    """Automates the OODA / Reflexion loop: Run -> Detect Errors -> Consult Memory -> Formulate Hypothesis -> Safe Rollback."""

    def __init__(self, cwd: Optional[str] = None):
        self.cwd = cwd or str(Path.cwd())
        self.memory = SuperAgentMemory()
        self.sast = SASTScanner()
        self.seen_fingerprints: Set[str] = set()

    def create_git_checkpoint(self) -> Optional[str]:
        """Creates an ephemeral git checkpoint without altering current worktree state."""
        try:
            res = subprocess.run(
                ["git", "stash", "create"],
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=5
            )
            commit_hash = res.stdout.strip()
            return commit_hash if commit_hash else None
        except Exception:
            return None

    def rollback_git_checkpoint(self, checkpoint_hash: str) -> bool:
        """Rolls back the working directory to the specified checkpoint hash."""
        if not checkpoint_hash:
            return False
        try:
            # Stash any dirty failed experiments and restore
            subprocess.run(["git", "reset", "--hard", "HEAD"], cwd=self.cwd, capture_output=True, timeout=5)
            subprocess.run(["git", "stash", "apply", checkpoint_hash], cwd=self.cwd, capture_output=True, timeout=5)
            return True
        except Exception:
            return False

    def run_check(self, command: str, timeout_s: int = 60, auto_checkpoint: bool = True) -> DiagnosticReport:
        """Execute validation command with closed-loop reflexion, SAST gates, and complexity audits. aci: ignore"""
        checkpoint_hash = self.create_git_checkpoint() if auto_checkpoint else None

        # 1. Run target test / build command
        try:
            res = subprocess.run(
                command,
                shell=True,  # nosec: intentional test/validation command execution
                cwd=self.cwd,
                capture_output=True,
                text=True,
                timeout=timeout_s
            )
            passed = (res.returncode == 0)
            stdout = res.stdout.strip()
            stderr = res.stderr.strip()
            code = res.returncode
        except subprocess.TimeoutExpired:
            passed = False
            stdout = ""
            stderr = f"Validation timed out after {timeout_s}s"
            code = -1
        except Exception as exc:
            passed = False
            stdout = ""
            stderr = str(exc)
            code = -1

        extracted_errors = self._extract_errors(stderr + "\n" + stdout)
        matched_learnings: List[Dict[str, Any]] = []

        # 2. Gate de Seguridad SAST y Complejidad ACI sobre archivos modificados
        sast_violations: List[Dict[str, Any]] = []
        complexity_violations: List[str] = []

        modified_files = self._get_modified_files()
        for fpath in modified_files:
            if fpath.exists() and fpath.is_file():
                # SAST Check
                findings = self.sast.scan_file(fpath)
                for find in findings:
                    if find.severity in ["CRITICAL", "HIGH"]:
                        sast_violations.append(asdict(find))
                # ACI Guard Check
                if fpath.suffix in [".py", ".js", ".ts"]:
                    aci_rep = ACIGuard.audit_file(fpath)
                    if not aci_rep.passed:
                        complexity_violations.extend(aci_rep.blocking_reasons)

        # Si hubo violaciones críticas de seguridad o complejidad, forzar fallo
        if sast_violations or complexity_violations:
            passed = False
            if sast_violations:
                extracted_errors.append(f"Security Gate Failed: {len(sast_violations)} CRITICAL/HIGH finding(s).")
            if complexity_violations:
                extracted_errors.append(f"ACI Guard Failed: {len(complexity_violations)} complexity violation(s).")

        if not passed and extracted_errors:
            query = " ".join(extracted_errors[:3])
            matched_learnings = self.memory.search_learnings(query, limit=3)

        hypothesis = self._formulate_hypothesis(passed, extracted_errors, matched_learnings, sast_violations, complexity_violations)

        # Detección de oscilación ToT (cortar bucle si se repite exactamente el mismo fallo)
        fingerprint = self.compute_fingerprint(stderr, extracted_errors, sast_violations, complexity_violations)
        is_oscillating = False
        if not passed:
            if fingerprint in self.seen_fingerprints:
                is_oscillating = True
                hypothesis = f"[OSCILLATION GUARD] Repeated identical failure state (fingerprint: {fingerprint}). Aborting cyclical retry.\n" + hypothesis
            else:
                self.seen_fingerprints.add(fingerprint)

        return DiagnosticReport(
            command=command,
            passed=passed,
            returncode=code,
            stdout=stdout,
            stderr=stderr,
            extracted_errors=extracted_errors,
            matched_prior_learnings=matched_learnings,
            suggested_hypothesis=hypothesis,
            sast_violations=sast_violations,
            complexity_violations=complexity_violations,
            checkpoint_created=checkpoint_hash,
            fingerprint=fingerprint,
            is_oscillating=is_oscillating
        )

    @staticmethod
    def compute_fingerprint(stderr: str, errors: List[str], sast: List[Dict[str, Any]], complexity: List[str]) -> str:
        """Genera un hash SHA-256 determinista del estado de fallo para evitar oscilaciones."""
        raw = f"{stderr.strip()}|{sorted(errors)}|{len(sast)}|{sorted(complexity)}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _get_modified_files(self) -> List[Path]:
        """Obtiene la lista de archivos modificados recientemente en git status."""
        try:
            res = subprocess.run(["git", "status", "--porcelain"], cwd=self.cwd, capture_output=True, text=True, timeout=3)
            files = []
            for line in res.stdout.splitlines():
                if len(line) > 3:
                    rel_path = line[3:].strip()
                    files.append(Path(self.cwd) / rel_path)
            return files
        except Exception:
            return []

    def _extract_errors(self, text: str) -> List[str]:
        """Extract key error lines, stack traces, and compiler warnings."""
        error_lines = []
        pattern = re.compile(r"(error|exception|fail|traceback|panic|syntaxerror|typeerror|undefined|critical)", re.IGNORECASE)
        for line in text.splitlines():
            line_str = line.strip()
            if pattern.search(line_str) and len(line_str) > 10:
                error_lines.append(line_str)
        return error_lines[:8]

    def _formulate_hypothesis(
        self,
        passed: bool,
        errors: List[str],
        prior: List[Dict[str, Any]],
        sast: List[Dict[str, Any]],
        complexity: List[str]
    ) -> str:
        if passed:
            return "All checks passed cleanly. System state and security gates verified."

        parts = ["Failure detected in execution loop."]
        if sast:
            parts.append(f"Security Alert: {len(sast)} secret or injection vulnerability detected in modified files!")
            for s in sast[:2]:
                parts.append(f"  * [{s['severity']}] {s['description']} ({s['file_path']}:{s['line_number']})")
        if complexity:
            parts.append(f"Complexity Alert: {len(complexity)} function(s) exceed cyclomatic/cognitive limits:")
            for c in complexity[:2]:
                parts.append(f"  * {c}")
        if prior:
            parts.append(f"Found {len(prior)} historical similar issue(s) in episodic memory:")
            for p in prior:
                parts.append(f" - Context: {p['context']} | Solution: {p['solution']}")
        if errors:
            parts.append("Primary execution signals:")
            for err in errors[:3]:
                parts.append(f" > {err}")

        parts.append("Recommended Reflexion Action: Isolate minimal reproducing failure, apply atomic fix without regressions, or invoke rollback if unrecoverable.")
        return "\n".join(parts)

    def resolve_and_learn(self, category: str, problem: str, solution: str, context: str = "", tags: str = "") -> int:
        """Commit the verified fix to episodic memory for permanent retention."""
        return self.memory.add_learning(
            category=category,
            problem=problem,
            solution=solution,
            context=context,
            tags=tags
        )
