"""
core/worktree_sandbox.py - Ephemeral Git Worktree Sandboxing for SuperAgent
Provides isolated, zero-risk environments for autonomous SWE task execution and testing.
"""

import os
import shutil
import tempfile
import subprocess
import secrets
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any

from .aci_guard import ACIGuard, ACIGuardReport
from .sast import SASTScanner, Finding


@dataclass
class CandidateEvaluation:
    candidate_id: str
    description: str
    command: str
    passed: bool
    score: float
    mccabe_max: int
    sast_count: int
    diff_lines: int
    duration_s: float
    worktree_path: str
    promoted: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SandboxResult:
    command: str
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float
    worktree_path: str
    passed: bool


@dataclass
class PromotionResult:
    success: bool
    source_branch: str
    target_branch: str
    message: str
    commit_hash: Optional[str] = None


class WorktreeSandbox:
    """Aisla ejecuciones y modificaciones de código en worktrees efímeros de Git."""

    def __init__(self, repo_root: Optional[Path] = None, base_ref: str = "HEAD"):
        self.repo_root = repo_root or self._detect_repo_root()
        self.base_ref = base_ref
        self.worktree_dir: Optional[Path] = None
        self.branch_name: Optional[str] = None
        self.created = False

    @staticmethod
    def _detect_repo_root() -> Path:
        # 1. Probar desde cwd actual
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip())

        # 2. Fallback: probar desde la raíz del paquete SuperAgent
        module_root = Path(__file__).resolve().parent.parent
        res_mod = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=module_root, capture_output=True, text=True, check=False
        )
        if res_mod.returncode == 0 and res_mod.stdout.strip():
            return Path(res_mod.stdout.strip())

        return Path.cwd()

    def create(self) -> Path:
        """Crea el worktree efímero en un directorio temporal aislado."""
        token = secrets.token_hex(4)
        self.branch_name = f"superagent-sandbox-{token}"
        temp_dir = Path(tempfile.gettempdir()) / f"superagent-wt-{token}"

        cmd = [
            "git", "worktree", "add", "-b", self.branch_name,
            str(temp_dir), self.base_ref
        ]
        res = subprocess.run(cmd, cwd=self.repo_root, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed to create Git worktree: {res.stderr.strip()}")

        self.worktree_dir = temp_dir
        self.created = True
        return self.worktree_dir

    def run_command(self, command: str, timeout_s: int = 120) -> SandboxResult:
        """Ejecuta un comando dentro del sandbox aislado."""
        if not self.created or not self.worktree_dir:
            raise RuntimeError("Sandbox has not been created yet.")

        import time
        start = time.perf_counter()
        proc = subprocess.run(
            command, shell=True, cwd=self.worktree_dir,  # nosec: sandboxed execution
            capture_output=True, text=True, timeout=timeout_s
        )
        duration = round(time.perf_counter() - start, 3)

        return SandboxResult(
            command=command,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_s=duration,
            worktree_path=str(self.worktree_dir),
            passed=(proc.returncode == 0)
        )

    def audit(self) -> Dict[str, Any]:
        """Audita el estado actual del sandbox usando SAST y ACI Guard."""
        if not self.created or not self.worktree_dir:
            raise RuntimeError("Sandbox has not been created yet.")

        scanner = SASTScanner()
        findings = scanner.scan_directory(self.worktree_dir)
        blocking_sast = [f for f in findings if f.severity in ["CRITICAL", "HIGH"]]

        aci_violations = []
        max_cc = 0
        for py_file in self.worktree_dir.rglob("*.py"):
            if ".git" in py_file.parts:
                continue
            rep = ACIGuard.audit_file(py_file)
            if rep.max_complexity > max_cc:
                max_cc = rep.max_complexity
            if not rep.passed:
                aci_violations.extend(rep.blocking_reasons)

        # Contabilizar líneas modificadas respecto a base_ref
        diff_res = subprocess.run(
            ["git", "diff", "--shortstat", self.base_ref],
            cwd=self.worktree_dir, capture_output=True, text=True
        )
        import re
        nums = re.findall(r"(\d+)\s+(?:insertion|deletion)", diff_res.stdout)
        diff_lines = sum(int(n) for n in nums)

        passed = (len(blocking_sast) == 0 and len(aci_violations) == 0)
        return {
            "passed": passed,
            "max_complexity": max_cc,
            "sast_findings": [f.__dict__ for f in findings],
            "blocking_sast_count": len(blocking_sast),
            "aci_violations": aci_violations,
            "diff_lines": diff_lines,
            "worktree_path": str(self.worktree_dir)
        }

    def promote(self, commit_message: str, target_branch: str = "main") -> PromotionResult:
        """Confirma los cambios en el sandbox y los fusiona en la rama destino."""
        if not self.created or not self.worktree_dir:
            raise RuntimeError("Sandbox has not been created yet.")

        # Stage and commit in sandbox
        subprocess.run(["git", "add", "-A"], cwd=self.worktree_dir, check=True)
        res = subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=self.worktree_dir, capture_output=True, text=True
        )
        if res.returncode != 0 and "nothing to commit" in res.stdout:
            return PromotionResult(False, self.branch_name, target_branch, "No changes detected to promote.")

        # Get commit hash
        rev = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.worktree_dir, capture_output=True, text=True, check=True
        )
        commit_hash = rev.stdout.strip()

        # Merge to target branch
        merge_res = subprocess.run(
            ["git", "merge", "--ff-only", self.branch_name],
            cwd=self.repo_root, capture_output=True, text=True
        )
        if merge_res.returncode != 0:
            return PromotionResult(
                False, self.branch_name, target_branch,
                f"Fast-forward merge failed: {merge_res.stderr.strip()}",
                commit_hash=commit_hash
            )

        return PromotionResult(
            True, self.branch_name, target_branch,
            f"Successfully merged {commit_hash[:8]} into {target_branch}.",
            commit_hash=commit_hash
        )

    def cleanup(self) -> None:
        """Elimina de forma segura el worktree, su rama temporal y poda el índice."""
        try:
            if self.created and self.worktree_dir and self.worktree_dir.exists():
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(self.worktree_dir)],
                    cwd=self.repo_root, capture_output=True, text=True
                )
                if self.branch_name:
                    subprocess.run(
                        ["git", "branch", "-D", self.branch_name],
                        cwd=self.repo_root, capture_output=True, text=True
                    )
                if self.worktree_dir.exists():
                    shutil.rmtree(self.worktree_dir, ignore_errors=True)
                self.created = False
        finally:
            subprocess.run(
                ["git", "worktree", "prune"],
                cwd=self.repo_root, capture_output=True, text=True
            )

    def __enter__(self):
        self.create()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()

    @classmethod
    def run_tournament(
        cls,
        candidates: List[Dict[str, Any]],
        test_command: Optional[str] = None,
        promote_winner: bool = True,
        target_branch: str = "main",
        max_workers: int = 2
    ) -> Dict[str, Any]:
        """Ejecuta un torneo concurrente Best-of-N evaluando múltiples hipótesis de parche en paralelo."""
        import concurrent.futures
        import time

        evaluations: List[CandidateEvaluation] = []
        sandboxes: Dict[str, WorktreeSandbox] = {}

        def eval_candidate(cand: Dict[str, Any]) -> CandidateEvaluation:
            cid = cand["id"]
            desc = cand.get("desc", cid)
            cmd = cand["command"]
            t0 = time.perf_counter()

            sb = cls()
            sandboxes[cid] = sb
            sb.create()

            res = sb.run_command(cmd)
            test_passed = res.passed
            if test_passed and test_command:
                test_res = sb.run_command(test_command)
                test_passed = test_res.passed

            audit_res = sb.audit()
            duration = round(time.perf_counter() - t0, 3)

            # Función de aptitud Pareto (fitness score)
            score = 100.0 if test_passed else 0.0
            score += max(0, 15 - audit_res.get("max_complexity", 0)) * 5.0
            score -= audit_res.get("blocking_sast_count", 0) * 25.0
            score -= min(audit_res.get("diff_lines", 0), 500) * 0.05

            return CandidateEvaluation(
                candidate_id=cid,
                description=desc,
                command=cmd,
                passed=test_passed,
                score=round(score, 2),
                mccabe_max=audit_res.get("max_complexity", 0),
                sast_count=audit_res.get("blocking_sast_count", 0),
                diff_lines=audit_res.get("diff_lines", 0),
                duration_s=duration,
                worktree_path=str(sb.worktree_dir),
                details=audit_res
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(eval_candidate, c) for c in candidates]
            for f in concurrent.futures.as_completed(futures):
                try:
                    evaluations.append(f.result())
                except Exception:
                    pass

        # Ordenar por score descendente
        evaluations.sort(key=lambda e: e.score, reverse=True)

        winner = None
        promotion_result = None
        if evaluations and evaluations[0].passed and evaluations[0].score > 0:
            winner = evaluations[0]
            if promote_winner:
                sb_winner = sandboxes[winner.candidate_id]
                commit_msg = f"fix(tournament): auto-promoted winner '{winner.candidate_id}' (Score: {winner.score})"
                promotion_result = sb_winner.promote(commit_msg, target_branch=target_branch)
                winner.promoted = promotion_result.success

        # Limpieza segura de todos los worktrees de candidatos
        for sb in sandboxes.values():
            try:
                sb.cleanup()
            except Exception:
                pass

        return {
            "total_candidates": len(candidates),
            "ranked_evaluations": [asdict(e) for e in evaluations],
            "winner": asdict(winner) if winner else None,
            "promotion": asdict(promotion_result) if promotion_result else None
        }
