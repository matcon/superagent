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
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from .aci_guard import ACIGuard, ACIGuardReport
from .sast import SASTScanner, Finding


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
        res = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False
        )
        if res.returncode == 0 and res.stdout.strip():
            return Path(res.stdout.strip())
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
        for py_file in self.worktree_dir.rglob("*.py"):
            if ".git" in py_file.parts:
                continue
            rep = ACIGuard.audit_file(py_file)
            if not rep.passed:
                aci_violations.extend(rep.blocking_reasons)

        passed = (len(blocking_sast) == 0 and len(aci_violations) == 0)
        return {
            "passed": passed,
            "sast_findings": [f.__dict__ for f in findings],
            "blocking_sast_count": len(blocking_sast),
            "aci_violations": aci_violations,
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
