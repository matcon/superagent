"""
core/doctor.py - System Health & Environment Diagnostics for SuperAgent
Audits dependencies, Niri Wayland IPC, SQLite FTS5 integrity, and host execution capabilities.
"""

import sys
import shutil
import sqlite3
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

from .os_control import OSControl
from .memory import DB_PATH


@dataclass
class DiagnosticCheck:
    name: str
    category: str
    status: str  # OK, WARN, FAIL
    details: str
    remediation: Optional[str] = None


@dataclass
class DoctorReport:
    checks: List[DiagnosticCheck] = field(default_factory=list)
    healthy: bool = True
    warnings: int = 0
    failures: int = 0


class SystemDoctor:
    """Diagnóstico integral de salud del entorno operativo del Superagente."""

    @classmethod
    def _check_python_runtime(cls) -> DiagnosticCheck:
        py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if sys.version_info >= (3, 10):
            return DiagnosticCheck("Python Runtime", "Core", "OK", f"Python {py_ver} (modern AST supported)")
        return DiagnosticCheck("Python Runtime", "Core", "FAIL", f"Python {py_ver} < 3.10", "Actualice Python a >= 3.10.")

    @classmethod
    def _check_sqlite_fts5(cls) -> DiagnosticCheck:
        try:
            conn = sqlite3.connect(":memory:")
            conn.execute("CREATE VIRTUAL TABLE test_fts USING fts5(content);")
            conn.close()
            return DiagnosticCheck("SQLite FTS5 Extension", "Core", "OK", "FTS5 virtual table support active")
        except Exception as e:
            return DiagnosticCheck("SQLite FTS5 Extension", "Core", "FAIL", str(e), "SQLite requiere compilación con soporte FTS5.")

    @classmethod
    def _check_memory_integrity(cls) -> DiagnosticCheck:
        if not DB_PATH.exists():
            return DiagnosticCheck("Tripartite Memory DB", "Storage", "OK", "Fresh state (DB will auto-initialize on first write)")
        try:
            conn = sqlite3.connect(str(DB_PATH))
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check;")
            row = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) FROM learnings;")
            learnings_count = cursor.fetchone()[0]
            conn.close()

            if row and row[0] == "ok":
                return DiagnosticCheck("Tripartite Memory DB", "Storage", "OK", f"Integrity OK ({learnings_count} entries recorded)")
            return DiagnosticCheck("Tripartite Memory DB", "Storage", "WARN", f"Integrity check returned: {row}")
        except Exception as e:
            return DiagnosticCheck("Tripartite Memory DB", "Storage", "WARN", f"Error checking DB: {e}")

    @classmethod
    def _check_git_cli(cls) -> DiagnosticCheck:
        if not shutil.which("git"):
            return DiagnosticCheck("Git CLI", "Tools", "FAIL", "Git no está en PATH", "Instale git con pkexec pacman -S git")
        try:
            res = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=3)
            return DiagnosticCheck("Git CLI", "Tools", "OK", res.stdout.strip())
        except Exception:
            return DiagnosticCheck("Git CLI", "Tools", "WARN", "git found but unresponsive")

    @classmethod
    def _check_polkit(cls) -> DiagnosticCheck:
        if shutil.which("pkexec"):
            return DiagnosticCheck("Polkit Agent (pkexec)", "OS", "OK", "pkexec disponible para prompts GUI en Wayland")
        return DiagnosticCheck("Polkit Agent (pkexec)", "OS", "WARN", "pkexec no encontrado en PATH", "Instale polkit para elevar permisos en GUI.")

    @classmethod
    def _check_niri_compositor(cls) -> DiagnosticCheck:
        niri_state = OSControl.get_niri_state()
        if niri_state.get("workspaces"):
            return DiagnosticCheck("Niri Compositor IPC", "Desktop", "OK", f"Niri activo ({len(niri_state['workspaces'])} workspaces)")
        return DiagnosticCheck("Niri Compositor IPC", "Desktop", "WARN", "Niri IPC no respondió o entorno no es Niri")

    @classmethod
    def _check_notifications(cls) -> DiagnosticCheck:
        if shutil.which("notify-send"):
            return DiagnosticCheck("Desktop Notifications", "Desktop", "OK", "notify-send disponible")
        return DiagnosticCheck("Desktop Notifications", "Desktop", "WARN", "notify-send no encontrado")

    @classmethod
    def _check_package_managers(cls) -> DiagnosticCheck:
        has_pacman = bool(shutil.which("pacman"))
        has_yay = bool(shutil.which("yay"))
        if has_pacman and has_yay:
            return DiagnosticCheck("Package Management", "OS", "OK", "pacman y yay (AUR) operativos")
        if has_pacman:
            return DiagnosticCheck("Package Management", "OS", "OK", "pacman operativo (sin yay)")
        return DiagnosticCheck("Package Management", "OS", "WARN", "pacman no encontrado")

    @classmethod
    def run_diagnostics(cls) -> DoctorReport:
        """Ejecuta los diagnósticos del sistema de manera orquestada."""
        checks = [
            cls._check_python_runtime(),
            cls._check_sqlite_fts5(),
            cls._check_memory_integrity(),
            cls._check_git_cli(),
            cls._check_polkit(),
            cls._check_niri_compositor(),
            cls._check_notifications(),
            cls._check_package_managers(),
        ]

        failures = sum(1 for c in checks if c.status == "FAIL")
        warnings = sum(1 for c in checks if c.status == "WARN")
        healthy = (failures == 0)

        return DoctorReport(checks=checks, healthy=healthy, warnings=warnings, failures=failures)
