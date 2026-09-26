"""
os_control.py - Superagent Hardware Telemetry and Desktop OS Control (Niri / Wayland / Polkit)
"""

import os
import sys
import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, List, Optional


@dataclass
class SystemTelemetry:
    cpu_cores: int
    load_1m: float
    load_5m: float
    load_15m: float
    ram_total_gb: float
    ram_available_gb: float
    ram_used_percent: float
    recommended_concurrency: int


class OSControl:
    """Provides deep integration with Arch Linux, Niri Wayland IPC, and hardware telemetry."""

    @staticmethod
    def get_telemetry() -> SystemTelemetry:
        cores = os.cpu_count() or 4
        try:
            load_1m, load_5m, load_15m = os.getloadavg()
        except (AttributeError, OSError):
            load_1m, load_5m, load_15m = 0.0, 0.0, 0.0

        ram_total_gb = 16.0
        ram_avail_gb = 8.0
        ram_used_pct = 50.0

        try:
            with open("/proc/meminfo", "r") as f:
                meminfo = {}
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val = parts[1].strip().split()[0]
                        meminfo[key] = int(val)
                total_kb = meminfo.get("MemTotal", 16 * 1024 * 1024)
                avail_kb = meminfo.get("MemAvailable", total_kb // 2)
                ram_total_gb = round(total_kb / (1024 * 1024), 2)
                ram_avail_gb = round(avail_kb / (1024 * 1024), 2)
                ram_used_pct = round(((total_kb - avail_kb) / total_kb) * 100, 1)
        except Exception:
            pass

        # Calculate recommended concurrency budget
        # Allocate ~1.2 GB per heavy subagent worker safely without swapping
        concurrency_by_ram = max(1, int(ram_avail_gb // 1.2))
        concurrency_by_cpu = max(1, int(cores * 1.5))
        # Reduce if system load is high
        load_factor = 1.0 if load_1m < cores else 0.6
        rec_concurrency = max(1, int(min(concurrency_by_ram, concurrency_by_cpu) * load_factor))

        return SystemTelemetry(
            cpu_cores=cores,
            load_1m=round(load_1m, 2),
            load_5m=round(load_5m, 2),
            load_15m=round(load_15m, 2),
            ram_total_gb=ram_total_gb,
            ram_available_gb=ram_avail_gb,
            ram_used_percent=ram_used_pct,
            recommended_concurrency=rec_concurrency,
        )

    @staticmethod
    def niri_cmd(args: List[str]) -> Optional[Dict[str, Any]]:
        """Execute a niri IPC command and parse JSON output."""
        if not shutil.which("niri"):
            return None
        cmd = ["niri", "msg", "-j"] + args
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0 and res.stdout.strip():
                return json.loads(res.stdout)
            return None
        except Exception:
            return None

    @staticmethod
    def get_niri_state() -> Dict[str, Any]:
        """Fetch active windows, workspaces, and focused output in Niri."""
        return {
            "focused_window": OSControl.niri_cmd(["focused-window"]),
            "workspaces": OSControl.niri_cmd(["workspaces"]),
            "outputs": OSControl.niri_cmd(["outputs"]),
        }

    @staticmethod
    def notify(title: str, message: str, urgency: str = "normal", icon: str = "dialog-information") -> bool:
        """Send a native desktop notification via notify-send."""
        if not shutil.which("notify-send"):
            return False
        try:
            subprocess.run(
                ["notify-send", "-a", "SuperAgent", "-u", urgency, "-i", icon, title, message],
                timeout=3,
                check=False
            )
            return True
        except Exception:
            return False

    @staticmethod
    def pkexec_run(command_args: List[str]) -> subprocess.CompletedProcess:
        """Run a privileged command via pkexec (triggers Polkit GUI)."""
        cmd = ["pkexec"] + command_args
        return subprocess.run(cmd, capture_output=True, text=True)
