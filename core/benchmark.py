"""
core/benchmark.py - Throughput & Latency Benchmark Suite for SuperAgent Engine
Measures AST parsing throughput, Shannon entropy scanning speed, FTS5 latency, and Git operations.
"""

import time
import math
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any

from .aci_guard import ACIGuard
from .sast import SASTScanner
from .memory import SuperAgentMemory
from .os_control import OSControl


@dataclass
class BenchmarkMetric:
    name: str
    category: str
    value: float
    unit: str
    details: str


@dataclass
class BenchmarkReport:
    metrics: List[BenchmarkMetric] = field(default_factory=list)
    host_summary: str = ""
    total_duration_s: float = 0.0


class SuperAgentBenchmark:
    """Suite de benchmarking para medir el rendimiento de cómputo del Superagente en el host."""

    @classmethod
    def run_all(cls) -> BenchmarkReport:
        t_start = time.perf_counter()
        metrics: List[BenchmarkMetric] = []

        # 1. AST Parsing & ACIGuard Throughput
        ast_metric = cls._benchmark_ast_guard()
        metrics.append(ast_metric)

        # 2. Shannon Entropy & SAST Scanner Throughput
        sast_metric = cls._benchmark_shannon_entropy()
        metrics.append(sast_metric)

        # 3. SQLite FTS5 Search Latency
        fts_metric = cls._benchmark_fts5_latency()
        metrics.append(fts_metric)

        # 4. Git Checkpoint Latency
        git_metric = cls._benchmark_git_checkpoint()
        metrics.append(git_metric)

        total_dur = round(time.perf_counter() - t_start, 3)
        telemetry = OSControl.get_telemetry()
        host_info = f"CPU: {telemetry.cpu_cores} cores (Load 1m: {telemetry.load_1m}) | RAM: {telemetry.ram_available_gb}/{telemetry.ram_total_gb} GB"

        return BenchmarkReport(
            metrics=metrics,
            host_summary=host_info,
            total_duration_s=total_dur
        )

    @classmethod
    def _benchmark_ast_guard(cls) -> BenchmarkMetric:
        # Generate representative Python sample
        sample_code = """
def sample_compute(a, b, c):
    total = 0
    for i in range(100):
        if i % 2 == 0 and a > 0:
            total += (b * i)
        elif i % 3 == 0 or c < 10:
            total -= (c // 2)
        else:
            total += 1
    return total
""" * 100  # ~1100 LOC

        loc = len(sample_code.splitlines())
        iterations = 15
        total_loc = loc * iterations

        start = time.perf_counter()
        for _ in range(iterations):
            ACIGuard.audit_code(sample_code, "bench_sample.py")
        elapsed = time.perf_counter() - start

        loc_per_sec = round(total_loc / elapsed, 0)
        return BenchmarkMetric(
            name="AST & Complexity Guard",
            category="SWE Intelligence",
            value=loc_per_sec,
            unit="LOC/sec",
            details=f"Analyzed {total_loc} lines across {iterations} AST audits in {round(elapsed*1000, 2)}ms"
        )

    @classmethod
    def _benchmark_shannon_entropy(cls) -> BenchmarkMetric:
        # Generate 2 MB synthetic buffer
        chunk = "export SECRET_TOKEN='4f89b1c78e32a674d892019483c671b5'\nconst harmless = 'text value string';\n"
        buffer_size_mb = 2.0
        repeats = int((buffer_size_mb * 1024 * 1024) / len(chunk))
        test_data = (chunk * repeats).splitlines()

        start = time.perf_counter()
        count = 0
        for line in test_data:
            if len(line) > 20:
                SASTScanner.calculate_shannon_entropy(line)
                count += 1
        elapsed = time.perf_counter() - start

        mb_per_sec = round(buffer_size_mb / elapsed, 2)
        return BenchmarkMetric(
            name="Shannon Entropy Scanning",
            category="DevSecOps SAST",
            value=mb_per_sec,
            unit="MB/sec",
            details=f"Processed {buffer_size_mb} MB ({count} candidate strings) in {round(elapsed*1000, 2)}ms"
        )

    @classmethod
    def _benchmark_fts5_latency(cls) -> BenchmarkMetric:
        mem = SuperAgentMemory()
        queries = ["memory", "pacman", "error", "dockerfile", "kernel", "wayland", "niri", "agent"]
        runs = 25
        total_queries = len(queries) * runs

        start = time.perf_counter()
        for _ in range(runs):
            for q in queries:
                mem.search_learnings(q, limit=3)
        elapsed = time.perf_counter() - start

        avg_latency_ms = round((elapsed / total_queries) * 1000, 3)
        qps = round(total_queries / elapsed, 1)

        return BenchmarkMetric(
            name="SQLite BM25 FTS5 Search",
            category="Persistent Memory",
            value=avg_latency_ms,
            unit="ms/query",
            details=f"Executed {total_queries} queries ({qps} QPS) with p50 avg latency of {avg_latency_ms}ms"
        )

    @classmethod
    def _benchmark_git_checkpoint(cls) -> BenchmarkMetric:
        start = time.perf_counter()
        runs = 5
        for _ in range(runs):
            subprocess.run(["git", "stash", "create"], capture_output=True, check=False)
        elapsed = time.perf_counter() - start

        avg_ms = round((elapsed / runs) * 1000, 2)
        return BenchmarkMetric(
            name="Git Checkpoint Latency",
            category="Reflexion Engine",
            value=avg_ms,
            unit="ms/checkpoint",
            details=f"Ephemeral git tree creation avg latency {avg_ms}ms over {runs} sample checkpoints"
        )
