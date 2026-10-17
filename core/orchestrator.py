"""
orchestrator.py - DAG Swarm Task Orchestration & Parallel Execution Engine
"""

import sys
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Set
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
from pathlib import Path

from .os_control import OSControl


@dataclass
class TaskNode:
    id: str
    name: str
    role: str
    skills: List[str]
    prompt: str
    depends_on: List[str] = field(default_factory=list)
    command: Optional[str] = None
    cwd: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed
    result: Optional[str] = None
    error: Optional[str] = None
    duration_s: float = 0.0


class DAGOrchestrator:
    """Manages DAG task dependency resolution, concurrency scheduling, and parallel execution."""

    def __init__(self, goal: str, max_workers: Optional[int] = None):
        self.goal = goal
        self.nodes: Dict[str, TaskNode] = {}
        if max_workers is None:
            telemetry = OSControl.get_telemetry()
            self.max_workers = telemetry.recommended_concurrency
        else:
            self.max_workers = max_workers

    def add_task(
        self,
        task_id: str,
        name: str,
        role: str,
        skills: List[str],
        prompt: str,
        depends_on: Optional[List[str]] = None,
        command: Optional[str] = None,
        cwd: Optional[str] = None
    ) -> "DAGOrchestrator":
        self.nodes[task_id] = TaskNode(
            id=task_id,
            name=name,
            role=role,
            skills=skills,
            prompt=prompt,
            depends_on=depends_on or [],
            command=command,
            cwd=cwd
        )
        return self

    @classmethod
    def validate_and_group_waves(cls, nodes: Dict[str, TaskNode]) -> List[List[str]]:
        """Agrupa TaskNodes en oleadas concurrentes o lanza ValueError si existe un ciclo (algoritmo de Kahn)."""
        in_degree = {nid: 0 for nid in nodes}
        dependents = {nid: [] for nid in nodes}

        for nid, node in nodes.items():
            for dep in node.depends_on:
                if dep not in nodes:
                    raise ValueError(f"Task '{nid}' depends on non-existent task '{dep}'")
                dependents[dep].append(nid)
                in_degree[nid] += 1

        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        waves: List[List[str]] = []
        visited = 0

        while queue:
            current_wave = list(queue)
            queue.clear()
            waves.append(current_wave)
            visited += len(current_wave)

            for nid in current_wave:
                for child in dependents[nid]:
                    in_degree[child] -= 1
                    if in_degree[child] == 0:
                        queue.append(child)

        if visited != len(nodes):
            raise ValueError("Ciclo detectado en el DAG de TaskNodes; dependencias circulares no permitidas.")
        return waves

    def validate_dag(self) -> List[str]:
        """Validate dependencies and perform topological sort using Kahn's algorithm."""
        waves = self.validate_and_group_waves(self.nodes)
        return [nid for wave in waves for nid in wave]

    def to_mermaid(self) -> str:
        """Render DAG as Mermaid flowchart."""
        lines = ["flowchart TD"]
        for nid, node in self.nodes.items():
            safe_name = node.name.replace('"', "'")
            lines.append(f'    {nid}["{safe_name} ({node.role})"]')
            for dep in node.depends_on:
                lines.append(f"    {dep} --> {nid}")
        return "\n".join(lines)

    def execute_commands_parallel(self) -> Dict[str, Any]:
        """Execute tasks with shell commands adhering to DAG dependency waves. aci: ignore"""
        self.validate_dag()
        completed: Set[str] = set()
        failed: Set[str] = set()

        start_time = time.time()
        print(f"[SuperAgent DAG] Starting execution with up to {self.max_workers} concurrent workers...")

        while len(completed) + len(failed) < len(self.nodes):
            ready_nodes = [
                node for nid, node in self.nodes.items()
                if node.status == "pending" and all(dep in completed for dep in node.depends_on)
            ]

            if not ready_nodes:
                if any(node.status == "running" for node in self.nodes.values()):
                    time.sleep(0.1)
                    continue
                else:
                    # Unresolvable tasks due to failures in upstream dependencies
                    for nid, node in self.nodes.items():
                        if node.status == "pending":
                            node.status = "failed"
                            node.error = "Upstream dependency failed."
                            failed.add(nid)
                    break

            with ThreadPoolExecutor(max_workers=min(self.max_workers, len(ready_nodes))) as executor:
                futures = {}
                for node in ready_nodes:
                    node.status = "running"
                    futures[executor.submit(self._run_single_task, node)] = node

                for future in as_completed(futures):
                    node = futures[future]
                    try:
                        res = future.result()
                        if res["success"]:
                            node.status = "completed"
                            node.result = res["output"]
                            completed.add(node.id)

                            # Detección y mutación dinámica del DAG en caliente
                            spawned = self._extract_spawned_tasks(res["output"], parent_id=node.id)
                            if spawned:
                                for st in spawned:
                                    if st.id not in self.nodes:
                                        self.nodes[st.id] = st
                                        print(f"[SuperAgent DAG] Dynamically mutated DAG: Added task '{st.id}' ({st.name})")
                                self.validate_dag()
                        else:
                            node.status = "failed"
                            node.error = res["error"]
                            failed.add(node.id)
                    except Exception as exc:
                        node.status = "failed"
                        node.error = str(exc)
                        failed.add(node.id)

        total_duration = time.time() - start_time
        return {
            "goal": self.goal,
            "total_duration_s": round(total_duration, 2),
            "completed": list(completed),
            "failed": list(failed),
            "tasks": {nid: asdict(node) for nid, node in self.nodes.items()}
        }

    @classmethod
    def _extract_spawned_tasks(cls, output: str, parent_id: str) -> List[TaskNode]:
        """Extrae tareas dinámicamente inyectadas desde la salida del proceso."""
        if "__SUPERAGENT_SPAWN__:" not in output:
            return []
        spawned = []
        try:
            parts = output.split("__SUPERAGENT_SPAWN__:")
            for p in parts[1:]:
                chunk = p.strip()
                if chunk.startswith("["):
                    end_idx = chunk.find("]") + 1
                    chunk = chunk[:end_idx]
                else:
                    chunk = chunk.splitlines()[0]

                tasks_data = json.loads(chunk)
                for t in tasks_data:
                    deps = t.get("depends_on", [parent_id])
                    spawned.append(TaskNode(
                        id=t["id"],
                        name=t.get("name", t["id"]),
                        role=t.get("role", "dynamic_worker"),
                        skills=t.get("skills", []),
                        prompt=t.get("prompt", ""),
                        depends_on=deps,
                        command=t.get("command"),
                        cwd=t.get("cwd")
                    ))
        except Exception:
            pass
        return spawned

    def _run_single_task(self, node: TaskNode) -> Dict[str, Any]:
        """Worker executing a single node's command."""
        t0 = time.time()
        if not node.command:
            # Informational / Subagent prompt node without local command
            node.duration_s = round(time.time() - t0, 3)
            return {"success": True, "output": f"Subagent Prompt Prepared: {node.prompt[:100]}..."}

        try:
            cwd = node.cwd or str(Path.cwd())
            res = subprocess.run(
                node.command,
                shell=True,  # nosec: intentional shell runner for DAG task nodes
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=120
            )
            node.duration_s = round(time.time() - t0, 3)
            if res.returncode == 0:
                return {"success": True, "output": res.stdout.strip()}
            else:
                return {"success": False, "error": res.stderr.strip() or res.stdout.strip()}
        except subprocess.TimeoutExpired:
            node.duration_s = round(time.time() - t0, 3)
            return {"success": False, "error": "Command execution timed out after 120s"}
        except Exception as exc:
            node.duration_s = round(time.time() - t0, 3)
            return {"success": False, "error": str(exc)}
