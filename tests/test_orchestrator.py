import pytest
from core.orchestrator import DAGOrchestrator, TaskNode


def test_topological_sort_and_wave_grouping():
    nodes = {
        "1": TaskNode("1", "T1", "worker", [], "", depends_on=[]),
        "2": TaskNode("2", "T2", "worker", [], "", depends_on=["1"]),
        "3": TaskNode("3", "T3", "worker", [], "", depends_on=["1"]),
        "4": TaskNode("4", "T4", "worker", [], "", depends_on=["2", "3"]),
    }
    waves = DAGOrchestrator.validate_and_group_waves(nodes)
    assert waves == [["1"], ["2", "3"], ["4"]]


def test_cycle_detection():
    nodes = {
        "A": TaskNode("A", "TA", "worker", [], "", depends_on=["B"]),
        "B": TaskNode("B", "TB", "worker", [], "", depends_on=["A"]),
    }
    with pytest.raises(ValueError, match="Ciclo detectado"):
        DAGOrchestrator.validate_and_group_waves(nodes)


def test_missing_dependency():
    nodes = {
        "A": TaskNode("A", "TA", "worker", [], "", depends_on=["Z"]),
    }
    with pytest.raises(ValueError, match="depends on non-existent task"):
        DAGOrchestrator.validate_and_group_waves(nodes)


def test_dynamic_task_spawning():
    output = """
Some initial log message
__SUPERAGENT_SPAWN__: [{"id": "child_1", "name": "Dynamic Subtask", "command": "echo subtask"}]
Final log message
"""
    spawned = DAGOrchestrator._extract_spawned_tasks(output, parent_id="root_task")
    assert len(spawned) == 1
    assert spawned[0].id == "child_1"
    assert spawned[0].depends_on == ["root_task"]
    assert spawned[0].command == "echo subtask"
