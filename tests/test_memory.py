import tempfile
import sqlite3
from pathlib import Path
from core.memory import SuperAgentMemory


def test_memory_wal_mode_and_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        mem = SuperAgentMemory(db_path=db_path)

        with sqlite3.connect(str(db_path)) as conn:
            mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
            assert mode.lower() == "wal"


def test_memory_deduplication():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        mem = SuperAgentMemory(db_path=db_path)

        id1 = mem.add_learning(
            category="bug", problem="crash on start", solution="fix null pointer", context="main.py"
        )
        id2 = mem.add_learning(
            category="bug", problem="crash on start", solution="fix null pointer", context="main.py"
        )
        assert id1 == id2, "Duplicate learning must return existing ID"


def test_memory_search_and_semantic_expansion():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        mem = SuperAgentMemory(db_path=db_path)

        mem.add_learning(
            category="stability",
            problem="SIGSEGV signal triggered in flutter rendering engine",
            solution="switched backend rendering context to vulkan",
            context="wayland"
        )

        # Search using synonym 'crash' which maps to 'sigsegv'
        results = mem.search_learnings("crash", semantic_expand=True)
        assert len(results) > 0
        assert "SIGSEGV" in results[0]["problem"]


def test_memory_compaction():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_memory.db"
        mem = SuperAgentMemory(db_path=db_path)

        with mem._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO learnings (category, context, problem, solution, tags) VALUES (?, ?, ?, ?, ?)",
                ("cat", "ctx", "prob", "sol", "tag")
            )
            cursor.execute(
                "INSERT INTO learnings (category, context, problem, solution, tags) VALUES (?, ?, ?, ?, ?)",
                ("cat", "ctx", "prob", "sol", "tag")
            )
            conn.commit()

        deleted = mem.compact_learnings()
        assert deleted == 1
