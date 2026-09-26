"""
memory.py - Tripartite Memory Architecture (Episodic, Knowledge Graph, & Learnings)
"""

import os
import sys
import json
import sqlite3
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = Path.home() / ".superagent" / "data" / "memory.db"


class SuperAgentMemory:
    """Manages persistent episodic memory, learned patterns, and graphify knowledge retrieval."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes database schema and FTS5 triggers. aci: ignore"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 1. Learnings & Reflexion table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS learnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    category TEXT NOT NULL,
                    context TEXT,
                    problem TEXT NOT NULL,
                    solution TEXT NOT NULL,
                    tags TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # FTS5 virtual table for fast full-text search and BM25 ranking
            cursor.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS learnings_fts USING fts5(
                    context, problem, solution, tags,
                    content='learnings',
                    content_rowid='id'
                );
            """)

            # Triggers to keep FTS in sync
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS learnings_ai AFTER INSERT ON learnings BEGIN
                    INSERT INTO learnings_fts(rowid, context, problem, solution, tags)
                    VALUES (new.id, new.context, new.problem, new.solution, new.tags);
                END;
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS learnings_ad AFTER DELETE ON learnings BEGIN
                    INSERT INTO learnings_fts(learnings_fts, rowid, context, problem, solution, tags)
                    VALUES('delete', old.id, old.context, old.problem, old.solution, old.tags);
                END;
            """)
            cursor.execute("""
                CREATE TRIGGER IF NOT EXISTS learnings_au AFTER UPDATE ON learnings BEGIN
                    INSERT INTO learnings_fts(learnings_fts, rowid, context, problem, solution, tags)
                    VALUES('delete', old.id, old.context, old.problem, old.solution, old.tags);
                    INSERT INTO learnings_fts(rowid, context, problem, solution, tags)
                    VALUES (new.id, new.context, new.problem, new.solution, new.tags);
                END;
            """)

            # 2. Architectural Decision Records (ADR)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS adr (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_path TEXT NOT NULL,
                    title TEXT NOT NULL,
                    context TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    consequences TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # 3. Tasks and Execution DAGs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    goal TEXT NOT NULL,
                    dag_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metrics_json TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def add_learning(self, category: str, problem: str, solution: str, context: str = "", tags: str = "") -> int:
        """Record an error solved, technical insight, or architectural decision."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO learnings (category, context, problem, solution, tags) VALUES (?, ?, ?, ?, ?)",
                (category, context, problem, solution, tags)
            )
            conn.commit()
            return cursor.lastrowid

    def search_learnings(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Search learnings using FTS5 BM25 relevance ranking."""
        # Sanitize query for FTS5 syntax
        clean_query = "".join(c if c.isalnum() or c.isspace() else " " for c in query).strip()
        if not clean_query:
            return []

        formatted_query = " OR ".join(f'"{word}"*' for word in clean_query.split())
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    SELECT l.id, l.category, l.context, l.problem, l.solution, l.tags, l.created_at,
                           bm25(learnings_fts) as rank
                    FROM learnings_fts f
                    JOIN learnings l ON f.rowid = l.id
                    WHERE learnings_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                """, (formatted_query, limit))
                return [dict(row) for row in cursor.fetchall()]
            except sqlite3.OperationalError:
                # Fallback to LIKE
                cursor.execute("""
                    SELECT id, category, context, problem, solution, tags, created_at
                    FROM learnings
                    WHERE problem LIKE ? OR solution LIKE ? OR tags LIKE ?
                    ORDER BY id DESC LIMIT ?
                """, (f"%{clean_query}%", f"%{clean_query}%", f"%{clean_query}%", limit))
                return [dict(row) for row in cursor.fetchall()]

    def record_adr(self, project_path: str, title: str, context: str, decision: str, consequences: str = "") -> int:
        """Save an Architectural Decision Record."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO adr (project_path, title, context, decision, consequences) VALUES (?, ?, ?, ?, ?)",
                (project_path, title, context, decision, consequences)
            )
            conn.commit()
            return cursor.lastrowid

    def get_adrs(self, project_path: str) -> List[Dict[str, Any]]:
        """Retrieve ADRs for a given project directory."""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM adr WHERE project_path = ? ORDER BY id ASC",
                (project_path,)
            )
            return [dict(row) for row in cursor.fetchall()]

    @staticmethod
    def query_graphify(question: str, cwd: Optional[str] = None) -> Optional[str]:
        """Query knowledge graph using graphify CLI if graphify-out exists."""
        target_dir = Path(cwd) if cwd else Path.cwd()
        graph_file = target_dir / "graphify-out" / "graph.json"

        # Walk up to find graphify-out if needed
        curr = target_dir
        while not graph_file.exists() and curr != curr.parent:
            curr = curr.parent
            graph_file = curr / "graphify-out" / "graph.json"

        if not graph_file.exists():
            return None

        try:
            res = subprocess.run(
                ["graphify", "query", question],
                cwd=str(graph_file.parent.parent),
                capture_output=True,
                text=True,
                timeout=10
            )
            if res.returncode == 0 and res.stdout.strip():
                return res.stdout.strip()
        except Exception:
            pass
        return None
