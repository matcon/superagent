"""
jit_tool.py - Just-In-Time Tool Synthesis & FastMCP Server Generator
"""

import os
import ast
import stat
import json
from pathlib import Path
from typing import Dict, Any, Optional

TOOLS_DIR = Path.home() / ".superagent" / "tools"
REGISTRY_FILE = TOOLS_DIR / "registry.json"


class JITToolSynthesizer:
    """Dynamically generates, validates with AST, and installs on-the-fly CLI and MCP tools."""

    def __init__(self, tools_dir: Path = TOOLS_DIR):
        self.tools_dir = tools_dir
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = REGISTRY_FILE
        self._init_registry()

    def _init_registry(self):
        if not self.registry_file.exists():
            self.registry_file.write_text(json.dumps({}, indent=2))

    def _get_registry(self) -> Dict[str, Any]:
        try:
            return json.loads(self.registry_file.read_text())
        except Exception:
            return {}

    def _save_registry(self, reg: Dict[str, Any]):
        self.registry_file.write_text(json.dumps(reg, indent=2))

    def synthesize_cli_tool(
        self,
        name: str,
        description: str,
        python_code: str,
        dependencies: Optional[list] = None
    ) -> Dict[str, Any]:
        """Synthesize a standalone Python CLI tool with PEP 723 script metadata."""
        # 1. AST Validation
        try:
            ast.parse(python_code)
        except SyntaxError as e:
            return {"success": False, "error": f"AST Syntax Validation Failed: {e}"}

        # 2. Add shebang and PEP 723 metadata if uv dependencies are specified
        header_lines = ["#!/usr/bin/env python3"]
        if dependencies:
            dep_str = ", ".join(f'"{d}"' for d in dependencies)
            header_lines.extend([
                "# /// script",
                f"# dependencies = [{dep_str}]",
                "# ///"
            ])

        full_code = "\n".join(header_lines) + "\n\n" + python_code.strip() + "\n"

        target_path = self.tools_dir / f"{name}.py"
        target_path.write_text(full_code)

        # Make executable
        st = os.stat(target_path)
        os.chmod(target_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

        # Register in registry
        reg = self._get_registry()
        reg[name] = {
            "name": name,
            "description": description,
            "path": str(target_path),
            "dependencies": dependencies or [],
            "created_at": str(Path(target_path).stat().st_mtime)
        }
        self._save_registry(reg)

        return {
            "success": True,
            "tool_name": name,
            "path": str(target_path),
            "command": f"python3 {target_path}" if not dependencies else f"uv run {target_path}"
        }

    def list_tools(self) -> Dict[str, Any]:
        return self._get_registry()
