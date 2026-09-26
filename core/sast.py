"""
core/sast.py - Lightweight Autonomous SAST & Secrets Detection Engine for SuperAgent
Detects leaked credentials, Shannon high-entropy tokens, and OWASP Top 10 anti-patterns without external dependencies.
"""

import ast
import re
import math
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    file_path: str
    line_number: int
    snippet: str
    description: str
    remediation: str


class SASTScanner:
    """Escáner estático autónomo para código fuente local y memoria pre-commit."""

    def __init__(self):
        self.secret_regexes = {
            "SEC001": ("AWS Access Key ID", r"\b(AKIA[0-9A-Z]{16})\b", "CRITICAL"),
            "SEC002": ("GitHub Personal Access Token", r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82})\b", "CRITICAL"),
            "SEC003": ("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----", "CRITICAL"),
            "SEC004": ("Hardcoded Secret/Token", r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.!@#$%^&*+=]{12,}['\"]", "HIGH"),
            "SEC005": ("Stripe API Key", r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b", "CRITICAL"),
            "SEC006": ("Slack Token", r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b", "CRITICAL"),
        }

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calcula la entropía de Shannon de una cadena de caracteres."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for char in set(data):
            p = data.count(char) / length
            entropy -= p * math.log2(p)
        return entropy

    def scan_text(self, text: str, filename: str = "<memory>") -> List[Finding]:
        """Escanea una cadena de texto en memoria."""
        findings: List[Finding] = []
        lines = text.splitlines()

        for idx, line in enumerate(lines, 1):
            line_str = line.strip()
            if "# nosec" in line_str or "# sast: ignore" in line_str:
                continue

            # 1. Reglas de Expresiones Regulares para Secretos
            for rule_id, (name, pattern, severity) in self.secret_regexes.items():
                if re.search(pattern, line_str):
                    findings.append(Finding(
                        rule_id=rule_id,
                        category="Secrets",
                        severity=severity,
                        file_path=filename,
                        line_number=idx,
                        snippet=line_str[:120],
                        description=f"Detección de secreto expuesto: {name}",
                        remediation="Extraiga este secreto a una variable de entorno o servicio de gestión de secretos."
                    ))

            # 2. Entropía de Shannon para tokens y cadenas literales largas
            string_literals = re.findall(r"['\"]([a-zA-Z0-9_\-+/=]{20,})['\"]", line_str)
            for lit in string_literals:
                entropy = self.calculate_shannon_entropy(lit)
                if entropy > 4.5:
                    # Descartar falsos positivos comunes
                    lower_lit = lit.lower()
                    if not any(token in lower_lit for token in ["dummy", "example", "mock", "test", "sha256", "uuid", "format"]):
                        findings.append(Finding(
                            rule_id="SEC-ENTROPY",
                            category="High-Entropy",
                            severity="HIGH",
                            file_path=filename,
                            line_number=idx,
                            snippet=line_str[:120],
                            description=f"Cadena de alta entropía detectada ({round(entropy, 2)} bits) - posible credencial/token",
                            remediation="Verifique si esta cadena representa un secreto en texto plano."
                        ))

        # 3. Análisis AST para Python
        if filename.endswith(".py") or filename == "<memory>":
            findings.extend(self._scan_python_ast(text, filename))

        # 4. Análisis léxico de patrones web / JS / TS
        if any(filename.endswith(ext) for ext in [".js", ".jsx", ".ts", ".tsx", ".html"]):
            findings.extend(self._scan_web_patterns(lines, filename))

        return findings

    def scan_file(self, file_path: Path) -> List[Finding]:
        """Escanea un archivo individual en disco."""
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_text(content, str(file_path))
        except Exception:
            return []

    def scan_directory(self, dir_path: Path, max_files: int = 500) -> List[Finding]:
        """Escanea un directorio recursivamente respetando extensiones de código."""
        target_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".c", ".cpp", ".sh", ".env", ".yml", ".yaml", ".json"}
        findings: List[Finding] = []
        count = 0

        for path in dir_path.rglob("*"):
            if count >= max_files:
                break
            if path.is_file() and path.suffix in target_exts:
                # Omitir .git, node_modules, .venv, etc.
                parts = path.parts
                if any(p in parts for p in [".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"]):
                    continue
                findings.extend(self.scan_file(path))
                count += 1

        return findings

    def _scan_python_ast(self, content: str, filepath: str) -> List[Finding]:
        """Escanea AST de Python para detección de inyecciones OWASP. aci: ignore"""
        findings = []
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return findings

        lines_list = content.splitlines()
        for node in ast.walk(tree):
            start_l = getattr(node, "lineno", 0)
            end_l = getattr(node, "end_lineno", start_l)
            node_lines = lines_list[max(0, start_l - 1):end_l]
            if any("# nosec" in l or "# sast: ignore" in l for l in node_lines):
                continue

            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # Command Injection: os.system o os.popen
                if func_name in ["system", "popen"] and getattr(node.func, "value", None) and getattr(node.func.value, "id", "") == "os":
                    findings.append(Finding(
                        rule_id="OWASP-A03-CMD",
                        category="Command Injection",
                        severity="CRITICAL",
                        file_path=filepath,
                        line_number=node.lineno,
                        snippet=f"os.{func_name}(...)",
                        description="Ejecución de shell insegura mediante os.system o os.popen",
                        remediation="Utilice subprocess.run(..., shell=False) pasando los argumentos en una lista de cadenas."
                    ))

                # Command Injection: subprocess(shell=True)
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(Finding(
                            rule_id="OWASP-A03-SHELL",
                            category="Command Injection",
                            severity="CRITICAL",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet="subprocess.*(..., shell=True)",
                            description="subprocess ejecutado con shell=True permite inyección de comandos",
                            remediation="Desactive shell=True y pase los argumentos como lista independiente."
                        ))

                # SQL Injection: cursor.execute con f-string o interpolación %
                if func_name == "execute" and node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                        findings.append(Finding(
                            rule_id="OWASP-A03-SQLI",
                            category="SQL Injection",
                            severity="CRITICAL",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet="cursor.execute(f'...' or '...' % ...)",
                            description="Interpolación dinámica de cadenas dentro de consulta SQL",
                            remediation="Utilice consultas parametrizadas con placeholders (ej. execute(query, (params,)))"
                        ))

                # Insecure Deserialization: pickle.loads / yaml.load unsafe
                if func_name in ["load", "loads"]:
                    val = getattr(node.func, "value", None)
                    mod_name = getattr(val, "id", "") if val else ""
                    if mod_name == "pickle":
                        findings.append(Finding(
                            rule_id="OWASP-A08-DESER",
                            category="Insecure Deserialization",
                            severity="CRITICAL",
                            file_path=filepath,
                            line_number=node.lineno,
                            snippet=f"pickle.{func_name}(...)",
                            description="Deserialización con pickle de datos no confiables",
                            remediation="Utilice formatos seguros como JSON o Protocol Buffers."
                        ))

        return findings

    def _scan_web_patterns(self, lines: List[str], filepath: str) -> List[Finding]:
        findings = []
        for idx, line in enumerate(lines, 1):
            if "dangerouslySetInnerHTML" in line:
                findings.append(Finding(
                    rule_id="OWASP-A03-XSS",
                    category="XSS",
                    severity="HIGH",
                    file_path=filepath,
                    line_number=idx,
                    snippet=line.strip()[:120],
                    description="dangerouslySetInnerHTML puede permitir Cross-Site Scripting (XSS)",
                    remediation="Sanitice el contenido HTML con DOMPurify antes de renderizarlo."
                ))
            if re.search(r"exec\s*\(\s*`[^`]*\${", line):
                findings.append(Finding(
                    rule_id="OWASP-A03-NODE-CMD",
                    category="Command Injection",
                    severity="CRITICAL",
                    file_path=filepath,
                    line_number=idx,
                    snippet=line.strip()[:120],
                    description="Ejecución de child_process.exec con template strings interpoladas",
                    remediation="Utilice execFile o spawn con argumentos como un array de strings."
                ))
        return findings
