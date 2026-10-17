import tempfile
from pathlib import Path
from core.auto_fix import AutoFixEngine


def test_apply_safe_fix_valid():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = Path(tmpdir) / "app.py"
        f.write_text("def hello():\n    print('old')\n")

        res = AutoFixEngine.apply_safe_fix(f, "def hello():\n    print('new')\n")
        assert res["applied"]
        assert "+    print('new')" in res["diff"]
        assert "-    print('old')" in res["diff"]
        assert "print('new')" in f.read_text()


def test_apply_safe_fix_invalid_syntax():
    with tempfile.TemporaryDirectory() as tmpdir:
        f = Path(tmpdir) / "app.py"
        f.write_text("def hello():\n    pass\n")

        res = AutoFixEngine.apply_safe_fix(f, "def broken(\n")
        assert not res["applied"]
        assert "SyntaxError" in res["error"]
        # Original content must remain intact
        assert "def hello():" in f.read_text()


def test_dockerfile_remediation():
    lines = [
        "FROM python:latest",
        "WORKDIR /app",
        "CMD [\"python\", \"app.py\"]"
    ]
    new_lines, fixes = AutoFixEngine._remediate_dockerfile(lines, "Dockerfile")
    assert any("USER 10001:10001" in l for l in new_lines)
    assert any(":stable" in l for l in new_lines)
    assert len(fixes) >= 2
