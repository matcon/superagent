from core.aci_guard import ACIGuard


def test_aci_guard_valid_python():
    code = """
def clean_function(x: int) -> int:
    return x * 2
"""
    rep = ACIGuard.audit_code(code, "test.py")
    assert rep.valid_syntax
    assert rep.passed
    assert len(rep.functions) == 1
    assert rep.functions[0].cyclomatic_complexity == 1


def test_aci_guard_syntax_error():
    code = """
def broken_syntax(
    return 42
"""
    rep = ACIGuard.audit_code(code, "test.py")
    assert not rep.valid_syntax
    assert not rep.passed
    assert rep.syntax_line is not None


def test_aci_guard_line_range_reporting():
    code = """
def complex_fn(a, b, c):
    if a:
        if b:
            if c:
                return 1
    return 0
"""
    rep = ACIGuard.audit_code(code, "test.py")
    assert rep.valid_syntax
    assert len(rep.functions) == 1
    fn = rep.functions[0]
    assert fn.line_start == 2
    assert fn.line_end == 7
