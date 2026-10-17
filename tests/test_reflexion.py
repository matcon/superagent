from core.reflexion import ReflexionEngine, DiagnosticReport


def test_fingerprint_generation():
    fp1 = ReflexionEngine.compute_fingerprint(
        stderr="ZeroDivisionError",
        errors=["ZeroDivisionError: division by zero"],
        sast=[],
        complexity=[]
    )
    fp2 = ReflexionEngine.compute_fingerprint(
        stderr="ZeroDivisionError",
        errors=["ZeroDivisionError: division by zero"],
        sast=[],
        complexity=[]
    )
    assert fp1 == fp2
    assert len(fp1) == 16


def test_oscillation_guard():
    engine = ReflexionEngine()
    rep1 = engine.run_check("python3 -c '1/0'", timeout_s=5, auto_checkpoint=False)
    assert not rep1.passed
    assert not rep1.is_oscillating

    # Run exact same failing command again
    rep2 = engine.run_check("python3 -c '1/0'", timeout_s=5, auto_checkpoint=False)
    assert not rep2.passed
    assert rep2.is_oscillating
    assert "[OSCILLATION GUARD]" in rep2.suggested_hypothesis
