import subprocess
from pathlib import Path
from core.worktree_sandbox import WorktreeSandbox, CandidateEvaluation


def test_worktree_sandbox_lifecycle():
    with WorktreeSandbox() as sb:
        assert sb.created
        assert sb.worktree_dir.exists()
        res = sb.run_command("echo 'sandbox running'")
        assert res.passed
        assert "sandbox running" in res.stdout

    # After exit, worktree directory must be cleaned up
    assert not sb.worktree_dir.exists()


def test_candidate_tournament_scoring():
    cand1 = {
        "id": "c1_good",
        "desc": "Clean passing candidate",
        "command": "echo 'Candidate 1 executed'"
    }
    cand2 = {
        "id": "c2_failing",
        "desc": "Broken candidate",
        "command": "exit 1"
    }

    report = WorktreeSandbox.run_tournament(
        candidates=[cand1, cand2],
        test_command=None,
        promote_winner=False,
        max_workers=2
    )

    assert report["total_candidates"] == 2
    assert len(report["ranked_evaluations"]) == 2
    assert report["winner"] is not None
    assert report["winner"]["candidate_id"] == "c1_good"
    assert report["winner"]["passed"] is True
