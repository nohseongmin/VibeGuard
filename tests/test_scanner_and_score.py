"""스캐너 순회, 점수, 리포터 통합 테스트."""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard.scanner import Scanner  # noqa: E402
from vibeguard.finding import Finding, Severity  # noqa: E402
from vibeguard import score as sc  # noqa: E402
from vibeguard.reporter import JsonReporter, MarkdownReporter, TerminalReporter  # noqa: E402


def _mk(sev):
    return Finding(
        rule_id="X", title="t", severity=sev, category="c",
        file="f.py", line=1, snippet="s", explanation="e", fix="fix",
    )


def test_score_perfect_when_clean():
    assert sc.compute_score([]) == 100
    assert sc.grade(100) == "A"


def test_score_decreases_with_severity():
    assert sc.compute_score([_mk(Severity.CRITICAL)]) == 70
    assert sc.compute_score([_mk(Severity.LOW)]) == 98


def test_score_floor_zero():
    many = [_mk(Severity.CRITICAL) for _ in range(10)]
    assert sc.compute_score(many) == 0


def test_verdict_critical():
    v = sc.verdict(70, [_mk(Severity.CRITICAL)])
    assert "치명적" in v


def test_scanner_skips_node_modules(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "bad.py").write_text("eval(x)\n", encoding="utf-8")
    (tmp_path / "good.py").write_text("x = 1\n", encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    # node_modules 안의 파일은 스캔되지 않아야 함
    assert all("node_modules" not in f.file for f in result.findings)


def test_scanner_walks_and_finds(tmp_path):
    sub = tmp_path / "src"
    sub.mkdir()
    (sub / "v.py").write_text('k = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n', encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    assert result.files_scanned >= 1
    assert any(f.rule_id == "VG-SECRET-001" for f in result.findings)


def test_json_reporter_valid(tmp_path):
    (tmp_path / "v.py").write_text("eval(x)\n", encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    out = JsonReporter().render(result)
    data = json.loads(out)
    assert data["tool"] == "vibeguard"
    assert "score" in data and "findings" in data


def test_markdown_reporter_runs(tmp_path):
    (tmp_path / "v.py").write_text("eval(x)\n", encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    out = MarkdownReporter().render(result)
    assert "VibeGuard" in out and "VG-EXEC-001" in out


def test_terminal_reporter_no_color_has_no_ansi(tmp_path):
    (tmp_path / "v.py").write_text("eval(x)\n", encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    out = TerminalReporter(use_color=False).render(result)
    assert "\033[" not in out  # 색상 코드 없음
