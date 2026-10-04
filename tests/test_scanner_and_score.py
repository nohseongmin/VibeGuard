"""스캐너 순회, 점수, 리포터 통합 테스트."""

import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard.scanner import MAX_FILE_BYTES, MAX_LINE_LEN, ScanResult, Scanner  # noqa: E402
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


@pytest.mark.parametrize("name", [None, "app.html"])
def test_no_supported_code_is_unrated_across_reporters(tmp_path, name):
    from vibeguard.reporter import get_reporter
    from vibeguard.server import build_scan_payload

    if name:
        (tmp_path / name).write_text('<script>eval(location.hash)</script>', encoding="utf-8")
    result = Scanner().scan(str(tmp_path))
    assert result.files_scanned == 0
    assert sc.summary(result)[0] is None
    for fmt in ("terminal", "json", "markdown", "html"):
        output = get_reporter(fmt).render(result)
        assert "미검사" in output
        assert "100/100" not in output
        assert "안전합니다" not in output
    sarif = json.loads(get_reporter("sarif").render(result))
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    payload = build_scan_payload(str(tmp_path), no_deps=True)
    assert payload["score"] is None
    assert payload["grade"] == "미검사"


@pytest.mark.parametrize("problem", ["oversized", "long-line", "invalid-utf8", "unreadable", "no-rules"])
def test_incomplete_scan_preserves_findings_and_withholds_score(tmp_path, problem):
    path = tmp_path / "partial.py"
    path.write_text("eval(value)\n", encoding="utf-8")
    if problem == "oversized":
        path.write_bytes(b" " * (MAX_FILE_BYTES + 1))
    elif problem == "long-line":
        path.write_text("eval(value)\n" + "x" * (MAX_LINE_LEN + 1), encoding="utf-8")
    elif problem == "invalid-utf8":
        path.write_bytes(b"\xff")
    (tmp_path / "clean.py").write_text("value = 1\n", encoding="utf-8")
    scanner = Scanner(rules=[] if problem == "no-rules" else None)
    if problem == "unreadable":
        real_open = open
        def guarded_open(file, *args, **kwargs):
            if str(file) == str(path):
                raise PermissionError("denied")
            return real_open(file, *args, **kwargs)
        with patch("builtins.open", guarded_open):
            result = scanner.scan(str(tmp_path))
    else:
        result = scanner.scan(str(tmp_path))
    assert result.files_skipped >= 1
    assert result.warnings
    assert sc.summary(result)[0] is None
    if problem == "long-line":
        assert any(f.rule_id == "VG-EXEC-001" for f in result.findings)
    assert "불완전" in sc.summary(result)[1] if result.files_scanned else sc.summary(result)[1] == "미검사"


def test_clean_supported_scan_keeps_numeric_score(tmp_path):
    (tmp_path / "clean.py").write_text("value = 1\n", encoding="utf-8")
    assert sc.summary(Scanner().scan(str(tmp_path)))[:2] == (100, "A")


def test_traversal_error_is_reported(tmp_path):
    with patch("vibeguard.scanner.os.walk", side_effect=PermissionError("denied")):
        result = Scanner().scan(str(tmp_path))
    assert result.files_skipped == 1
    assert result.warnings
    assert sc.summary(result)[0] is None


def test_unreadable_subtree_does_not_hide_readable_findings(tmp_path):
    (tmp_path / "app.py").write_text("eval(value)\n", encoding="utf-8")
    def walk(root, onerror):
        yield root, [], ["app.py"]
        onerror(PermissionError(13, "denied", str(tmp_path / "private")))
    with patch("vibeguard.scanner.os.walk", walk):
        result = Scanner().scan(str(tmp_path))
    assert result.files_scanned == result.files_skipped == 1
    assert result.findings
    assert sc.summary(result)[1] == "불완전"
