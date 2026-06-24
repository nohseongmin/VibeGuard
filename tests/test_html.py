"""HTML 리포터 테스트."""

from vibeguard.finding import Finding, Severity
from vibeguard.reporter import get_reporter
from vibeguard.scanner import ScanResult


def _result():
    r = ScanResult(files_scanned=1)
    r.findings.append(
        Finding(
            rule_id="VG-X-1",
            title="<주의> eval",
            severity=Severity.CRITICAL,
            category="dangerous",
            file="a/b.py",
            line=3,
            snippet="eval(x) & y",
            explanation="설명 <tag>",
            fix="고치세요",
            cwe="CWE-95",
            column=2,
        )
    )
    return r


def test_html_is_self_contained_document():
    out = get_reporter("html").render(_result())
    assert out.startswith("<!DOCTYPE html>")
    assert out.strip().endswith("</html>")
    assert "<style>" in out  # 인라인 CSS


def test_html_escapes_user_content():
    out = get_reporter("html").render(_result())
    assert "&lt;주의&gt; eval" in out
    assert "eval(x) &amp; y" in out
    assert "<주의>" not in out


def test_html_empty_result():
    out = get_reporter("html").render(ScanResult(files_scanned=0))
    assert "발견된 문제가 없습니다" in out
    assert out.strip().endswith("</html>")
