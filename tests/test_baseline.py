"""베이스라인(지문 기반) 기능 테스트."""

from vibeguard import baseline
from vibeguard.finding import Finding, Severity


def _finding(rule="VG-X-1", file="a.py", snippet="bad()", line=1):
    return Finding(
        rule_id=rule,
        title="t",
        severity=Severity.HIGH,
        category="c",
        file=file,
        line=line,
        snippet=snippet,
        explanation="e",
        fix="f",
    )


def test_fingerprint_is_line_independent():
    assert _finding(line=1).fingerprint() == _finding(line=999).fingerprint()


def test_fingerprint_distinguishes_rule_file_snippet():
    assert _finding(rule="A").fingerprint() != _finding(rule="B").fingerprint()
    assert _finding(file="a.py").fingerprint() != _finding(file="b.py").fingerprint()
    assert _finding(snippet="x()").fingerprint() != _finding(snippet="y()").fingerprint()


def test_fingerprint_normalizes_path_separator():
    assert _finding(file="a/b.py").fingerprint() == _finding(file="a\\b.py").fingerprint()


def test_write_load_filter(tmp_path):
    findings = [_finding(rule="VG-A"), _finding(rule="VG-B")]
    path = str(tmp_path / "bl.json")
    assert baseline.write_baseline(path, findings) == 2

    known = baseline.load_fingerprints(path)
    new = _finding(rule="VG-C")
    remaining = baseline.filter_new(findings + [new], known)
    assert remaining == [new]


def test_filter_new_empty_when_all_known(tmp_path):
    findings = [_finding(rule="VG-A"), _finding(rule="VG-B")]
    path = str(tmp_path / "bl.json")
    baseline.write_baseline(path, findings)
    known = baseline.load_fingerprints(path)
    assert baseline.filter_new(findings, known) == []
