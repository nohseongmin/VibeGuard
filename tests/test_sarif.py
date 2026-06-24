"""SARIF 2.1.0 리포터 테스트."""

import json

from vibeguard.finding import Finding, Severity
from vibeguard.reporter import get_reporter
from vibeguard.scanner import ScanResult


def _result(severity=Severity.CRITICAL, file="a\\b.py", cwe="CWE-95"):
    r = ScanResult(files_scanned=1)
    r.findings.append(
        Finding(
            rule_id="VG-TEST-001",
            title="테스트 취약점",
            severity=severity,
            category="dangerous",
            file=file,
            line=3,
            snippet="eval(x)",
            explanation="설명",
            fix="고치세요",
            cwe=cwe,
            column=2,
        )
    )
    return r


def test_sarif_basic_structure():
    d = json.loads(get_reporter("sarif").render(_result()))
    assert d["version"] == "2.1.0"
    assert "$schema" in d
    run = d["runs"][0]
    assert run["tool"]["driver"]["name"] == "VibeGuard"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "VG-TEST-001"
    assert res["level"] == "error"  # CRITICAL -> error
    loc = res["locations"][0]["physicalLocation"]
    # Windows 역슬래시가 슬래시로 정규화되어야 함
    assert loc["artifactLocation"]["uri"] == "a/b.py"
    assert loc["region"]["startLine"] == 3
    assert loc["region"]["startColumn"] == 2


def test_sarif_rule_metadata():
    d = json.loads(get_reporter("sarif").render(_result()))
    rule = d["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "VG-TEST-001"
    assert rule["properties"]["security-severity"] == "9.0"
    assert "https://cwe.mitre.org/data/definitions/95.html" == rule["helpUri"]
    assert "external/cwe/cwe-95" in rule["properties"]["tags"]


def test_sarif_level_mapping():
    cases = [
        (Severity.CRITICAL, "error"),
        (Severity.HIGH, "error"),
        (Severity.MEDIUM, "warning"),
        (Severity.LOW, "note"),
        (Severity.INFO, "note"),
    ]
    for sev, level in cases:
        d = json.loads(get_reporter("sarif").render(_result(severity=sev)))
        assert d["runs"][0]["results"][0]["level"] == level


def test_sarif_empty_is_valid():
    d = json.loads(get_reporter("sarif").render(ScanResult(files_scanned=0)))
    assert d["version"] == "2.1.0"
    assert d["runs"][0]["results"] == []
    assert d["runs"][0]["tool"]["driver"]["rules"] == []
