"""CVE(알려진 취약점) 검사 테스트 — 실제 네트워크를 쓰지 않는다.

OSV 호출부(_post_json/_get_json)를 monkeypatch 로 가짜 응답으로 대체해,
파서·심각도 매핑·Finding 생성 로직만 검증한다.
"""

from vibeguard import cve
from vibeguard.finding import Severity


def test_parse_requirements_only_pinned():
    text = "flask==2.0.1\nrequests>=2.0  # 고정 아님\nnumpy==1.26.0\n# 주석\n"
    got = cve.parse_requirements(text)
    assert ("flask", "2.0.1") in got
    assert ("numpy", "1.26.0") in got
    # '=='로 고정된 것만 — '>='는 버전 범위라 제외
    assert all(n != "requests" for n, _ in got)


def test_clean_ver_strips_range_prefixes():
    assert cve._clean_ver("^1.2.3") == "1.2.3"
    assert cve._clean_ver("~1.2") == "1.2"
    assert cve._clean_ver(">=1.0.0") == "1.0.0"
    assert cve._clean_ver("v3.4.5") == "3.4.5"
    assert cve._clean_ver("*") is None


def test_parse_package_json():
    text = '{"dependencies": {"express": "^4.17.1"}, "devDependencies": {"jest": "~29.0.0"}}'
    got = dict(cve.parse_package_json(text))
    assert got["express"] == "4.17.1"
    assert got["jest"] == "29.0.0"


def test_map_severity_from_database_specific():
    assert cve._map_severity({"database_specific": {"severity": "CRITICAL"}}) == Severity.CRITICAL
    assert cve._map_severity({"database_specific": {"severity": "MODERATE"}}) == Severity.MEDIUM
    assert cve._map_severity({"database_specific": {"severity": "LOW"}}) == Severity.LOW
    # 정보 없으면 기본 HIGH
    assert cve._map_severity({}) == Severity.HIGH


def test_map_severity_from_cvss_score():
    vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
    assert cve._map_severity(vuln) == Severity.CRITICAL


def test_fixed_version_and_cve_alias():
    detail = {
        "aliases": ["CVE-2018-18074", "PYSEC-2018-28"],
        "affected": [{
            "package": {"name": "requests"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
        }],
    }
    assert cve._cve_alias(detail) == "CVE-2018-18074"
    assert cve._fixed_version(detail, "requests") == "2.20.0"


def test_offline_returns_empty(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    assert cve.check_project_cve(str(tmp_path), offline=True) == []


def test_no_manifest_returns_empty(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert cve.check_project_cve(str(tmp_path), offline=False) == []


def test_end_to_end_mocked(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("requests==2.5.0\n", encoding="utf-8")

    monkeypatch.setattr(
        cve, "_post_json",
        lambda url, payload, timeout: {"results": [{"vulns": [{"id": "GHSA-x4qr-2fvf-3mr5"}]}]},
    )
    monkeypatch.setattr(
        cve, "_get_json",
        lambda url, timeout: {
            "id": "GHSA-x4qr-2fvf-3mr5",
            "aliases": ["CVE-2018-18074"],
            "summary": "requests before 2.20.0 sends auth over http redirect",
            "database_specific": {"severity": "HIGH"},
            "affected": [{
                "package": {"name": "requests"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}],
            }],
        },
    )

    findings = cve.check_project_cve(str(tmp_path), offline=False)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "VG-CVE-001"
    assert f.severity == Severity.HIGH
    assert f.category == "vulnerable-dependency"
    assert "CVE-2018-18074" in f.title
    assert "requests" in f.title
    assert "2.20.0" in f.fix           # 수정 버전 안내
    assert f.file == "requirements.txt"
    assert f.line == 1
    assert f.metadata["fixed"] == "2.20.0"


def test_network_failure_is_silent(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")

    def boom(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr(cve, "_post_json", boom)
    # 네트워크 실패는 조용히 빈 목록 — 스캔을 멈추면 안 된다
    assert cve.check_project_cve(str(tmp_path), offline=False) == []
