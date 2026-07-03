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


def test_parse_requirements_extras_syntax():
    # uvicorn[standard]==0.23.0 처럼 extras 표기도 잡아야 한다
    text = "uvicorn[standard]==0.23.0\ncelery[redis,msgpack]==5.2.0\n"
    got = dict(cve.parse_requirements(text))
    assert got["uvicorn"] == "0.23.0"
    assert got["celery"] == "5.2.0"


def test_parse_package_lock_v3():
    text = """{
      "lockfileVersion": 3,
      "packages": {
        "": {"name": "myapp", "version": "1.0.0"},
        "node_modules/express": {"version": "4.17.1"},
        "node_modules/express/node_modules/qs": {"version": "6.7.0"}
      }
    }"""
    got = dict(cve.parse_package_lock(text))
    assert got["express"] == "4.17.1"
    assert got["qs"] == "6.7.0"          # 중첩 node_modules 는 마지막 이름
    assert "myapp" not in got            # 루트("" 키)는 제외


def test_parse_package_lock_v1():
    text = """{
      "lockfileVersion": 1,
      "dependencies": {
        "lodash": {"version": "4.17.15",
                   "dependencies": {"inner": {"version": "1.0.0"}}}
      }
    }"""
    got = dict(cve.parse_package_lock(text))
    assert got["lodash"] == "4.17.15"
    assert got["inner"] == "1.0.0"


def test_parse_pipfile_lock():
    text = '{"default": {"requests": {"version": "==2.5.0"}}, "develop": {"pytest": {"version": "==7.0.0"}}}'
    got = dict(cve.parse_pipfile_lock(text))
    assert got["requests"] == "2.5.0"
    assert got["pytest"] == "7.0.0"


def test_parse_poetry_lock():
    text = '''
[[package]]
name = "flask"
version = "0.12.2"
description = "web framework"

[[package]]
name = "jinja2"
version = "2.10"
'''
    got = dict(cve.parse_poetry_lock(text))
    assert got["flask"] == "0.12.2"
    assert got["jinja2"] == "2.10"


def test_lockfile_wins_over_package_json(tmp_path):
    # 같은 폴더에 락파일이 있으면 package.json 은 건너뛴다(정확 버전 우선)
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.0.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion": 3, "packages": {"node_modules/express": {"version": "4.17.1"}}}',
        encoding="utf-8")
    targets = cve._collect_manifests(str(tmp_path))
    vers = [t[2] for t in targets if t[1] == "express"]
    assert vers == ["4.17.1"]            # ^4.0.0(추정)이 아니라 설치본 4.17.1 하나만


def test_collect_dedupes_same_target(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("flask==2.0.1\n", encoding="utf-8")
    targets = cve._collect_manifests(str(tmp_path))
    assert len([t for t in targets if t[1] == "flask"]) == 1


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
