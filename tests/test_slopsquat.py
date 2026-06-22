"""슬롭스쿼팅/오타스쿼팅 탐지 단위 테스트(네트워크 미사용)."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard import slopsquat as ss  # noqa: E402


def test_extract_python_imports():
    text = "import os\nimport requests\nfrom flask import Flask\nimport numpy as np\n"
    names = ss.extract_python_imports(text)
    assert {"os", "requests", "flask", "numpy"} <= names


def test_extract_js_imports():
    text = "import React from 'react'\nconst x = require('axios')\nimport './local'\n"
    names = ss.extract_js_imports(text)
    assert "react" in names and "axios" in names
    assert "./local" not in names  # 상대경로 제외


def test_scoped_npm_package():
    assert ss._top_pkg_js("@scope/pkg/sub") == "@scope/pkg"


def test_levenshtein():
    assert ss.levenshtein("requests", "reqeusts") == 2
    assert ss.levenshtein("flask", "flask") == 0
    assert ss.levenshtein("numpy", "numpyy") == 1


def test_nearest_popular_typo():
    near = ss.nearest_popular("reqeusts", ss._POPULAR_PYPI)
    assert near is not None
    assert near[0] == "requests"
    assert near[1] <= 2


def test_nearest_popular_exact_is_none():
    assert ss.nearest_popular("requests", ss._POPULAR_PYPI) is None


def test_parse_requirements():
    text = "flask==2.0\nrequests>=2.1\n# comment\n-e .\nnumpy\n"
    names = ss.parse_requirements_txt(text)
    assert {"flask", "requests", "numpy"} == names


def test_parse_package_json():
    text = '{"dependencies": {"react": "^18"}, "devDependencies": {"jest": "^29"}}'
    names = ss.parse_package_json(text)
    assert {"react", "jest"} == names


def test_offline_typosquat_finding(tmp_path):
    # 오프라인 모드: 레지스트리 조회 없이 오타 휴리스틱만 동작해야 함
    (tmp_path / "app.py").write_text("import reqeusts\n", encoding="utf-8")
    findings = ss.check_project(str(tmp_path), offline=True)
    ids = {f.rule_id for f in findings}
    assert "VG-SLOP-002" in ids  # 오타스쿼팅 후보


def test_registry_cache_and_mock(tmp_path):
    # _head_ok 를 가짜로 대체해 '존재하지 않는 패키지' 경로를 검증
    (tmp_path / "app.py").write_text("import totallynotreal_pkg_xyz\n", encoding="utf-8")

    client = ss.RegistryClient(offline=False)
    # 강제로 캐시에 '존재하지 않음(False)' 주입
    orig = client._head_ok

    def fake(url):
        return False

    client._head_ok = fake  # type: ignore
    assert client.exists_pypi("totallynotreal_pkg_xyz") is False
    client._head_ok = orig  # 복구


def test_stdlib_not_flagged(tmp_path):
    (tmp_path / "app.py").write_text("import os\nimport sys\nimport json\n", encoding="utf-8")
    findings = ss.check_project(str(tmp_path), offline=True)
    # 표준 라이브러리는 검사 대상에서 제외되므로 결과 없음
    assert findings == []
