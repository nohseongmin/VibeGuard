"""설정 파일(.vibeguard.json) 동작 테스트 (CLI 통합)."""

import json

from vibeguard.cli import main


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def _scan_json(tmp_path, capsys, *extra):
    code = main(["scan", str(tmp_path), "--offline", "--format", "json", *extra])
    return code, json.loads(capsys.readouterr().out)


def test_config_disable_rule(tmp_path, capsys):
    _write(tmp_path, "v.py", "ctx = ssl._create_unverified_context()\n")
    _write(tmp_path, ".vibeguard.json", '{"disable": ["VG-WEB-009"]}')
    _, d = _scan_json(tmp_path, capsys)
    assert all(f["rule_id"] != "VG-WEB-009" for f in d["findings"])


def test_config_exclude_path(tmp_path, capsys):
    _write(tmp_path, "v.py", "ctx = ssl._create_unverified_context()\n")
    _write(tmp_path, ".vibeguard.json", '{"exclude": ["v.py"]}')
    _, d = _scan_json(tmp_path, capsys)
    assert d["findings"] == []


def test_config_fail_on(tmp_path, capsys):
    _write(tmp_path, "v.py", "ctx = ssl._create_unverified_context()\n")
    _write(tmp_path, ".vibeguard.json", '{"fail_on": "high"}')
    code, _ = _scan_json(tmp_path, capsys)
    assert code == 1


def test_config_min_severity(tmp_path, capsys):
    _write(tmp_path, "v.py", "import tarfile\ntarfile.open(p).extractall(d)\n")
    _write(tmp_path, ".vibeguard.json", '{"min_severity": "high"}')
    _, d = _scan_json(tmp_path, capsys)
    assert d["findings"] == []


def test_cli_flag_overrides_config(tmp_path, capsys):
    # 설정은 disable 하지만 별도 플래그 없이도 동작 확인: disable 비우면 발견됨
    _write(tmp_path, "v.py", "ctx = ssl._create_unverified_context()\n")
    _write(tmp_path, ".vibeguard.json", "{}")
    _, d = _scan_json(tmp_path, capsys)
    assert any(f["rule_id"] == "VG-WEB-009" for f in d["findings"])
