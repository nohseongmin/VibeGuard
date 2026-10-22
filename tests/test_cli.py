"""CLI 스캔 명령의 경로 검증 테스트."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard.cli import build_parser  # noqa: E402


def test_unscanned_ci_gate_and_baseline_fail(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    parser = build_parser()
    for flags in (["--fail-on", "high"], ["--write-baseline", str(baseline)]):
        args = parser.parse_args(["scan", str(tmp_path), "--no-deps", *flags])
        assert args.func(args) == 2
    assert not baseline.exists()


def test_diff_preserves_unscanned_status(tmp_path, monkeypatch, capsys):
    import json
    from vibeguard import gitdiff

    path = tmp_path / "app.html"
    path.write_text("<p>Hello</p>", encoding="utf-8")
    monkeypatch.setattr(gitdiff, "changed_files", lambda *_: [str(path)])
    args = build_parser().parse_args(["scan", str(tmp_path), "--diff", "--no-deps", "--format", "json"])
    assert args.func(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["score"] is None
    assert payload["files_scanned"] == 0
    assert payload["files_skipped"] == 0


def test_diff_ignores_unsupported_changes_when_code_was_scanned(tmp_path, monkeypatch, capsys):
    from vibeguard import gitdiff

    code = tmp_path / "clean.py"
    code.write_text("value = 1\n", encoding="utf-8")
    readme = tmp_path / "README.md"
    readme.write_text("Documentation", encoding="utf-8")
    monkeypatch.setattr(gitdiff, "changed_files", lambda *_: [str(code), str(readme)])
    args = build_parser().parse_args(["scan", str(tmp_path), "--diff", "--no-deps", "--fail-on", "high"])
    assert args.func(args) == 0


def test_scan_missing_path_fails_loudly(tmp_path, capsys):
    missing = str(tmp_path / "no-such-folder")
    args = build_parser().parse_args(["scan", missing, "--no-deps"])
    code = args.func(args)
    assert code == 1
    assert missing in capsys.readouterr().err


def test_scan_existing_empty_path_succeeds(tmp_path, capsys):
    args = build_parser().parse_args(["scan", str(tmp_path), "--no-deps"])
    code = args.func(args)
    assert code == 0
    assert "스캔한 파일: 0개" in capsys.readouterr().out


def test_scan_missing_baseline_fails_loudly(tmp_path, capsys):
    missing = str(tmp_path / "no-such-baseline.json")
    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--no-deps", "--baseline", missing]
    )
    code = args.func(args)
    assert code == 1
    assert missing in capsys.readouterr().err


@pytest.mark.parametrize("content", [
    b"{", b"[]", b"null", b"{}", b'{"fingerprints": null}',
    b'{"fingerprints": "abc"}', b'{"fingerprints": [123]}',
    b'{"fingerprints": [[]]}', b"\xff",
])
def test_scan_invalid_baseline_fails_loudly(tmp_path, capsys, content):
    baseline = tmp_path / "baseline.json"
    baseline.write_bytes(content)
    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--no-deps", "--baseline", str(baseline)]
    )
    assert args.func(args) == 1
    assert "베이스라인 파일을 읽을 수 없습니다" in capsys.readouterr().err


def test_scan_baseline_directory_fails_loudly(tmp_path, capsys):
    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--no-deps", "--baseline", str(tmp_path)]
    )
    assert args.func(args) == 1
    assert "베이스라인 파일을 읽을 수 없습니다" in capsys.readouterr().err


def test_scan_empty_baseline_succeeds(tmp_path, capsys):
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"version": 1, "fingerprints": []}', encoding="utf-8")
    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--no-deps", "--baseline", str(baseline)]
    )
    assert args.func(args) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("flags, config", [
    (["--min-severity", "critical", "--fail-on", "high"], {}),
    ([], {"min_severity": "critical", "fail_on": "high"}),
])
def test_hidden_findings_still_fail_scan(tmp_path, capsys, flags, config):
    import json

    (tmp_path / "app.py").write_text(
        "ctx = ssl._create_unverified_context()\n", encoding="utf-8"
    )
    (tmp_path / ".vibeguard.json").write_text(json.dumps(config), encoding="utf-8")
    args = build_parser().parse_args(
        ["scan", str(tmp_path), "--no-deps", "--format", "json", *flags]
    )
    assert args.func(args) == 1
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_baseline_findings_do_not_fail_scan_with_display_filter(tmp_path, capsys):
    (tmp_path / "app.py").write_text(
        "ctx = ssl._create_unverified_context()\n", encoding="utf-8"
    )
    baseline = tmp_path / "baseline.json"
    parser = build_parser()
    args = parser.parse_args(
        ["scan", str(tmp_path), "--no-deps", "--write-baseline", str(baseline)]
    )
    assert args.func(args) == 0
    capsys.readouterr()
    args = parser.parse_args(
        ["scan", str(tmp_path), "--no-deps", "--baseline", str(baseline),
         "--min-severity", "critical", "--fail-on", "high"]
    )
    assert args.func(args) == 0
