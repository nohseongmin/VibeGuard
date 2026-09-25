"""CLI 스캔 명령의 경로 검증 테스트."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard.cli import build_parser  # noqa: E402


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
