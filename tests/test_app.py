"""데스크톱 앱의 순수 로직 테스트(창을 띄우지 않는 부분만).

tkinter 창을 실제로 여는 검증은 CI 에서 불안정하므로, 화면 없이 검증할 수 있는
경로 해석·표시 보조 함수만 테스트한다.
"""

import os

from vibeguard.app import _short, target_from_args


def test_target_from_args_prefers_joined_path(tmp_path):
    # "C:/My Code" 처럼 공백이 든 경로가 따옴표 없이 쪼개져 들어오는 경우
    folder = tmp_path / "My Code"
    folder.mkdir()
    parts = str(folder).split(" ")
    assert len(parts) > 1
    assert target_from_args(parts) == str(folder)


def test_target_from_args_single_path(tmp_path):
    assert target_from_args([str(tmp_path)]) == str(tmp_path)


def test_target_from_args_missing_and_empty(tmp_path):
    assert target_from_args([str(tmp_path / "nope")]) is None
    assert target_from_args([]) is None
    assert target_from_args(["", "  "]) is None


def test_target_from_args_picks_existing_among_flags(tmp_path):
    assert target_from_args(["--weird", str(tmp_path)]) == str(tmp_path)


def test_short_keeps_short_paths():
    assert _short("C:/a/b") == "C:/a/b"


def test_short_truncates_long_paths():
    long_path = "C:/" + ("x" * 200)
    out = _short(long_path, limit=40)
    assert len(out) == 40
    assert out.startswith("…")
    assert out.endswith(long_path[-39:])
