"""--diff 모드(git 변경 파일만 스캔) 테스트."""

import json
import os
import shutil
import subprocess

import pytest

from vibeguard import gitdiff
from vibeguard.cli import main

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git 미설치")


def _git(root, *args):
    subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, check=True)


def _init_repo(tmp_path):
    root = str(tmp_path)
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "tester")
    return root


@needs_git
def test_changed_files_lists_modified_and_new(tmp_path):
    root = _init_repo(tmp_path)
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    (tmp_path / "a.py").write_text("x = 2\n", encoding="utf-8")  # 수정
    (tmp_path / "b.py").write_text("y = 3\n", encoding="utf-8")  # 신규(추적 안 됨)
    names = {os.path.basename(f) for f in gitdiff.changed_files(root)}
    assert "a.py" in names
    assert "b.py" in names


def test_changed_files_graceful_without_repo(tmp_path):
    assert isinstance(gitdiff.changed_files(str(tmp_path)), list)


@pytest.mark.parametrize("command", ["diff", "ls-files"])
def test_changed_files_preserves_special_filenames(tmp_path, monkeypatch, command):
    names = ["보안 검사.py", " leading.py", 'quoted"file.py', "tab\tfile.py", "line\nbreak.py", "line\r\nbreak.py"]
    expected = [os.path.normpath(os.path.join(str(tmp_path), name)) for name in names]
    output = b"\0".join(os.fsencode(name) for name in names) + b"\0"

    def run(args, **kwargs):
        assert "-z" in args
        return subprocess.CompletedProcess(args, 0, stdout=output if command in args else b"")

    monkeypatch.setattr(gitdiff.subprocess, "run", run)
    monkeypatch.setattr(gitdiff.os.path, "isfile", lambda path: path in expected)
    assert gitdiff.changed_files(str(tmp_path)) == expected


@needs_git
def test_cli_diff_scans_only_changed(tmp_path, capsys):
    root = _init_repo(tmp_path)
    (tmp_path / "clean.py").write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    # 새 취약 파일(추적 안 됨)
    (tmp_path / "vuln.py").write_text("ctx = ssl._create_unverified_context()\n", encoding="utf-8")
    main(["scan", root, "--offline", "--diff", "--format", "json"])
    d = json.loads(capsys.readouterr().out)
    files = {f["file"] for f in d["findings"]}
    assert any("vuln.py" in f for f in files)


@needs_git
@pytest.mark.parametrize("diff_args", [["--diff"], ["--diff", "HEAD~0"]])
def test_cli_diff_scans_modified_files_in_subdirectory(tmp_path, capsys, diff_args):
    root = _init_repo(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    tracked = source / "tracked.py"
    tracked.write_text("x = 1\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "init")
    tracked.write_text("ctx = ssl._create_unverified_context()\n", encoding="utf-8")
    (source / "new.py").write_text("y = 2\n", encoding="utf-8")

    code = main([
        "scan", str(source), "--no-deps", *diff_args,
        "--format", "json", "--fail-on", "high",
    ])
    data = json.loads(capsys.readouterr().out)

    assert code == 1
    assert data["files_scanned"] == 2
    assert {f["file"] for f in data["findings"]} == {str(tracked)}
