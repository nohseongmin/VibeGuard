"""훅 설치 유틸리티.

VibeGuard 의 핵심 가치는 '바이브코딩 루프 안에서 자동으로' 돌아가는 것이다.
- git pre-commit 훅: 커밋 직전 스테이징된 변경을 스캔.
- Claude Code 훅: AI 가 파일을 수정한 직후 스캔(에이전트가 결과를 보고 스스로 교정 가능).
"""

from __future__ import annotations

import os
import stat
from typing import Tuple

# git pre-commit 훅 본문(POSIX sh; Git for Windows 의 bash 에서도 동작)
_PRE_COMMIT = """#!/bin/sh
# VibeGuard pre-commit hook - AI 생성 코드의 보안 문제를 커밋 전에 차단합니다.
# 우회가 필요하면: git commit --no-verify
echo "[VibeGuard] 보안 점검 중..."
python -m vibeguard scan . --fail-on high --no-color
status=$?
if [ $status -ne 0 ]; then
  echo ""
  echo "[VibeGuard] high 이상 보안 문제가 있어 커밋을 중단합니다."
  echo "            의도적으로 무시하려면: git commit --no-verify"
  exit 1
fi
exit 0
"""


def install_git_hook(repo_path: str) -> Tuple[bool, str]:
    git_dir = os.path.join(repo_path, ".git")
    if not os.path.isdir(git_dir):
        return False, f"git 저장소를 찾지 못했습니다: {os.path.abspath(repo_path)} (git init 후 다시 시도하세요)"

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_path = os.path.join(hooks_dir, "pre-commit")

    if os.path.exists(hook_path):
        with open(hook_path, "r", encoding="utf-8", errors="ignore") as fh:
            existing = fh.read()
        if "VibeGuard" not in existing:
            return (
                False,
                f"이미 pre-commit 훅이 존재합니다: {hook_path}\n"
                "기존 훅을 유지하기 위해 자동 설치를 중단했습니다. 수동으로 다음 줄을 추가하세요:\n"
                "  python -m vibeguard scan . --fail-on high",
            )

    with open(hook_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(_PRE_COMMIT)
    # 실행 권한 부여(POSIX). Windows 에서는 무해.
    try:
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass

    return True, f"git pre-commit 훅을 설치했습니다: {hook_path}"


def claude_hook_snippet(repo_path: str) -> str:
    """Claude Code 의 PostToolUse 훅 설정 예시(.claude/settings.json)."""
    return (
        '  // .claude/settings.json 에 추가하면 AI 가 파일을 수정한 직후 자동 점검됩니다.\n'
        '  {\n'
        '    "hooks": {\n'
        '      "PostToolUse": [\n'
        '        {\n'
        '          "matcher": "Edit|Write|MultiEdit",\n'
        '          "hooks": [\n'
        '            { "type": "command", "command": "python -m vibeguard scan . --offline --min-severity high --no-color" }\n'
        '          ]\n'
        '        }\n'
        '      ]\n'
        '    }\n'
        '  }'
    )
