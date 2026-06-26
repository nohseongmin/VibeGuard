"""git 변경 파일 목록 (--diff 모드용).

PR/CI 에서 '바뀐 파일만' 빠르게 스캔하기 위한 보조 모듈.
git 이 없거나 저장소가 아니면 빈 목록을 반환해 안전하게 무시된다.
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Optional


def _run_git(root: str, args: List[str]) -> List[str]:
    try:
        proc = subprocess.run(
            ["git", "-C", root, *args],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0:
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def changed_files(path: str, base: Optional[str] = None) -> List[str]:
    """path 가 속한 git 저장소에서 변경·추가된 파일의 절대 경로 목록."""
    if os.path.isdir(path):
        root = path
    else:
        root = os.path.dirname(os.path.abspath(path)) or "."

    names = _run_git(root, ["diff", "--name-only", base or "HEAD"])
    names += _run_git(root, ["ls-files", "--others", "--exclude-standard"])

    out: List[str] = []
    seen = set()
    for n in names:
        p = os.path.normpath(os.path.join(root, n))
        if p not in seen and os.path.isfile(p):
            seen.add(p)
            out.append(p)
    return out
