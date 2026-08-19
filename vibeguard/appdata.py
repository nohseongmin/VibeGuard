"""데스크톱 앱의 설정과 검사 기록 저장소.

설정과 지난 검사 결과를 사용자 폴더에 보관한다(윈도우는 %APPDATA% 아래 VibeGuard 폴더).
표준 라이브러리만 사용하며, 저장에 실패해도 검사 자체는 막지 않는다.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List

APP_NAME = "VibeGuard"

DEFAULT_SETTINGS: Dict[str, Any] = {
    "online_lookup": True,   # 슬롭스쿼팅·CVE 실시간 조회(끄면 오프라인 검사)
    "min_severity": "LOW",   # 결과에 표시할 최소 심각도
    "exclude": [],           # 추가로 건너뛸 폴더 이름
    "history_limit": 30,     # 보관할 검사 기록 개수
}

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def app_dir() -> str:
    """설정·기록을 두는 사용자 폴더(없으면 만든다)."""
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, APP_NAME) if os.environ.get("APPDATA") \
        else os.path.join(base, "." + APP_NAME.lower())
    os.makedirs(path, exist_ok=True)
    return path


def history_dir() -> str:
    path = os.path.join(app_dir(), "history")
    os.makedirs(path, exist_ok=True)
    return path


def _settings_file() -> str:
    return os.path.join(app_dir(), "settings.json")


def load_settings() -> Dict[str, Any]:
    """저장된 설정을 기본값 위에 덮어 읽는다(파일이 깨져도 기본값으로 동작)."""
    data = dict(DEFAULT_SETTINGS)
    try:
        with open(_settings_file(), "r", encoding="utf-8") as fh:
            saved = json.load(fh)
        if isinstance(saved, dict):
            for key in DEFAULT_SETTINGS:
                if key in saved:
                    data[key] = saved[key]
    except (OSError, ValueError):
        pass
    if data.get("min_severity") not in _SEV_ORDER:
        data["min_severity"] = DEFAULT_SETTINGS["min_severity"]
    if not isinstance(data.get("exclude"), list):
        data["exclude"] = []
    try:
        data["history_limit"] = max(1, min(500, int(data["history_limit"])))
    except (TypeError, ValueError):
        data["history_limit"] = DEFAULT_SETTINGS["history_limit"]
    data["online_lookup"] = bool(data.get("online_lookup", True))
    return data


def save_settings(settings: Dict[str, Any]) -> None:
    with open(_settings_file(), "w", encoding="utf-8") as fh:
        json.dump(settings, fh, ensure_ascii=False, indent=2)


def save_scan(payload: Dict[str, Any], limit: int = 30) -> str:
    """검사 결과를 기록으로 저장하고 보관 개수를 넘으면 오래된 것부터 지운다."""
    payload = dict(payload)
    payload["scanned_at"] = time.time()
    name = "scan-%s-%d.json" % (time.strftime("%Y%m%d-%H%M%S"), int(time.time() * 1000) % 1000)
    out = os.path.join(history_dir(), name)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    _trim(limit)
    return out


def _trim(limit: int) -> None:
    files = _history_files()
    for path in files[limit:]:
        try:
            os.remove(path)
        except OSError:
            pass


def _history_files() -> List[str]:
    """기록 파일 경로를 최신순으로 돌려준다."""
    directory = history_dir()
    try:
        names = [n for n in os.listdir(directory) if n.endswith(".json")]
    except OSError:
        return []
    paths = [os.path.join(directory, n) for n in names]
    paths.sort(key=lambda p: _mtime(p), reverse=True)
    return paths


def _mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def list_scans() -> List[Dict[str, Any]]:
    """지난 검사 목록(최신순). 각 항목은 목록 표시에 필요한 요약만 담는다."""
    out: List[Dict[str, Any]] = []
    for path in _history_files():
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        out.append({
            "file": path,
            "scanned_at": data.get("scanned_at") or _mtime(path),
            "path": data.get("path", ""),
            "score": data.get("score", 0),
            "grade": data.get("grade", "-"),
            "total": data.get("total", 0),
            "counts": data.get("counts", {}),
        })
    return out


def load_scan(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def clear_history() -> int:
    removed = 0
    for path in _history_files():
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    return removed
