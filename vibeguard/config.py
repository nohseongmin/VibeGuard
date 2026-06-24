"""선택적 설정 파일(.vibeguard.json) 로딩.

스캔 대상(또는 현재 폴더)에서 .vibeguard.json 을 찾아 기본값을 제공한다.
의존성을 늘리지 않도록 TOML 이 아닌 표준 라이브러리 json 을 사용한다.

지원 키:
  exclude:       추가로 제외할 경로 조각(부분 문자열) 목록  예: ["tests/", "vendor/"]
  disable:       비활성화할 규칙 ID 목록                  예: ["VG-WEB-006"]
  min_severity:  이 미만 심각도는 숨김                     예: "low"
  fail_on:       이 이상 발견 시 종료코드 1                예: "high"

CLI 플래그가 설정 파일보다 우선한다.
"""

from __future__ import annotations

import json
import os
from typing import Optional

CONFIG_NAME = ".vibeguard.json"


def find_config(path: str) -> Optional[str]:
    """스캔 경로의 폴더와 현재 작업 폴더에서 설정 파일을 찾는다."""
    if os.path.isdir(path):
        base = path
    else:
        base = os.path.dirname(os.path.abspath(path))
    candidates = [
        os.path.join(base, CONFIG_NAME),
        os.path.join(os.getcwd(), CONFIG_NAME),
    ]
    for cand in candidates:
        if os.path.isfile(cand):
            return cand
    return None


def load_config(path: str) -> dict:
    """설정 파일을 읽어 dict 로 반환한다. 없거나 오류면 빈 dict."""
    cfg_path = find_config(path)
    if not cfg_path:
        return {}
    try:
        with open(cfg_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}
