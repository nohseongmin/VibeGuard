"""베이스라인 지원.

기존 코드베이스에 처음 도입할 때, 현재 발견을 '수용된 상태'로 저장해 두고
이후에는 새로 생긴 문제만 보고/차단할 수 있게 한다. 지문은 라인 번호와 무관해
코드가 위아래로 밀려도 동일 발견으로 인식된다.
"""

from __future__ import annotations

import json
from typing import Iterable, List, Set

from .finding import Finding


def write_baseline(path: str, findings: Iterable[Finding]) -> int:
    """현재 발견들의 지문을 베이스라인 파일로 저장하고 개수를 반환."""
    fingerprints = sorted({f.fingerprint() for f in findings})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            {"version": 1, "fingerprints": fingerprints},
            fh,
            ensure_ascii=False,
            indent=2,
        )
    return len(fingerprints)


def load_fingerprints(path: str) -> Set[str]:
    """베이스라인 파일에서 지문 집합을 읽어온다."""
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return set(data.get("fingerprints", []))


def filter_new(findings: List[Finding], known: Set[str]) -> List[Finding]:
    """베이스라인에 없는(새로 생긴) 발견만 남긴다."""
    return [f for f in findings if f.fingerprint() not in known]
