"""'바이브 보안 점수(Vibe Security Score)' 계산.

비전문가가 직관적으로 이해하도록 0~100 점수와 A~F 등급, 한 줄 평을 제공한다.
"""

from __future__ import annotations

from typing import List, Tuple

from .finding import Finding, Severity


def compute_score(findings: List[Finding]) -> int:
    """100점에서 심각도 가중치를 차감. 0~100 범위로 제한."""
    penalty = sum(f.severity.weight for f in findings)
    return max(0, 100 - penalty)


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def verdict(score: int, findings: List[Finding]) -> str:
    has_critical = any(f.severity == Severity.CRITICAL for f in findings)
    if has_critical:
        return "치명적 문제가 있습니다. 배포 전에 반드시 고치세요."
    if score >= 90:
        return "양호합니다. 발견된 경고를 가볍게 확인하세요."
    if score >= 70:
        return "주의가 필요합니다. 표시된 항목을 점검하세요."
    return "위험합니다. 배포 전 다수 항목을 수정해야 합니다."


def summary(findings: List[Finding]) -> Tuple[int, str, str]:
    """(점수, 등급, 한 줄 평)."""
    s = compute_score(findings)
    return s, grade(s), verdict(s, findings)
