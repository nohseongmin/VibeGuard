"""탐지 결과(Finding)와 심각도(Severity) 데이터 모델."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Optional


class Severity(enum.IntEnum):
    """취약점 심각도. 숫자가 클수록 위험하며 점수 계산과 정렬에 사용된다."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "정보",
            Severity.LOW: "낮음",
            Severity.MEDIUM: "중간",
            Severity.HIGH: "높음",
            Severity.CRITICAL: "치명적",
        }[self]

    @property
    def weight(self) -> int:
        """보안 점수 차감 가중치."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 6,
            Severity.HIGH: 15,
            Severity.CRITICAL: 30,
        }[self]

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


@dataclass
class Finding:
    """탐지된 취약점 1건.

    Attributes:
        rule_id:    규칙 식별자 (예: "VG-SECRET-001")
        title:      한 줄 제목
        severity:   심각도
        category:   분류 (secrets / dangerous / injection / web / crypto / supply-chain)
        file:       대상 파일 경로
        line:       라인 번호 (1-base)
        snippet:    문제가 된 코드 한 줄
        explanation: 비전문가용 평이한 설명 (왜 위험한지)
        fix:        수정 가이드 (어떻게 고치는지)
        cwe:        관련 CWE 번호 (예: "CWE-798")
    """

    rule_id: str
    title: str
    severity: Severity
    category: str
    file: str
    line: int
    snippet: str
    explanation: str
    fix: str
    cwe: Optional[str] = None
    column: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        d["severity_label"] = self.severity.label
        return d

    def location(self) -> str:
        return f"{self.file}:{self.line}"

    def __lt__(self, other: "Finding") -> bool:
        # 심각도 내림차순 -> 파일 -> 라인 순으로 정렬되도록
        return (-self.severity, self.file, self.line) < (
            -other.severity,
            other.file,
            other.line,
        )
