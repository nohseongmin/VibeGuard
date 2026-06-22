"""규칙(Rule) 추상화와 전역 레지스트리.

대부분의 규칙은 정규식 한 줄 매칭으로 표현되므로 RegexRule 로 간단히 정의한다.
오탐을 줄이기 위해 placeholder(예: your-api-key, xxxx, example) 필터와
주석/문자열 컨텍스트를 일부 고려한다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Pattern

from ..finding import Finding, Severity

# 전역 규칙 레지스트리
_REGISTRY: List["Rule"] = []


def register(rule: "Rule") -> "Rule":
    _REGISTRY.append(rule)
    return rule


def all_rules() -> List["Rule"]:
    return list(_REGISTRY)


# placeholder 로 보이는 값은 실제 비밀이 아닐 가능성이 높으므로 제외
_PLACEHOLDER = re.compile(
    r"(your[-_ ]?|example|placeholder|dummy|sample|changeme|<.*?>|xxxx|0000|\.\.\.|"
    r"insert[-_ ]?your|todo|fixme|redacted|test[-_]?key|fake)",
    re.IGNORECASE,
)


def looks_like_placeholder(value: str) -> bool:
    return bool(_PLACEHOLDER.search(value))


@dataclass
class Rule:
    """탐지 규칙의 공통 인터페이스."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    explanation: str
    fix: str
    cwe: Optional[str] = None
    # 적용할 파일 확장자 (None 이면 모든 텍스트 파일)
    extensions: Optional[frozenset] = None

    def applies_to(self, path: str) -> bool:
        if self.extensions is None:
            return True
        lowered = path.lower()
        return any(lowered.endswith(ext) for ext in self.extensions)

    def scan_line(self, line: str, lineno: int, path: str) -> Iterable[Finding]:
        raise NotImplementedError


@dataclass
class RegexRule(Rule):
    """정규식 기반 규칙. 한 줄 단위로 매칭한다."""

    pattern: Optional[Pattern] = None
    # 매칭 그룹 중 '비밀 값'에 해당하는 그룹 번호 (placeholder 검사 대상)
    secret_group: int = 0
    # 추가 검증: (match, line) -> bool. False 면 무시.
    validator: Optional[Callable[[re.Match, str], bool]] = None
    # placeholder 필터 적용 여부
    skip_placeholders: bool = False

    def scan_line(self, line: str, lineno: int, path: str) -> Iterable[Finding]:
        if self.pattern is None:
            return
        for m in self.pattern.finditer(line):
            if self.skip_placeholders:
                value = m.group(self.secret_group) if self.secret_group else m.group(0)
                if value and looks_like_placeholder(value):
                    continue
            if self.validator and not self.validator(m, line):
                continue
            yield Finding(
                rule_id=self.rule_id,
                title=self.title,
                severity=self.severity,
                category=self.category,
                file=path,
                line=lineno,
                snippet=line.strip()[:200],
                explanation=self.explanation,
                fix=self.fix,
                cwe=self.cwe,
                column=m.start() + 1,
            )


def make_regex_rule(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    pattern: str,
    explanation: str,
    fix: str,
    cwe: Optional[str] = None,
    extensions: Optional[Iterable[str]] = None,
    flags: int = 0,
    secret_group: int = 0,
    validator: Optional[Callable[[re.Match, str], bool]] = None,
    skip_placeholders: bool = False,
) -> RegexRule:
    """RegexRule 생성 + 레지스트리 등록 헬퍼."""
    rule = RegexRule(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category=category,
        explanation=explanation,
        fix=fix,
        cwe=cwe,
        extensions=frozenset(extensions) if extensions else None,
        pattern=re.compile(pattern, flags),
        secret_group=secret_group,
        validator=validator,
        skip_placeholders=skip_placeholders,
    )
    return register(rule)
