"""스캔 결과를 사람이 읽기 쉬운 형태로 출력.

- terminal: 색상(옵션) 입힌 콘솔 리포트. 바이브코더가 흐름을 끊지 않고 바로 이해.
- json:     CI/에디터 연동용 기계 판독 형식.
- markdown: PR/이슈/문서 첨부용.
"""

from __future__ import annotations

import json
import os
import sys
from typing import List

from .finding import Finding, Severity
from .scanner import ScanResult
from . import score as _score

# ANSI 색상 코드 (지원 안 되는 환경에서는 비활성화)
_COLORS = {
    Severity.CRITICAL: "\033[1;37;41m",  # 흰 글자 빨강 배경
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("VIBEGUARD_FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class TerminalReporter:
    def __init__(self, use_color: bool = None):
        self.color = _supports_color() if use_color is None else use_color

    def _c(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return f"{code}{text}{_RESET}"

    def render(self, result: ScanResult) -> str:
        findings = result.sorted_findings()
        out: List[str] = []
        out.append("")
        out.append(self._c("  VibeGuard  ", "\033[1;30;47m") + " 바이브코딩 보안 점검 결과")
        out.append("")

        if not findings:
            out.append(self._c("  문제를 발견하지 못했습니다. ", "\033[32m"))
            out.append(f"  스캔한 파일: {result.files_scanned}개")
            sc, gr, vd = _score.summary(findings)
            out.append(f"  보안 점수: {sc}/100 (등급 {gr})  {vd}")
            out.append("")
            return "\n".join(out)

        for f in findings:
            sev = self._c(f" {f.severity.label} ", _COLORS[f.severity])
            out.append(f"{sev} {self._c(f.title, _BOLD)}  [{f.rule_id}]")
            out.append(self._c(f"   위치: {f.location()} (col {f.column})", _DIM))
            out.append(f"   코드: {f.snippet}")
            out.append(f"   설명: {f.explanation}")
            out.append(self._c(f"   해결: {f.fix}", "\033[32m"))
            if f.cwe:
                out.append(self._c(f"   참고: {f.cwe}", _DIM))
            out.append("")

        # 요약
        counts = result.by_severity()
        sc, gr, vd = _score.summary(findings)
        out.append(self._c("  요약", _BOLD))
        out.append(
            "   "
            + "  ".join(
                f"{s.label} {counts[s]}"
                for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
                if counts[s]
            )
        )
        out.append(f"   스캔한 파일: {result.files_scanned}개, 발견: {len(findings)}건")
        bar = _score_bar(sc)
        out.append(f"   보안 점수: {sc}/100 (등급 {gr})  {bar}")
        out.append(f"   {vd}")
        out.append("")
        return "\n".join(out)


def _score_bar(score: int, width: int = 20) -> str:
    filled = round(score / 100 * width)
    return "[" + "#" * filled + "-" * (width - filled) + "]"


class JsonReporter:
    def render(self, result: ScanResult) -> str:
        findings = result.sorted_findings()
        sc, gr, vd = _score.summary(findings)
        payload = {
            "tool": "vibeguard",
            "score": sc,
            "grade": gr,
            "verdict": vd,
            "files_scanned": result.files_scanned,
            "summary": {s.name: c for s, c in result.by_severity().items()},
            "findings": [f.to_dict() for f in findings],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)


class MarkdownReporter:
    """PR/이슈/문서 첨부용. 의도적으로 굵게/색 등 장식 없이 평이한 표로 출력."""

    def render(self, result: ScanResult) -> str:
        findings = result.sorted_findings()
        sc, gr, vd = _score.summary(findings)
        lines: List[str] = []
        lines.append("# VibeGuard 보안 점검 리포트")
        lines.append("")
        lines.append(f"- 보안 점수: {sc}/100 (등급 {gr})")
        lines.append(f"- 총평: {vd}")
        lines.append(f"- 스캔한 파일: {result.files_scanned}개, 발견: {len(findings)}건")
        lines.append("")
        if not findings:
            lines.append("발견된 문제가 없습니다.")
            return "\n".join(lines)
        lines.append("| 심각도 | 규칙 | 위치 | 제목 |")
        lines.append("| --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f.severity.label} | {f.rule_id} | {f.location()} | {f.title} |"
            )
        lines.append("")
        lines.append("## 상세")
        lines.append("")
        for f in findings:
            lines.append(f"### [{f.rule_id}] {f.title} ({f.severity.label})")
            lines.append(f"- 위치: {f.location()}")
            lines.append(f"- 코드: `{f.snippet}`")
            lines.append(f"- 설명: {f.explanation}")
            lines.append(f"- 해결: {f.fix}")
            if f.cwe:
                lines.append(f"- 참고: {f.cwe}")
            lines.append("")
        return "\n".join(lines)


def get_reporter(fmt: str):
    fmt = (fmt or "terminal").lower()
    if fmt == "json":
        return JsonReporter()
    if fmt in ("md", "markdown"):
        return MarkdownReporter()
    return TerminalReporter()
