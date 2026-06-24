"""스캔 결과를 사람이 읽기 쉬운 형태로 출력.

- terminal: 색상(옵션) 입힌 콘솔 리포트. 바이브코더가 흐름을 끊지 않고 바로 이해.
- json:     CI/에디터 연동용 기계 판독 형식.
- markdown: PR/이슈/문서 첨부용.
"""

from __future__ import annotations

import html
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


# 심각도 -> SARIF level / GitHub code scanning security-severity
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "1.0",
}


def _sarif_uri(path: str) -> str:
    """파일 경로를 SARIF 용 상대 URI(슬래시)로 정규화."""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


class SarifReporter:
    """SARIF 2.1.0 출력. GitHub code scanning, VS Code SARIF Viewer 등과 연동된다."""

    SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

    def render(self, result: ScanResult) -> str:
        from . import __version__

        findings = result.sorted_findings()
        rules: dict = {}
        for f in findings:
            if f.rule_id in rules:
                continue
            rule = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.title},
                "properties": {
                    "category": f.category,
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "tags": ["security"],
                },
            }
            if f.cwe:
                num = "".join(ch for ch in f.cwe if ch.isdigit())
                if num:
                    rule["helpUri"] = f"https://cwe.mitre.org/data/definitions/{num}.html"
                    rule["properties"]["tags"].append(f"external/cwe/cwe-{num}")
            rules[f.rule_id] = rule

        results = []
        for f in findings:
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _SARIF_LEVEL[f.severity],
                    "message": {"text": f"{f.title} — {f.explanation} (해결: {f.fix})"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _sarif_uri(f.file)},
                                "region": {
                                    "startLine": max(1, f.line),
                                    "startColumn": max(1, f.column or 1),
                                },
                            }
                        }
                    ],
                    "properties": {"severity": f.severity.name, "cwe": f.cwe or ""},
                }
            )

        sarif = {
            "$schema": self.SCHEMA,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VibeGuard",
                            "informationUri": "https://github.com/nohseongmin/VibeGuard",
                            "version": __version__,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(sarif, ensure_ascii=False, indent=2)


_SEV_COLOR = {
    Severity.CRITICAL: "#e5484d",
    Severity.HIGH: "#f76808",
    Severity.MEDIUM: "#ffb224",
    Severity.LOW: "#4593e6",
    Severity.INFO: "#8b949e",
}


def _grade_color(grade: str) -> str:
    if grade in ("A", "B"):
        return "#3fb950"
    if grade in ("C", "D"):
        return "#ffb224"
    return "#e5484d"


_HTML_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0b0f15;color:#e6edf3;line-height:1.55;
font-family:'Malgun Gothic',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.logo{width:40px;height:40px;border-radius:11px;background:#15351f;color:#3fb950;
display:flex;align-items:center;justify-content:center;font-size:22px}
h1{font-size:21px;margin:0}.sub{color:#94a3b2;font-size:13px;margin-top:2px}
.summary{display:flex;gap:18px;align-items:center;flex-wrap:wrap;background:#141b24;
border:1px solid #27313d;border-radius:16px;padding:18px;margin-bottom:18px}
.ring{width:96px;height:96px;border-radius:50%;border:8px solid #888;display:flex;
flex-direction:column;align-items:center;justify-content:center;flex:0 0 auto}
.score{font-size:26px;font-weight:700;line-height:1}.of{font-size:11px;color:#94a3b2}
.grade{display:inline-block;font-weight:700;font-size:14px;padding:2px 12px;border-radius:999px;color:#0b0f15}
.verdict{margin-top:8px;font-size:15px}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.chip{display:inline-flex;align-items:center;gap:7px;background:#1b2531;border:1px solid #27313d;
border-radius:999px;padding:6px 13px;font-size:13px}
.dot{width:9px;height:9px;border-radius:50%}
.cards{display:flex;flex-direction:column;gap:12px}
.card{background:#141b24;border:1px solid #27313d;border-left:4px solid #888;border-radius:8px;padding:14px 16px}
.top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:11.5px;font-weight:700;padding:3px 9px;border-radius:6px;color:#0b0f15}
.ttl{font-weight:700;font-size:15px}
.rid{font-family:Consolas,monospace;font-size:11.5px;color:#94a3b2;background:#1b2531;
border:1px solid #27313d;padding:2px 7px;border-radius:6px}
.slop{font-size:11px;font-weight:700;color:#2a1a4a;background:#c8a2ff;padding:2px 8px;border-radius:6px}
.loc{color:#94a3b2;font-size:12.5px;font-family:Consolas,monospace;margin:8px 0 0}
pre.snip{margin:8px 0;background:#0d141d;border:1px solid #27313d;border-radius:8px;padding:9px 12px;
overflow:auto;font-family:Consolas,monospace;font-size:12.5px;color:#d6dee7;white-space:pre-wrap;word-break:break-all}
.row{margin-top:7px;font-size:13.5px}.row .k{color:#94a3b2;margin-right:6px}
.row a{color:#6cb6ff}.empty{text-align:center;padding:50px;color:#94a3b2}
footer{margin-top:22px;color:#94a3b2;font-size:12px}
"""


class HtmlReporter:
    """단독 HTML 리포트. 브라우저로 열거나 PR/이슈에 첨부할 수 있다(외부 의존성 없음)."""

    def render(self, result: ScanResult) -> str:
        findings = result.sorted_findings()
        sc, gr, vd = _score.summary(findings)
        counts = result.by_severity()
        esc = html.escape
        gc = _grade_color(gr)
        p: List[str] = []
        p.append("<!DOCTYPE html>")
        p.append('<html lang="ko"><head><meta charset="utf-8">')
        p.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
        p.append("<title>VibeGuard 보안 리포트</title>")
        p.append("<style>" + _HTML_CSS + "</style></head><body><div class=\"wrap\">")
        p.append(
            '<header><div class="logo">\U0001f6e1️</div><div>'
            "<h1>VibeGuard 보안 리포트</h1>"
            f'<div class="sub">스캔한 파일 {result.files_scanned}개 · 발견 {len(findings)}건</div>'
            "</div></header>"
        )
        p.append('<section class="summary">')
        p.append(f'<div class="ring" style="border-color:{gc}"><div class="score">{sc}</div><div class="of">/100</div></div>')
        p.append('<div class="sumtext">')
        p.append(f'<span class="grade" style="background:{gc}">등급 {esc(gr)}</span>')
        p.append(f'<div class="verdict">{esc(vd)}</div>')
        p.append('<div class="chips">')
        for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
            p.append(
                f'<span class="chip"><span class="dot" style="background:{_SEV_COLOR[s]}"></span>'
                f'{esc(s.label)} <b>{counts[s]}</b></span>'
            )
        p.append("</div></div></section>")
        if not findings:
            p.append('<div class="empty">발견된 문제가 없습니다. 안전합니다!</div>')
        else:
            p.append('<section class="cards">')
            for f in findings:
                col = _SEV_COLOR[f.severity]
                slop = ""
                if "SLOP" in f.rule_id or f.category == "supply-chain":
                    slop = ' <span class="slop">공급망/슬롭스쿼팅</span>'
                col_str = f":{f.column}" if f.column else ""
                cwe_html = ""
                if f.cwe:
                    num = "".join(ch for ch in f.cwe if ch.isdigit())
                    cwe_html = (
                        f'<div class="row"><span class="k">참고</span>'
                        f'<a href="https://cwe.mitre.org/data/definitions/{num}.html" '
                        f'target="_blank" rel="noopener">{esc(f.cwe)}</a></div>'
                    )
                p.append(
                    f'<div class="card" style="border-left-color:{col}">'
                    f'<div class="top"><span class="badge" style="background:{col}">{esc(f.severity.label)}</span>'
                    f'<span class="ttl">{esc(f.title)}</span><span class="rid">{esc(f.rule_id)}</span>{slop}</div>'
                    f'<div class="loc">{esc(f.file)}:{f.line}{col_str}</div>'
                    f'<pre class="snip">{esc(f.snippet)}</pre>'
                    f'<div class="row"><span class="k">설명</span>{esc(f.explanation)}</div>'
                    f'<div class="row"><span class="k">해결</span>{esc(f.fix)}</div>'
                    f"{cwe_html}</div>"
                )
            p.append("</section>")
        p.append(
            '<footer>VibeGuard · 런타임 외부 의존성 0 (Python 표준 라이브러리만 사용) · '
            "github.com/nohseongmin/VibeGuard</footer>"
        )
        p.append("</div></body></html>")
        return "\n".join(p)


def get_reporter(fmt: str):
    fmt = (fmt or "terminal").lower()
    if fmt == "json":
        return JsonReporter()
    if fmt in ("md", "markdown"):
        return MarkdownReporter()
    if fmt == "sarif":
        return SarifReporter()
    if fmt == "html":
        return HtmlReporter()
    return TerminalReporter()
