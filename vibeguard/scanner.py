"""파일/디렉터리를 순회하며 규칙을 적용하는 스캐너 엔진."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .finding import Finding, Severity
from .rules import all_rules

# 스캔에서 제외할 디렉터리(의존성·빌드·VCS 산출물)
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
        "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
        ".next", ".nuxt", "out", "target", "vendor", "site-packages",
        ".idea", ".vscode", "coverage", ".tox", "bower_components",
    }
)

# 스캔 대상 텍스트 소스 확장자
DEFAULT_INCLUDE_EXT = frozenset(
    {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".env", ".yaml", ".yml", ".json", ".rb", ".go", ".php",
        ".java", ".sh", ".cfg", ".ini", ".toml",
    }
)

# 라인 단위 비활성 주석: "# vibeguard: ignore" 또는 "// vibeguard: ignore"
_IGNORE_MARK = "vibeguard: ignore"

MAX_FILE_BYTES = 2_000_000  # 2MB 초과 파일은 건너뜀(미니파이/번들 가능성)
MAX_LINE_LEN = 4000  # 비정상적으로 긴 라인(미니파이)은 건너뜀

# AST 문자열-리터럴 필터를 적용할 '코드성' 분류 (시크릿/공급망은 문자열이 대상이라 제외)
_CODE_CATEGORIES = frozenset({"dangerous", "injection", "web", "crypto", "path"})

# 코드성 분류이지만 '문자열 안의 값'을 정당하게 탐지하는 규칙(예: 0.0.0.0 IP,
# JWT 의 verify_signature/none)은 문자열 필터에서 제외한다.
_STRING_OK_RULES = frozenset({"VG-WEB-006", "VG-CRYPTO-006"})


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    def by_severity(self) -> dict:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings)


class Scanner:
    """디렉터리/파일을 스캔해 Finding 목록을 만든다."""

    def __init__(
        self,
        include_ext: Optional[Iterable[str]] = None,
        skip_dirs: Optional[Iterable[str]] = None,
        rules=None,
    ):
        self.include_ext = frozenset(include_ext) if include_ext else DEFAULT_INCLUDE_EXT
        self.skip_dirs = frozenset(skip_dirs) if skip_dirs else DEFAULT_SKIP_DIRS
        self.rules = rules if rules is not None else all_rules()

    # ---- 파일 수집 --------------------------------------------------------
    def collect_files(self, root: str) -> List[str]:
        if os.path.isfile(root):
            return [root]
        files: List[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # 제외 디렉터리 가지치기
            dirnames[:] = [d for d in dirnames if d not in self.skip_dirs and not d.startswith(".")]
            for name in filenames:
                ext = os.path.splitext(name)[1].lower()
                # .env 처럼 확장자 자체가 이름인 경우도 포함
                if ext in self.include_ext or name.lower().startswith(".env"):
                    files.append(os.path.join(dirpath, name))
        return files

    # ---- 단일 파일 스캔 ---------------------------------------------------
    def scan_file(self, path: str) -> List[Finding]:
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                return []
        except OSError:
            return []

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except (OSError, UnicodeError):
            return []

        # 적용 가능한 규칙만 미리 추림
        applicable = [r for r in self.rules if r.applies_to(path)]
        if not applicable:
            return []

        findings: List[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > MAX_LINE_LEN:
                continue
            if _IGNORE_MARK in line:
                continue
            for rule in applicable:
                findings.extend(rule.scan_line(line, lineno, path))

        # AST 정밀도: .py 파일에서 문자열 리터럴 안의 코드성 매치(가짜 양성)를 제거
        if findings and path.lower().endswith(".py"):
            from .astscan import in_string_span, string_literal_spans

            spans = string_literal_spans(text)
            if spans:
                findings = [
                    f
                    for f in findings
                    if not (
                        f.category in _CODE_CATEGORIES
                        and f.rule_id not in _STRING_OK_RULES
                        and in_string_span(spans, f.line, f.column - 1)
                    )
                ]
        return findings

    # ---- 전체 스캔 --------------------------------------------------------
    def scan(self, root: str) -> ScanResult:
        result = ScanResult()
        for path in self.collect_files(root):
            file_findings = self.scan_file(path)
            if file_findings:
                result.findings.extend(file_findings)
            result.files_scanned += 1
        return result
