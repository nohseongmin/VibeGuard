"""VibeGuard 명령행 인터페이스.

사용 예:
  vibeguard scan .                 현재 폴더 스캔
  vibeguard scan app.py --format json
  vibeguard scan . --offline       레지스트리 조회 없이(오프라인)
  vibeguard scan . --fail-on high  high 이상 발견 시 종료코드 1 (CI/훅용)
  vibeguard rules                  탑재된 규칙 목록
  vibeguard init-hooks             git pre-commit 훅 설치
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from . import __version__
from .finding import Finding, Severity
from .reporter import get_reporter
from .scanner import Scanner, ScanResult
from .slopsquat import check_project


def _ensure_utf8_output() -> None:
    """비 UTF-8 콘솔(예: Windows cp949)에서도 한글 출력이 깨지지 않도록 고정한다."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass


def _run_scan(args) -> int:
    scanner = Scanner()
    result: ScanResult = scanner.scan(args.path)

    # 슬롭스쿼팅/오타스쿼팅 검사(옵션)
    if not args.no_deps:
        dep_findings: List[Finding] = check_project(
            args.path, offline=args.offline, timeout=args.timeout
        )
        result.findings.extend(dep_findings)

    # 최소 심각도 필터
    if args.min_severity:
        floor = Severity.from_name(args.min_severity)
        result.findings = [f for f in result.findings if f.severity >= floor]

    reporter = get_reporter(args.format)
    if args.format == "terminal" and args.no_color:
        from .reporter import TerminalReporter

        reporter = TerminalReporter(use_color=False)

    output = reporter.render(result)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"리포트를 저장했습니다: {args.output}")
    else:
        print(output)

    # 종료 코드 결정
    if args.fail_on:
        threshold = Severity.from_name(args.fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def _run_rules(args) -> int:
    from .rules import all_rules

    rules = sorted(all_rules(), key=lambda r: r.rule_id)
    print(f"탑재된 규칙: {len(rules)}개 (+ 공급망 검사 VG-SLOP-001/002)\n")
    cur = None
    for r in rules:
        if r.category != cur:
            cur = r.category
            print(f"[{cur}]")
        print(f"  {r.rule_id}  ({r.severity.label})  {r.title}")
    print("  VG-SLOP-001  (높음)  레지스트리에 없는 패키지(슬롭스쿼팅)")
    print("  VG-SLOP-002  (중간)  유명 패키지 오타스쿼팅 후보")
    return 0


def _run_init_hooks(args) -> int:
    from .hooks import install_git_hook, claude_hook_snippet

    ok, msg = install_git_hook(args.path)
    print(msg)
    print()
    print("Claude Code / AI 에이전트 연동(선택):")
    print(claude_hook_snippet(args.path))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibeguard",
        description="바이브코딩을 위한 보안 가드레일 - AI 생성 코드의 취약점을 잡아냅니다.",
    )
    p.add_argument("--version", action="version", version=f"vibeguard {__version__}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="파일/폴더를 스캔")
    sp.add_argument("path", nargs="?", default=".", help="스캔할 경로(기본: 현재 폴더)")
    sp.add_argument("--format", "-f", default="terminal", choices=["terminal", "json", "md", "markdown"])
    sp.add_argument("--output", "-o", help="결과를 파일로 저장")
    sp.add_argument("--no-color", action="store_true", help="색상 출력 끄기")
    sp.add_argument("--no-deps", action="store_true", help="의존성(슬롭스쿼팅) 검사 생략")
    sp.add_argument("--offline", action="store_true", help="레지스트리 조회 없이 로컬 휴리스틱만")
    sp.add_argument("--timeout", type=float, default=4.0, help="레지스트리 조회 타임아웃(초)")
    sp.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], help="이 심각도 미만은 숨김")
    sp.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], help="이 심각도 이상 발견 시 종료코드 1")
    sp.set_defaults(func=_run_scan)

    rp = sub.add_parser("rules", help="탑재된 규칙 목록 보기")
    rp.set_defaults(func=_run_rules)

    hp = sub.add_parser("init-hooks", help="git pre-commit 훅 설치")
    hp.add_argument("path", nargs="?", default=".", help="git 저장소 경로(기본: 현재 폴더)")
    hp.set_defaults(func=_run_init_hooks)

    return p


def main(argv=None) -> int:
    _ensure_utf8_output()
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # 인자 없이 실행하면 현재 폴더 스캔
        args = parser.parse_args(["scan", "."])
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\n중단되었습니다.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
