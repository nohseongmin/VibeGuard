"""VibeGuard 명령행 인터페이스.

사용 예:
  vibeguard scan .                 현재 폴더 스캔
  vibeguard scan app.py --format json
  vibeguard scan . --offline       레지스트리 조회 없이(오프라인)
  vibeguard scan . --fail-on high  high 이상 발견 시 종료코드 1 (CI/훅용)
  vibeguard rules                  탑재된 규칙 목록
  vibeguard init-hooks             git pre-commit 훅 설치
  vibeguard gui                    브라우저 기반 GUI 실행(로컬 서버)
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
from .config import load_config


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
    if getattr(args, "diff", None):
        from .gitdiff import changed_files

        base = None if args.diff == "HEAD" else args.diff
        result = ScanResult()
        for fp in changed_files(args.path, base):
            result.findings.extend(scanner.scan_file(fp))
            result.files_scanned += 1
    else:
        result = scanner.scan(args.path)

    # 슬롭스쿼팅/오타스쿼팅 검사(옵션) — diff 모드에서는 변경 코드에 집중하므로 생략
    if not args.no_deps and not getattr(args, "diff", None):
        dep_findings: List[Finding] = check_project(
            args.path, offline=args.offline, timeout=args.timeout
        )
        result.findings.extend(dep_findings)

    # 설정 파일(.vibeguard.json): 규칙 비활성화 / 경로 제외 (CLI 플래그가 우선)
    cfg = load_config(args.path)
    disabled = set(cfg.get("disable", []))
    if disabled:
        result.findings = [f for f in result.findings if f.rule_id not in disabled]
    excludes = cfg.get("exclude", [])
    if excludes:
        result.findings = [
            f
            for f in result.findings
            if not any(x in f.file.replace("\\", "/") for x in excludes)
        ]

    # 베이스라인 기록 모드: 현재 발견을 저장하고 종료
    if getattr(args, "write_baseline", None):
        from .baseline import write_baseline

        n = write_baseline(args.write_baseline, result.findings)
        print(f"베이스라인을 저장했습니다: {args.write_baseline} ({n}건)")
        return 0

    # 베이스라인 비교: 기존(수용된) 발견은 숨기고 새로 생긴 것만 남김
    if getattr(args, "baseline", None):
        from .baseline import filter_new, load_fingerprints

        known = load_fingerprints(args.baseline)
        result.findings = filter_new(result.findings, known)

    # 최소 심각도 필터 (CLI > 설정 파일)
    min_sev = args.min_severity or cfg.get("min_severity")
    if min_sev:
        floor = Severity.from_name(min_sev)
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

    # 종료 코드 결정 (CLI > 설정 파일)
    fail_on = args.fail_on or cfg.get("fail_on")
    if fail_on:
        threshold = Severity.from_name(fail_on)
        if any(f.severity >= threshold for f in result.findings):
            return 1
    return 0


def _run_rules(args) -> int:
    from .rules import all_rules

    rules = sorted(all_rules(), key=lambda r: r.rule_id)
    print(f"탑재된 규칙: {len(rules)}개 (+ 공급망 검사 VG-SLOP, 취약점 검사 VG-CVE)\n")
    cur = None
    for r in rules:
        if r.category != cur:
            cur = r.category
            print(f"[{cur}]")
        print(f"  {r.rule_id}  ({r.severity.label})  {r.title}")
    print("[supply-chain]")
    print("  VG-SLOP-001  (높음)  레지스트리에 없는 패키지(슬롭스쿼팅)")
    print("  VG-SLOP-002  (중간)  유명 패키지 오타스쿼팅 후보")
    print("[vulnerable-dependency]")
    print("  VG-CVE-001   (동적)  의존성 버전의 알려진 취약점(CVE) — OSV.dev 실시간 조회")
    return 0


def _run_init_hooks(args) -> int:
    from .hooks import install_git_hook, claude_hook_snippet

    ok, msg = install_git_hook(args.path)
    print(msg)
    print()
    print("Claude Code / AI 에이전트 연동(선택):")
    print(claude_hook_snippet(args.path))
    return 0 if ok else 1


def _run_gui(args) -> int:
    from .server import serve

    return serve(host=args.host, port=args.port, open_browser=not args.no_browser)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vibeguard",
        description="바이브코딩을 위한 보안 가드레일 - AI 생성 코드의 취약점을 잡아냅니다.",
    )
    p.add_argument("--version", action="version", version=f"vibeguard {__version__}")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("scan", help="파일/폴더를 스캔")
    sp.add_argument("path", nargs="?", default=".", help="스캔할 경로(기본: 현재 폴더)")
    sp.add_argument("--format", "-f", default="terminal", choices=["terminal", "json", "md", "markdown", "sarif", "html"])
    sp.add_argument("--output", "-o", help="결과를 파일로 저장")
    sp.add_argument("--no-color", action="store_true", help="색상 출력 끄기")
    sp.add_argument("--no-deps", action="store_true", help="의존성(슬롭스쿼팅) 검사 생략")
    sp.add_argument("--offline", action="store_true", help="레지스트리 조회 없이 로컬 휴리스틱만")
    sp.add_argument("--timeout", type=float, default=4.0, help="레지스트리 조회 타임아웃(초)")
    sp.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"], help="이 심각도 미만은 숨김")
    sp.add_argument("--fail-on", choices=["info", "low", "medium", "high", "critical"], help="이 심각도 이상 발견 시 종료코드 1")
    sp.add_argument("--baseline", metavar="FILE", help="베이스라인에 있는 발견은 숨기고 새로 생긴 것만 보고")
    sp.add_argument("--write-baseline", metavar="FILE", help="현재 발견을 베이스라인으로 저장하고 종료(기존 코드 수용용)")
    sp.add_argument("--diff", nargs="?", const="HEAD", default=None, metavar="BASE",
                    help="git 변경 파일만 스캔(기본 HEAD 대비, BASE 지정 가능) — PR/CI용")
    sp.set_defaults(func=_run_scan)

    rp = sub.add_parser("rules", help="탑재된 규칙 목록 보기")
    rp.set_defaults(func=_run_rules)

    hp = sub.add_parser("init-hooks", help="git pre-commit 훅 설치")
    hp.add_argument("path", nargs="?", default=".", help="git 저장소 경로(기본: 현재 폴더)")
    hp.set_defaults(func=_run_init_hooks)

    gp = sub.add_parser("gui", help="브라우저 기반 GUI 실행(로컬 서버)")
    gp.add_argument("--port", type=int, default=8000, help="포트(기본: 8000)")
    gp.add_argument("--host", default="127.0.0.1", help="바인딩 호스트(기본: 127.0.0.1)")
    gp.add_argument("--no-browser", action="store_true", help="브라우저 자동 실행 안 함")
    gp.set_defaults(func=_run_gui)

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
