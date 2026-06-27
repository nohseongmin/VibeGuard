"""VibeGuard 단독 실행 진입점 (더블클릭 / 드래그&드롭용).

비개발자(바이브코더)가 터미널 없이 쓰도록 만든 진입점이다.
- 폴더를 끌어다 놓으면(인자로 폴더가 들어오면): 그 폴더를 스캔하고 HTML 리포트를 브라우저로 연다.
- 그냥 실행하면(인자 없음): 브라우저 GUI 서버를 띄운다.

PyInstaller 로 단일 실행파일(.exe/.app/바이너리)로 패키징한다:
    pyinstaller --onefile --name VibeGuard packaging/vibeguard_app.py
"""

import os
import sys
import tempfile
import webbrowser


def _scan_folder_to_html(path: str) -> str:
    from vibeguard.reporter import get_reporter
    from vibeguard.scanner import Scanner
    from vibeguard.slopsquat import check_project

    scanner = Scanner()
    result = scanner.scan(path)
    try:
        result.findings.extend(check_project(path, offline=False, timeout=4.0))
    except Exception:
        pass  # 네트워크 문제로 의존성 검사가 실패해도 코드 스캔 결과는 보여준다

    html = get_reporter("html").render(result)
    out = os.path.join(tempfile.gettempdir(), "vibeguard_report.html")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    try:
        webbrowser.open("file:///" + out.replace("\\", "/"))
    except Exception:
        pass
    return out


def main() -> int:
    # 윈도우 콘솔에서도 한글 메시지가 깨지지 않도록 출력 인코딩을 UTF-8로 고정
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8")
            except (ValueError, OSError):
                pass

    args = [a for a in sys.argv[1:] if a]
    folders = [a for a in args if os.path.isdir(a)]

    if folders:
        for folder in folders:
            out = _scan_folder_to_html(folder)
            print("VibeGuard 리포트를 열었습니다:", out)
        return 0

    # 인자가 없으면 브라우저 GUI 를 띄운다.
    from vibeguard.cli import main as cli_main

    return cli_main(["gui"])


if __name__ == "__main__":
    raise SystemExit(main())
