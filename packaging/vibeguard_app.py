"""VibeGuard 단독 실행 진입점 (exe 더블클릭 / 드래그&드롭용).

비개발자(바이브코더)가 터미널 없이 쓰도록 만든 진입점이다.
- 그냥 실행하면: 네이티브 앱 창이 뜬다(검사 실행 · 이전 검사 결과 · 설정).
- exe 아이콘에 폴더를 끌어다 놓으면: 앱이 뜨면서 그 폴더를 바로 검사한다.
- 앱 창에 폴더를 끌어다 놓아도 바로 검사한다.

PyInstaller 로 단일 실행파일(.exe/바이너리)로 패키징한다:
    pyinstaller --onefile --windowed --name VibeGuard packaging/vibeguard_app.py
"""

import os
import sys


def main() -> int:
    # 소스에서 바로 실행할 때도 패키지를 찾도록 저장소 루트를 경로에 넣는다
    if not getattr(sys, "frozen", False):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)

    from vibeguard.app import main as app_main

    return app_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
