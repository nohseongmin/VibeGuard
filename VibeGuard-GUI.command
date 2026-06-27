#!/bin/bash
# macOS/Linux 더블클릭 런처. 인자로 폴더를 주면 그 폴더를 스캔해 HTML 리포트를 연다.
cd "$(dirname "$0")" || exit 1

PY=python3
if ! command -v "$PY" >/dev/null 2>&1; then
  echo
  echo " Python3가 설치되어 있지 않습니다."
  echo " https://www.python.org/downloads 에서 설치한 뒤 다시 실행하세요."
  echo " (또는 GitHub Releases에서 Python 없이 쓰는 VibeGuard 실행파일을 받으세요)"
  echo
  read -r -p "엔터를 누르면 닫힙니다..."
  exit 1
fi

if [ -n "$1" ] && [ -d "$1" ]; then
  echo "$1 폴더를 스캔합니다..."
  "$PY" -m vibeguard scan "$1" --format html -o "/tmp/vibeguard_report.html"
  (command -v open >/dev/null && open "/tmp/vibeguard_report.html") || xdg-open "/tmp/vibeguard_report.html" 2>/dev/null
else
  echo "VibeGuard GUI를 실행합니다. 브라우저가 자동으로 열립니다..."
  "$PY" -m vibeguard gui
fi
