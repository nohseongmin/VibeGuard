@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "PYEXE="
where py >nul 2>nul && set "PYEXE=py"
if not defined PYEXE ( where python >nul 2>nul && set "PYEXE=python" )

if not defined PYEXE (
  echo.
  echo  Python이 설치되어 있지 않습니다.
  echo  https://www.python.org/downloads 에서 설치한 뒤 다시 실행하세요.
  echo  (또는 GitHub Releases에서 Python 없이 쓰는 VibeGuard 실행파일을 받으세요)
  echo.
  pause
  exit /b 1
)

if "%~1"=="" (
  echo VibeGuard GUI를 실행합니다. 브라우저가 자동으로 열립니다...
  %PYEXE% -m vibeguard gui
) else (
  echo "%~1" 폴더를 스캔합니다...
  %PYEXE% -m vibeguard scan "%~1" --format html -o "%TEMP%\vibeguard_report.html"
  start "" "%TEMP%\vibeguard_report.html"
)
