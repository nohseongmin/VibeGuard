# 변경 이력 (Changelog)

이 프로젝트의 주요 변경 사항을 기록합니다. 형식은 [Keep a Changelog](https://keepachangelog.com/)를 따릅니다.

## [Unreleased]

### 추가됨
- 알려진 취약점(CVE) 실시간 검사 (VG-CVE-001) — `requirements.txt`/`package.json`에 고정된 의존성 버전을 [OSV.dev](https://osv.dev)에 조회해, 그 버전에 공개된 CVE/GHSA와 수정 버전을 보고합니다.
  - 코드 패턴 규칙(SAST)이 놓치는 "취약한 라이브러리 사용(SCA)"을 보완합니다. 취약점 목록을 도구에 내장하지 않고 OSV에 실시간 조회하므로, 도구 업데이트 없이 항상 최신 CVE가 반영됩니다.
  - 호출은 표준 라이브러리(`urllib`)만 사용 — 런타임 의존성 0 유지. `--offline`이면 건너뜁니다. 네트워크 실패 시 스캔을 멈추지 않고 조용히 넘어갑니다.
- 락파일 지원 — `package-lock.json`(v1/v2/v3)·`Pipfile.lock`·`poetry.lock`에서 실제 설치된 정확한 버전을 읽어 CVE를 조회합니다. 같은 폴더에 락파일이 있으면 `package.json`(범위 추정) 대신 락파일을 우선합니다.
- `uvicorn[standard]==0.23.0` 같은 extras 표기 인식(이전에는 누락).
- GUI·HTML 리포트의 CVE 발견 항목에 "알려진 취약점(CVE)" 배지 표시.

- 데스크톱 앱(`vibeguard app`) — 표준 라이브러리 tkinter 로 만든 네이티브 창. 실행파일을 더블클릭하면 열린다.
  - 홈 화면에 버튼 셋: 검사 실행 · 이전 검사 결과 · 설정.
  - 검사 실행: 폴더를 창에 끌어다 놓으면(윈도우 네이티브 드래그앤드롭, ctypes 로 WM_DROPFILES 처리) 즉시 검사하고 결과를 같은 창 안에 표시. 드래그앤드롭이 안 되는 환경에서는 '폴더 선택' 버튼으로 대체된다.
  - 이전 검사 결과: 지난 검사를 최신순으로 나열하고, 클릭하면 그때 결과를 그대로 다시 연다.
  - 설정: 실시간 조회(가짜 패키지·CVE) 사용 여부, 표시할 최소 심각도, 제외할 폴더, 기록 보관 개수.
  - 설정과 기록은 사용자 폴더에 저장된다(Windows `%APPDATA%\VibeGuard`).
- 실행파일이 창 모드(`--windowed`)로 빌드되어 앱 뒤에 검은 콘솔 창이 뜨지 않는다.

### 개선됨
- 취약점 상세 조회를 병렬화(표준 라이브러리 `concurrent.futures`)해 CVE 검사 속도 개선.
- 앱에 폴더를 넘길 때 공백이 든 경로("C:/My Code")가 따옴표 없이 쪼개져 들어와도 올바른 폴더를 검사한다.
- 검사한 코드 파일이 하나도 없으면 '안전합니다' 대신 사실대로 알린다(빈 폴더를 만점으로 오해하지 않도록).

## [0.1.0] - 2026-06

최초 공개 릴리스.

### 추가됨
- 규칙 기반 정적 분석 엔진과 48개 보안 규칙
  - 시크릿(API 키·토큰·개인키·평문 비밀번호·DB URL), 위험한 실행(eval/exec·shell·pickle·yaml.load·zip-slip), 인젝션(SQL·NoSQL·SSTI), 웹 설정(debug·CORS·TLS/SSL 검증·0.0.0.0·XSS·오픈 리다이렉트), 약한 암호화(MD5/SHA1·약한 난수·DES/ECB·JWT), 다국어(Go·PHP)
- 슬롭스쿼팅/오타스쿼팅 탐지: PyPI/npm 레지스트리 대조 + 편집거리 휴리스틱
- 바이브 보안 점수(0~100)와 A~F 등급, 비전문가용 한국어 설명·해결 가이드
- 출력 형식: 터미널, JSON, Markdown, SARIF 2.1.0, 단독 HTML 리포트
- 브라우저 GUI(`vibeguard gui`) — 표준 라이브러리 http.server 기반, 127.0.0.1 바인딩
- CI 연동: GitHub Actions 예시 워크플로(SARIF 업로드), `--fail-on` 종료코드
- 베이스라인 모드(`--baseline`/`--write-baseline`) — 기존 코드 수용 후 새 문제만 보고
- 설정 파일(`.vibeguard.json`) — 규칙 비활성화·경로 제외·기본 심각도/실패 임계값
- `--diff` 모드 — git 변경 파일만 스캔(PR/CI용)
- git pre-commit 훅(`vibeguard init-hooks`)과 pre-commit 프레임워크 연동(`.pre-commit-hooks.yaml`)
- 오탐 억제: AST 기반 문자열-리터럴 필터(Python — 문자열·문서 안의 코드 패턴 제외), `# vibeguard: ignore` 주석, placeholder 자동 제외, 산출물 디렉터리 제외

### 특징
- 런타임 외부 의존성 0 (Python 표준 라이브러리만 사용)
- 지원 언어: Python, JavaScript/TypeScript, Go, PHP
- 도구 자체 코드 스캔 시 발견 0건, 단위 테스트 79개 통과

[Unreleased]: https://github.com/nohseongmin/VibeGuard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nohseongmin/VibeGuard/releases/tag/v0.1.0
