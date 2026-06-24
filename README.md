# VibeGuard

바이브코딩(vibe coding)을 위한 보안 가드레일.

AI 코딩 어시스턴트(Cursor, Claude Code, GitHub Copilot, v0, Bolt, Lovable 등)가 생성한 코드를 사람이 깊게 검토하지 않고 그대로 배포하는 흐름을 "바이브코딩"이라고 부릅니다. 빠르지만, 보안 결함이 그대로 섞여 들어갑니다. VibeGuard는 그 코드를 정적 분석으로 점검하고, 비보안 전문가도 이해할 수 있는 언어로 "무엇이, 왜 위험하고, 어떻게 고치는지"를 알려주는 오픈소스 명령행 도구입니다.

런타임 의존성이 없습니다(파이썬 표준 라이브러리만 사용). 보안 도구 스스로가 공급망 위험을 만들지 않도록 한 설계입니다.

## 왜 필요한가

AI가 생성한 코드의 보안 문제는 일화가 아니라 측정된 현상입니다.

- AI 생성 코드의 약 45%가 보안 취약점을 포함한다는 분석이 있습니다(Veracode, 2025).
- "바이브" 방식으로 다섯 번 다듬으면 초기 버전보다 치명적 취약점이 약 37% 더 늘어난다는 보고가 있습니다.
- AI가 만든 코드의 약 20%가 실제로 존재하지 않는 패키지를 참조하며, 공격자가 그 이름을 미리 선점해 악성코드를 심는 "슬롭스쿼팅(slopsquatting)" 공격으로 이어집니다.

바이브코더는 대체로 보안 전문가가 아닙니다. 따라서 도구는 빠르고, 흐름을 끊지 않고, 평이한 말로 설명해야 합니다. VibeGuard는 그 지점을 노립니다.

## 주요 기능

- 정적 분석으로 AI 코드 특유의 취약 패턴 탐지(시크릿, 위험한 실행, 인젝션, 웹 설정 결함, 약한 암호화).
- 슬롭스쿼팅/오타스쿼팅 탐지: import·의존성을 실제 레지스트리(PyPI/npm)와 대조하고, 유명 패키지와 철자가 비슷한 가짜 후보를 찾아냅니다.
- 비전문가용 설명: 각 발견 항목마다 "설명(왜 위험한가)"과 "해결(어떻게 고치는가)"을 한국어로 제공합니다.
- 바이브 보안 점수(0~100)와 A~F 등급으로 한눈에 상태를 보여줍니다.
- 바이브코딩 루프에 자동 결합: git pre-commit 훅, Claude Code 등 AI 에이전트용 PostToolUse 훅 설치를 지원합니다.
- 출력 형식: 터미널, JSON(CI/에디터 연동), Markdown(PR/이슈 첨부).

## 설치

```
git clone https://github.com/nohseongmin/VibeGuard
cd VibeGuard
pip install -e .
```

또는 설치 없이 바로 실행할 수 있습니다.

```
python -m vibeguard scan .
```

## 사용법

```
vibeguard scan .                  현재 폴더 스캔
vibeguard scan app.py             단일 파일 스캔
vibeguard scan . --format json    JSON 출력(CI/에디터 연동)
vibeguard scan . --format md -o report.md   Markdown 리포트 저장
vibeguard scan . --offline        레지스트리 조회 없이(오프라인) 스캔
vibeguard scan . --fail-on high   high 이상 발견 시 종료코드 1 (CI/훅용)
vibeguard scan . --format sarif -o out.sarif   SARIF 출력(GitHub 코드 스캐닝/VS Code)
vibeguard rules                   탑재된 규칙 목록 보기
vibeguard init-hooks              git pre-commit 훅 설치
vibeguard gui                     브라우저 기반 GUI 실행(로컬 서버)
```

## GUI (브라우저)

터미널이 익숙하지 않아도 쓸 수 있도록, 외부 프레임워크 없이 표준 라이브러리만으로 동작하는 로컬 웹 GUI를 제공합니다.

```
vibeguard gui            # http://127.0.0.1:8000 에서 GUI 실행(브라우저 자동 열림)
vibeguard gui --port 8080
```

경로를 입력하고 스캔하면 보안 점수 링, 심각도별 칩 필터, 취약점 카드(위치·코드·설명·해결책·CWE), 슬롭스쿼팅 강조 태그를 한눈에 볼 수 있습니다. 로컬호스트(127.0.0.1)에만 바인딩하며 외부 의존성은 없습니다.

## CI 연동 (GitHub Actions)

`vibeguard scan . --format sarif` 로 SARIF 2.1.0 리포트를 만들면 GitHub 코드 스캐닝(Security 탭)이나 VS Code SARIF Viewer에서 결과를 확인할 수 있습니다. 저장소의 [.github/workflows/vibeguard.yml](.github/workflows/vibeguard.yml) 이 예시 워크플로입니다 — 푸시/PR마다 스캔해 SARIF를 업로드하고, 제품 코드에서 medium 이상이 나오면 빌드를 실패시킵니다.

참고: VibeGuard는 자기 자신의 코드(`vibeguard/`)를 스캔해도 발견 0건입니다(규칙 정의 라인은 `# vibeguard: ignore` 로 표시).

## 예시 출력

데모 앱(`examples/vibe_coded_app`)을 스캔하면 다음과 같은 결과가 나옵니다(요약).

```
  VibeGuard   바이브코딩 보안 점검 결과

 치명적  OpenAI API 키가 코드에 하드코딩됨  [VG-SECRET-001]
   위치: examples/vibe_coded_app/app.py:25 (col 18)
   코드: OPENAI_API_KEY = "sk-...redacted..."
   설명: OpenAI 형식의 비밀 API 키가 소스코드에 직접 들어 있습니다. 저장소가 공개되면 즉시 도용됩니다.
   해결: 코드에서 값을 제거하고 환경변수(.env)나 비밀관리 서비스로 옮기세요...
   참고: CWE-798

 치명적  f-string 으로 SQL 쿼리를 조립  [VG-SQLI-001]
   ...

  요약
   치명적 3  높음 6  중간 2  낮음 1
   스캔한 파일: 2개, 발견: 12건
   보안 점수: 0/100 (등급 F)  [--------------------]
   치명적 문제가 있습니다. 배포 전에 반드시 고치세요.
```

## 탐지 범위

| 분류 | 대표 규칙 | 예시 |
| --- | --- | --- |
| 시크릿(secrets) | VG-SECRET-001~010 | OpenAI/Anthropic/AWS/GitHub/Stripe 키, 개인키, 평문 비밀번호, DB URL 내 비밀번호 |
| 위험한 실행(dangerous) | VG-EXEC-001~008 | eval/exec, shell=True, os.system 포매팅, pickle, yaml.load, new Function, child_process, 압축 해제 zip-slip |
| 인젝션(injection) | VG-SQLI-001~004, VG-SSTI-001 | f-string/템플릿/문자열결합 SQL, MongoDB $where, Flask 템플릿 인젝션(SSTI) |
| 웹 설정(web) | VG-WEB-001~009 | debug=True, 전체 허용 CORS, TLS/SSL 검증 비활성화, innerHTML/dangerouslySetInnerHTML |
| 약한 암호화(crypto) | VG-CRYPTO-001~006 | MD5/SHA1, random 토큰, Math.random, DES/ECB, JWT 서명검증 비활성화/none |
| 공급망(supply-chain) | VG-SLOP-001~002 | 레지스트리에 없는 환각 패키지, 유명 패키지 오타스쿼팅 |

지원 언어: Python, JavaScript/TypeScript(.js/.jsx/.ts/.tsx). 시크릿 규칙은 모든 텍스트 파일에 적용됩니다.

## 슬롭스쿼팅이란

AI는 그럴듯하지만 존재하지 않는 패키지 이름을 만들어냅니다(예: `flask-easy-auth`). 공격자는 이런 이름을 미리 레지스트리에 올려 두고, 개발자가 의심 없이 `pip install` 하기를 기다립니다. VibeGuard는 코드의 import와 requirements.txt/package.json의 의존성을 모아 실제 레지스트리에 존재하는지 확인하고, 유명 패키지와 편집거리 1~2인 오타 후보도 함께 경고합니다. 네트워크가 없으면 `--offline`으로 오타 휴리스틱만 수행합니다.

## 오탐 줄이기

- 특정 줄을 무시하려면 줄 끝에 주석을 답니다: `eval(x)  # vibeguard: ignore`
- `your-api-key`, `example`, `xxxx` 같은 placeholder 값은 시크릿 규칙에서 자동 제외됩니다.
- `node_modules`, `.venv`, `dist` 등 산출물 디렉터리는 스캔에서 제외됩니다.

## 바이브코딩 루프에 결합

git pre-commit 훅:

```
vibeguard init-hooks
```

커밋 직전 자동으로 스캔하고 high 이상이면 커밋을 막습니다(우회: `git commit --no-verify`).

Claude Code 등 AI 에이전트와 결합하면, AI가 파일을 수정한 직후 자동으로 점검되어 에이전트가 결과를 보고 스스로 교정할 수 있습니다(`vibeguard init-hooks` 실행 시 설정 예시를 출력).

## 개발/테스트

```
pip install -e ".[dev]"
pytest
```

## 한계와 다음 단계

- 현재는 정규식·휴리스틱 기반의 라인 단위 분석입니다. 데이터 흐름 분석(taint analysis)은 포함하지 않습니다.
- 로드맵: AST 기반 분석으로 오탐 감소, 더 많은 언어, 자동 수정(quick-fix), VS Code 확장, 규칙 플러그인 API.

## 라이선스

MIT License. 자세한 내용은 [LICENSE](LICENSE)를 참고하세요.
