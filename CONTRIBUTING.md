# 기여 가이드 (Contributing)

VibeGuard에 기여해 주셔서 감사합니다. 이 문서는 규칙 추가·버그 수정·문서 개선을 위한 안내입니다.

## 개발 환경

```
git clone https://github.com/nohseongmin/VibeGuard
cd VibeGuard
pip install -e ".[dev]"
pytest          # 전체 테스트
```

런타임 외부 의존성은 두지 않습니다(표준 라이브러리만 사용). 보안 도구 자체가 공급망 위험을 만들지 않도록 한 원칙입니다. 개발/테스트 의존성(pytest)만 `[dev]`에 둡니다.

## 프로젝트 구조

```
vibeguard/
  finding.py     탐지 결과(Finding)·심각도(Severity) 모델
  scanner.py     파일 수집·라인 단위 규칙 적용
  rules/         규칙 정의 (secrets/dangerous/injection/web/crypto/golang/php ...)
  slopsquat.py   슬롭스쿼팅/오타스쿼팅 탐지
  score.py       0~100 점수·A~F 등급
  reporter.py    terminal/json/md/sarif/html 출력
  baseline.py    베이스라인(기존 발견 수용)
  config.py      .vibeguard.json 설정
  gitdiff.py     --diff(변경 파일만 스캔)
  server.py      브라우저 GUI(표준 라이브러리 http.server)
  cli.py         명령행 진입점
```

## 규칙 추가하기

대부분의 규칙은 정규식 한 줄로 표현됩니다. `vibeguard/rules/`의 적절한 파일에 `make_regex_rule`로 추가하세요.

```python
make_regex_rule(
    "VG-WEB-009",                       # 고유 ID
    "Python SSL/TLS 인증서 검증 비활성화",  # 한 줄 제목
    Severity.HIGH,                      # 심각도
    "web",                              # 분류
    r"ssl\._create_unverified_context", # 정규식 패턴
    "검증을 끄면 중간자 공격에 노출됩니다.",  # 설명(왜 위험한가)
    "검증을 끄지 말고 신뢰 CA를 추가하세요.", # 해결(어떻게 고치는가)
    cwe="CWE-295",
    extensions=(".py",),                # 적용 확장자(None이면 전체)
)
```

체크리스트:
- 설명·해결은 비전문가도 이해할 수 있는 한국어로 작성합니다.
- 제목/설명/해결 문구가 자기 자신의 패턴에 걸리지 않게 합니다. 불가피하면 해당 줄 끝에 `# vibeguard: ignore`를 답니다.
- `tests/`에 탐지 테스트와, 가능하면 오탐(정상 코드 미탐지) 테스트를 추가합니다.
- 백신이 오인할 수 있는 페이로드(웹셸 등)는 테스트에서 토큰을 조합해 완전한 리터럴을 소스에 남기지 않습니다.

## 확인 사항 (PR 전)

```
pytest                                   # 전체 통과
python -m vibeguard scan vibeguard --offline   # 도구 자체 코드: 발견 0건이어야 함
python -m vibeguard rules                # 규칙이 정상 등록됐는지
```

## 커밋·PR

- 한 PR에는 한 가지 주제만 담습니다.
- 커밋 메시지는 무엇을·왜 바꿨는지 명확히 적습니다.
- CI(GitHub Actions)가 통과해야 머지됩니다.

## 라이선스

기여하신 코드는 [MIT License](LICENSE) 하에 배포됩니다.
