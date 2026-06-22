# 데모: 취약한 바이브코딩 앱

이 폴더(`vibe_coded_app`)는 AI 어시스턴트에게 "간단한 메모/로그인 API를 만들어줘"라고
시켰을 때 나올 법한, 빠르게 동작하지만 보안 결함이 가득한 코드를 모사한 것입니다.
VibeGuard가 어떤 문제를 잡아내는지 보여주기 위한 의도적 취약 코드이며, 모든 키 값은
가짜입니다. 실제 프로젝트에 복사하지 마세요.

## 실행

```
python -m vibeguard scan examples/vibe_coded_app
```

레지스트리 조회 없이(오프라인) 빠르게 보려면:

```
python -m vibeguard scan examples/vibe_coded_app --offline
```

## 이 데모에 심어둔 취약점

app.py (Python)
- 하드코딩된 OpenAI 키, AWS 키, DB 비밀번호 (VG-SECRET-001/003/009)
- f-string으로 만든 SQL 쿼리 (VG-SQLI-001)
- subprocess 없이 shell 명령에 사용자 입력 결합 (VG-EXEC-003)
- TLS 검증 비활성화 verify=False (VG-WEB-003)
- pickle 역직렬화 (VG-EXEC-004)
- 비밀번호 MD5 해시 (VG-CRYPTO-001)
- random으로 토큰 생성 (VG-CRYPTO-003)
- 디버그 모드 + 0.0.0.0 바인딩 (VG-WEB-001/006)

server.js (JavaScript)
- 하드코딩된 JWT 시크릿 (VG-SECRET-009)
- 전체 허용 CORS (VG-WEB-002)
- 템플릿 문자열 SQL (VG-SQLI-003)
- Math.random 토큰 (VG-CRYPTO-004)
- child_process.exec 템플릿 문자열 (VG-EXEC-007)
- eval 사용 (VG-EXEC-006)
- rejectUnauthorized:false (VG-WEB-004)

requirements.txt / package.json (공급망)
- 존재하지 않는 환각 패키지: flask-easy-auth, react-hook-form-validator-pro (VG-SLOP-001)
- 오타스쿼팅 후보: reqeusts(=requests), expres(=express) (VG-SLOP-002)
