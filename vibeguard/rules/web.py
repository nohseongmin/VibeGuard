"""웹 애플리케이션 보안 설정 결함 탐지.

AI 로 만든 웹앱은 디버그 모드 노출, 전체 허용 CORS, TLS 검증 비활성화,
SSRF 등 '설정' 차원의 결함을 거의 항상 동반한다는 보안 연구 결과가 있다.
"""

from __future__ import annotations

import re

from ..finding import Severity
from .base import make_regex_rule

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# Flask / FastAPI debug 모드
make_regex_rule(
    "VG-WEB-001",
    "디버그 모드가 켜진 채 실행",
    Severity.HIGH,
    "web",
    r"\.run\s*\([^)]*debug\s*=\s*True",
    "디버그 모드는 스택트레이스와 대화형 콘솔을 노출합니다. 운영 환경에 배포되면 코드 실행까지 가능합니다.",
    "운영 환경에서는 debug=False 로 두고, 디버그 여부는 환경변수로 제어하세요.",
    cwe="CWE-489",
    extensions=PY,
)

# 전체 허용 CORS
make_regex_rule(
    "VG-WEB-002",
    "CORS 가 모든 출처(*)를 허용",
    Severity.MEDIUM,
    "web",
    r"(?i)(?:Access-Control-Allow-Origin|allow_origins|origin)\s*[:=]\s*"
    r"[\[\(]?\s*[\"']\*[\"']",
    "모든 도메인에서의 요청을 허용합니다. 인증 쿠키와 함께 쓰면 다른 사이트가 사용자 데이터를 읽을 수 있습니다.",
    "허용할 출처를 명시적 목록으로 제한하세요. 자격증명(credentials)을 쓸 때는 절대 '*' 를 쓰지 마세요.",
    cwe="CWE-942",
)

# TLS 인증서 검증 비활성화 (Python requests)
make_regex_rule(
    "VG-WEB-003",
    "TLS 인증서 검증을 비활성화(verify=False)",  # vibeguard: ignore
    Severity.HIGH,
    "web",
    r"\bverify\s*=\s*False\b",
    "서버 인증서 검증을 끄면 중간자(MITM) 공격에 노출됩니다. 누구든 통신을 가로채 위조할 수 있습니다.",
    "verify=False 를 제거하세요. 사설 CA 가 필요하면 verify='/path/to/ca.pem' 처럼 인증서를 지정하세요.",  # vibeguard: ignore
    cwe="CWE-295",
    extensions=PY,
)

# TLS 검증 비활성화 (Node)
make_regex_rule(
    "VG-WEB-004",
    "TLS 인증서 검증을 비활성화(rejectUnauthorized:false)",
    Severity.HIGH,
    "web",
    r"rejectUnauthorized\s*:\s*false",
    "TLS 인증서 검증을 끄면 중간자 공격에 노출됩니다.",
    "rejectUnauthorized:false 를 제거하세요. 사설 CA 는 ca 옵션으로 신뢰 인증서를 지정하세요.",
    cwe="CWE-295",
    extensions=JS,
)

make_regex_rule(
    "VG-WEB-005",
    "전역 TLS 검증 비활성화(NODE_TLS_REJECT_UNAUTHORIZED=0)",
    Severity.HIGH,
    "web",
    r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0",
    "프로세스 전체의 TLS 검증을 끕니다. 모든 외부 통신이 중간자 공격에 노출됩니다.",
    "이 설정을 제거하세요. 인증서 문제는 신뢰 저장소나 ca 옵션으로 올바르게 해결하세요.",
    cwe="CWE-295",
    extensions=JS,
)

# 0.0.0.0 바인딩 + 디버그 (정보성)
make_regex_rule(
    "VG-WEB-006",
    "모든 인터페이스(0.0.0.0)에 바인딩",
    Severity.LOW,
    "web",
    r"host\s*=\s*[\"']0\.0\.0\.0[\"']",
    "모든 네트워크 인터페이스에 서버를 열고 있습니다. 의도치 않게 외부에 노출될 수 있습니다.",
    "로컬 개발에는 127.0.0.1 을 사용하고, 외부 노출이 필요한 경우에만 명시적으로 0.0.0.0 을 쓰세요.",
    cwe="CWE-668",
    extensions=PY,
)

# Express 등에서 보안 헤더 미들웨어(helmet) 부재는 정적으로 단정하기 어렵지만,
# 명시적으로 X-Powered-By 등을 끄지 않은 app 생성은 정보성으로 안내.
make_regex_rule(
    "VG-WEB-007",
    "innerHTML 에 동적 값 할당(XSS 위험)",
    Severity.MEDIUM,
    "web",
    r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])",
    "innerHTML 에 동적 문자열을 넣으면 사용자 입력에 포함된 스크립트가 실행될 수 있습니다(XSS).",
    "textContent 를 쓰거나, 신뢰할 수 없는 값은 DOMPurify 등으로 정제한 뒤 삽입하세요.",
    cwe="CWE-79",
    extensions=JS,
)

# dangerouslySetInnerHTML (React)
make_regex_rule(
    "VG-WEB-008",
    "React dangerouslySetInnerHTML 사용",
    Severity.MEDIUM,
    "web",
    r"dangerouslySetInnerHTML",
    "정제되지 않은 HTML 을 그대로 렌더링하면 XSS 에 취약합니다.",
    "가능하면 사용하지 말고, 불가피하면 DOMPurify.sanitize() 로 정제한 값만 넣으세요.",
    cwe="CWE-79",
    extensions=JS,
)


# Python SSL/TLS 인증서 검증 비활성화
make_regex_rule(
    "VG-WEB-009",
    "Python SSL/TLS 인증서 검증 비활성화",
    Severity.HIGH,
    "web",
    r"ssl\._create_unverified_context|ssl\.CERT_NONE|check_hostname\s*=\s*False",
    "SSL/TLS 인증서 검증을 끄면 중간자(MITM) 공격에 통신이 그대로 노출됩니다.",
    "검증을 끄지 마세요. 사설 인증서는 ssl.create_default_context(cafile=...) 로 신뢰를 추가하세요.",
    cwe="CWE-295",
    extensions=PY,
)


# Django 디버그 모드 활성화 (settings.py)
make_regex_rule(
    "VG-WEB-010",
    "Django 디버그 모드 활성화(DEBUG)",
    Severity.MEDIUM,
    "web",
    r"^\s*DEBUG\s*=\s*True\b",
    "디버그 모드가 켜져 있으면 오류 페이지로 소스·환경변수·설정이 외부에 노출될 수 있습니다.",
    "운영 환경에서는 디버그 모드를 끄고, 환경변수로 개발/운영 설정을 분기하세요.",
    cwe="CWE-489",
    extensions=PY,
)


# 오픈 리다이렉트 (사용자 입력으로 리다이렉트)
make_regex_rule(
    "VG-WEB-011",
    "사용자 입력으로 리다이렉트(오픈 리다이렉트)",
    Severity.MEDIUM,
    "web",
    r"redirect\s*\(\s*request\.(?:args|form|values|GET|POST)\b",
    "사용자 입력을 그대로 리다이렉트 대상에 쓰면 피싱 사이트로 유도하는 오픈 리다이렉트가 됩니다.",
    "허용된 경로/도메인 목록(allowlist)으로 대상 URL 을 검증한 뒤 리다이렉트하세요.",
    cwe="CWE-601",
    extensions=PY,
)
