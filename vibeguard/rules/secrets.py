"""하드코딩된 비밀정보(API 키, 토큰, 비밀번호, 개인키) 탐지 규칙.

AI 어시스턴트는 동작하는 예시를 빠르게 만들기 위해 키를 코드에 그대로 박아 넣는
경우가 매우 흔하다. 이 키가 git 에 커밋되면 그대로 유출된다.
"""

from __future__ import annotations

import re

from ..finding import Severity
from .base import make_regex_rule

_SECRET_FIX = (
    "코드에서 값을 제거하고 환경변수(.env)나 비밀관리 서비스로 옮기세요. "
    "예: key = os.environ['API_KEY']. 이미 커밋했다면 키를 즉시 폐기/재발급하세요."
)

# 제공자별 고유 패턴 키 (오탐이 거의 없음 -> CRITICAL)
make_regex_rule(
    "VG-SECRET-001",
    "OpenAI API 키가 코드에 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\bsk-[A-Za-z0-9]{20,}\b",
    "OpenAI 형식의 비밀 API 키가 소스코드에 직접 들어 있습니다. 저장소가 공개되면 즉시 도용됩니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-002",
    "Anthropic API 키가 코드에 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b",
    "Anthropic(Claude) 비밀 API 키가 소스코드에 노출되어 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-003",
    "AWS 액세스 키 ID가 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\bAKIA[0-9A-Z]{16}\b",
    "AWS 액세스 키가 코드에 들어 있습니다. 클라우드 계정 전체가 탈취될 수 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-004",
    "GitHub 토큰이 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "GitHub 개인 액세스 토큰이 노출되어 있습니다. 저장소·조직 접근 권한이 탈취될 수 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-005",
    "Google API 키가 하드코딩됨",
    Severity.HIGH,
    "secrets",
    r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "Google API 키가 코드에 노출되어 있습니다. 과금형 API라면 비용 폭탄으로 이어질 수 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-006",
    "Stripe 비밀 키가 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\b[rs]k_live_[A-Za-z0-9]{20,}\b",
    "Stripe 라이브 비밀 키가 노출되어 있습니다. 실결제·환불 권한이 탈취될 수 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

make_regex_rule(
    "VG-SECRET-007",
    "Slack 토큰이 하드코딩됨",
    Severity.HIGH,
    "secrets",
    r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b",
    "Slack 토큰이 코드에 노출되어 있습니다. 워크스페이스 메시지·데이터가 탈취될 수 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
)

# 개인키(PEM) 블록 시작
make_regex_rule(
    "VG-SECRET-008",
    "개인키(Private Key)가 저장소에 포함됨",
    Severity.CRITICAL,
    "secrets",
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    "암호화 개인키가 소스에 포함되어 있습니다. 서버 신원·TLS·SSH 접근이 통째로 탈취될 수 있습니다.",
    "개인키 파일은 저장소에서 제거하고 .gitignore 에 추가하세요. 비밀관리 시스템으로 옮기고 키를 재발급하세요.",
    cwe="CWE-798",
)

# 일반 패턴: password/secret/token/api_key 변수에 따옴표 값 할당
make_regex_rule(
    "VG-SECRET-009",
    "비밀번호/키가 변수에 평문으로 하드코딩됨",
    Severity.HIGH,
    "secrets",
    r"""(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|"""
    r"""auth[_-]?token|client[_-]?secret|private[_-]?key|db[_-]?password)\b"""
    r"""\s*[:=]\s*["']([^"']{6,})["']""",
    "비밀번호 또는 키로 보이는 값이 코드에 평문으로 들어 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
    secret_group=1,
    skip_placeholders=True,
)

# 데이터베이스 연결 문자열 안에 비밀번호 포함
make_regex_rule(
    "VG-SECRET-010",
    "DB 접속 URL에 비밀번호가 포함됨",
    Severity.HIGH,
    "secrets",
    r"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://"
    r"[^:\s/]+:([^@\s/]{3,})@",
    "데이터베이스 연결 문자열에 비밀번호가 평문으로 포함되어 있습니다.",
    "연결 정보를 환경변수로 분리하세요. 예: DATABASE_URL 을 .env 에 두고 코드에서는 os.environ 으로 읽습니다.",
    cwe="CWE-798",
    secret_group=1,
    skip_placeholders=True,
)

# SendGrid API 키
make_regex_rule(
    "VG-SECRET-011",
    "SendGrid API 키가 하드코딩됨",
    Severity.CRITICAL,
    "secrets",
    r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
    "SendGrid 형식의 비밀 API 키가 코드에 직접 들어 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
    skip_placeholders=True,
)

# Twilio API 키 SID
make_regex_rule(
    "VG-SECRET-012",
    "Twilio API 키 SID가 하드코딩됨",
    Severity.HIGH,
    "secrets",
    r"\bSK[0-9a-fA-F]{32}\b",
    "Twilio API 키 SID 형식의 비밀 값이 코드에 직접 들어 있습니다.",
    _SECRET_FIX,
    cwe="CWE-798",
    skip_placeholders=True,
)
