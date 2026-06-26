"""Java 언어에서 흔한 취약 패턴."""

from __future__ import annotations

from ..finding import Severity
from .base import make_regex_rule

JAVA = (".java",)

make_regex_rule(
    "VG-JV-001",
    "Java 런타임 명령 실행에 문자열 결합 사용(명령 주입)",
    Severity.HIGH,
    "dangerous",
    r"Runtime\.getRuntime\(\)\.exec\([^)]*\+",
    "명령 문자열에 변수를 + 로 이어 붙이면 명령어 주입 위험이 있습니다.",
    "ProcessBuilder 에 인자를 배열로 분리해 전달하고 셸 보간을 피하세요.",
    cwe="CWE-78",
    extensions=JAVA,
)

make_regex_rule(
    "VG-JV-002",
    "Java SQL 쿼리에 문자열 결합 사용",
    Severity.HIGH,
    "injection",
    r"(?:executeQuery|executeUpdate|execute)\s*\(\s*\"[^\"]*\"\s*\+",
    "SQL 문자열에 값을 + 로 이어 붙이면 SQL 인젝션에 취약합니다.",
    "PreparedStatement 와 ? 플레이스홀더, setString/setInt 바인딩을 사용하세요.",
    cwe="CWE-89",
    extensions=JAVA,
)

make_regex_rule(
    "VG-JV-003",
    "Java 약한 해시(MD5/SHA-1)",
    Severity.MEDIUM,
    "crypto",
    r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"",
    "MD5/SHA-1 은 충돌 공격에 취약해 비밀번호 해시나 무결성 검증에 부적합합니다.",
    "비밀번호는 bcrypt/argon2/scrypt 를, 무결성은 SHA-256 이상을 사용하세요.",
    cwe="CWE-327",
    extensions=JAVA,
)
