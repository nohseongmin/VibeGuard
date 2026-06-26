"""PHP 언어에서 흔한 취약 패턴.

AI 가 만든 PHP 코드는 사용자 입력을 코드/셸/SQL 에 그대로 넘기는 경우가 잦다.
"""

from __future__ import annotations

from ..finding import Severity
from .base import make_regex_rule

PHP = (".php",)

make_regex_rule(
    "VG-PHP-001",
    "PHP eval 코드 실행",
    Severity.HIGH,
    "dangerous",
    r"\beval\s*\(",
    "문자열을 코드로 실행합니다. 외부 입력이 섞이면 원격 코드 실행으로 이어집니다.",
    "eval 사용을 피하고, 동적 분기는 화이트리스트 매핑으로 처리하세요.",
    cwe="CWE-95",
    extensions=PHP,
)

make_regex_rule(
    "VG-PHP-002",
    "PHP 셸 명령 함수에 변수 사용(명령 주입)",
    Severity.HIGH,
    "dangerous",
    r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*[^)]*\$",
    "셸 명령 실행 함수에 변수가 들어가면 명령어 주입 위험이 큽니다.",
    "escapeshellarg/escapeshellcmd 로 인자를 이스케이프하거나 셸을 거치지 않는 API 를 쓰세요.",
    cwe="CWE-78",
    extensions=PHP,
)

make_regex_rule(
    "VG-PHP-003",
    "PHP SQL 쿼리에 사용자 입력 직접 사용",
    Severity.CRITICAL,
    "injection",
    r"(?:mysqli?_query|->query|->exec)\s*\(\s*[^)]*\$_(?:GET|POST|REQUEST)",
    "사용자 입력($_GET/$_POST 등)을 쿼리에 직접 넣으면 SQL 인젝션에 취약합니다.",
    "PDO prepared statement(플레이스홀더 + bindParam)를 사용하세요.",
    cwe="CWE-89",
    extensions=PHP,
)
