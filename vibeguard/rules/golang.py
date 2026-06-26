"""Go 언어에서 흔한 취약 패턴.

AI 가 만든 Go 코드는 TLS 검증을 끄거나, 셸 명령·SQL 에 fmt.Sprintf 로 값을
끼워 넣는 실수를 자주 한다.
"""

from __future__ import annotations

from ..finding import Severity
from .base import make_regex_rule

GO = (".go",)

make_regex_rule(
    "VG-GO-001",
    "Go TLS 인증서 검증 비활성화(InsecureSkipVerify)",
    Severity.HIGH,
    "web",
    r"InsecureSkipVerify\s*:\s*true",
    "TLS 인증서 검증을 끄면 중간자(MITM) 공격에 통신이 그대로 노출됩니다.",
    "검증을 끄지 말고, 사설 CA 는 tls.Config 의 RootCAs 에 추가하세요.",
    cwe="CWE-295",
    extensions=GO,
)

make_regex_rule(
    "VG-GO-002",
    "Go 셸 명령에 포맷 문자열 사용(명령 주입)",
    Severity.HIGH,
    "dangerous",
    r"exec\.Command\([^)]*fmt\.Sprintf",
    "명령에 변수를 포맷으로 끼워 넣으면 명령어 주입(command injection) 위험이 있습니다.",
    "인자를 exec.Command(name, arg1, arg2) 처럼 분리해 전달하고 셸 보간을 피하세요.",
    cwe="CWE-78",
    extensions=GO,
)

make_regex_rule(
    "VG-GO-003",
    "Go SQL 쿼리에 포맷 문자열 사용",
    Severity.HIGH,
    "injection",
    r"\.(?:Query|QueryRow|Exec)\w*\([^)]*fmt\.Sprintf",
    "SQL 문자열에 값을 포맷으로 끼워 넣으면 SQL 인젝션에 취약합니다.",
    "플레이스홀더($1, ?)와 인자를 분리해 전달하는 매개변수화 쿼리를 쓰세요.",
    cwe="CWE-89",
    extensions=GO,
)
