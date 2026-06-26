"""Ruby 언어에서 흔한 취약 패턴."""

from __future__ import annotations

from ..finding import Severity
from .base import make_regex_rule

RB = (".rb",)

make_regex_rule(
    "VG-RB-001",
    "Ruby eval 코드 실행",
    Severity.HIGH,
    "dangerous",
    r"\beval\s*\(",
    "문자열을 코드로 실행합니다. 외부 입력이 섞이면 원격 코드 실행으로 이어집니다.",
    "eval 사용을 피하고, 동적 분기는 화이트리스트 매핑으로 처리하세요.",
    cwe="CWE-95",
    extensions=RB,
)

make_regex_rule(
    "VG-RB-002",
    "Ruby 셸 명령에 문자열 보간 사용(명령 주입)",
    Severity.HIGH,
    "dangerous",
    r"(?:\bsystem|\bexec|\bspawn)\s*\(\s*[\"'][^\"']*#\{",
    "셸 명령 문자열에 #{...} 로 변수를 끼워 넣으면 명령어 주입 위험이 큽니다.",
    "인자를 배열로 분리해 전달하세요. 예: system('ls', dir). 셸 보간을 피하세요.",
    cwe="CWE-78",
    extensions=RB,
)

make_regex_rule(
    "VG-RB-003",
    "Ruby Marshal 역직렬화(신뢰할 수 없는 데이터)",
    Severity.HIGH,
    "dangerous",
    r"\bMarshal\.load\s*\(",
    "신뢰할 수 없는 데이터를 역직렬화하면 객체 주입으로 코드 실행이 가능합니다.",
    "외부 입력에는 Marshal 을 쓰지 말고 JSON 등 안전한 포맷을 사용하세요.",
    cwe="CWE-502",
    extensions=RB,
)
