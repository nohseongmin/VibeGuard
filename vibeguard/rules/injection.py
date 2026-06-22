"""SQL/NoSQL 인젝션 패턴 탐지.

AI 가 만든 코드는 매개변수화 쿼리 대신 문자열을 이어 붙여 SQL 을 만드는 경우가 많다.
이는 전형적인 SQL 인젝션 취약점이다.
"""

from __future__ import annotations

import re

from ..finding import Severity
from .base import make_regex_rule

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

_SQL_VERBS = r"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|INTO|VALUES|DROP|UNION)"

# Python: cursor.execute(f"... {x} ...")  / execute("..." % x) / execute("..." + x)
make_regex_rule(
    "VG-SQLI-001",
    "f-string 으로 SQL 쿼리를 조립",
    Severity.CRITICAL,
    "injection",
    rf"\.execute\w*\s*\(\s*f[\"'][^\"']*{_SQL_VERBS}[^\"']*\{{",
    "f-string 으로 만든 SQL 을 실행합니다. 값이 그대로 쿼리에 박혀 SQL 인젝션에 취약합니다.",
    "매개변수화 쿼리를 쓰세요. 예: cursor.execute('SELECT * FROM u WHERE id=%s', (uid,)). 값은 절대 문자열로 합치지 마세요.",
    cwe="CWE-89",
    extensions=PY,
    flags=re.IGNORECASE,
)

make_regex_rule(
    "VG-SQLI-002",
    "문자열 결합/포맷으로 SQL 쿼리를 조립",
    Severity.HIGH,
    "injection",
    rf"\.execute\w*\s*\(\s*[\"'][^\"']*{_SQL_VERBS}[^\"']*[\"']\s*(?:%|\+|\.format\s*\()",
    "SQL 문자열에 + 또는 % 또는 .format 으로 값을 끼워 넣고 있습니다. SQL 인젝션 위험이 큽니다.",
    "매개변수화 쿼리(플레이스홀더 %s, ?)와 파라미터 튜플을 사용하세요.",
    cwe="CWE-89",
    extensions=PY,
    flags=re.IGNORECASE,
)

# JS: db.query(`... ${x} ...`) with SQL verbs
make_regex_rule(
    "VG-SQLI-003",
    "템플릿 문자열로 SQL 쿼리를 조립",
    Severity.CRITICAL,
    "injection",
    rf"\.(?:query|execute|raw)\s*\(\s*`[^`]*{_SQL_VERBS}[^`]*\$\{{",
    "템플릿 문자열(`${...}`)로 SQL 을 만들고 있습니다. 값이 쿼리에 직접 들어가 SQL 인젝션에 취약합니다.",
    "매개변수화 쿼리를 쓰세요. 예: db.query('SELECT * FROM u WHERE id = ?', [id]). ORM 의 안전한 빌더를 써도 좋습니다.",
    cwe="CWE-89",
    extensions=JS,
    flags=re.IGNORECASE,
)

# MongoDB $where 사용
make_regex_rule(
    "VG-SQLI-004",
    "MongoDB $where 연산자 사용",
    Severity.HIGH,
    "injection",
    r"['\"]?\$where['\"]?\s*:",
    "$where 는 서버에서 JS 를 실행하므로 NoSQL 인젝션·성능 문제의 원인이 됩니다.",
    "$where 대신 일반 쿼리 연산자($eq, $gt 등)를 사용하세요.",
    cwe="CWE-943",
    extensions=JS,
)
