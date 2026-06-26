"""위험한 코드 실행/역직렬화 패턴 탐지.

사용자 입력이나 외부 데이터를 그대로 실행/역직렬화하면 원격 코드 실행(RCE)으로
이어진다. AI 가 "간단히 동작하는" 코드를 만들 때 자주 끼워 넣는 패턴이다.
"""

from __future__ import annotations

import re

from ..finding import Severity
from .base import make_regex_rule

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# Python eval/exec
make_regex_rule(
    "VG-EXEC-001",
    "eval()/exec() 사용",
    Severity.HIGH,
    "dangerous",
    r"\b(?:eval|exec)\s*\(",
    "문자열을 코드로 실행합니다. 입력 일부라도 외부에서 들어오면 원격 코드 실행(RCE)이 가능합니다.",
    "eval/exec 대신 명시적 분기, ast.literal_eval(데이터 파싱용), 또는 매핑 딕셔너리를 사용하세요.",
    cwe="CWE-95",
    extensions=PY,
)

# os.system / subprocess shell=True 와 문자열 결합
make_regex_rule(
    "VG-EXEC-002",
    "shell=True 로 외부 명령 실행",
    Severity.HIGH,
    "dangerous",
    r"subprocess\.(?:run|call|Popen|check_output|check_call)\s*\([^)]*shell\s*=\s*True",
    "셸을 통해 명령을 실행합니다. 입력이 문자열로 결합되면 명령어 주입(command injection)에 취약합니다.",
    "shell=True 를 제거하고 인자를 리스트로 전달하세요. 예: subprocess.run(['ls', path]) (셸 해석 없음).",
    cwe="CWE-78",
    extensions=PY,
)

make_regex_rule(
    "VG-EXEC-003",
    "os.system() 에 문자열 포매팅 사용",
    Severity.HIGH,
    "dangerous",
    r"os\.system\s*\(\s*(?:f[\"']|[\"'][^\"']*[\"']\s*(?:%|\.format)|.*\+)",
    "os.system 에 동적으로 만든 문자열을 넘기면 명령어 주입에 취약합니다.",
    "subprocess 의 인자 리스트 방식으로 바꾸고 사용자 입력을 직접 셸에 넘기지 마세요.",
    cwe="CWE-78",
    extensions=PY,
)

# pickle / yaml.load / marshal
make_regex_rule(
    "VG-EXEC-004",
    "신뢰할 수 없는 데이터를 pickle 로 역직렬화",
    Severity.HIGH,
    "dangerous",
    r"\bpickle\.(?:load|loads)\s*\(",
    "pickle 역직렬화는 임의 코드 실행이 가능합니다. 네트워크/파일에서 받은 데이터에 쓰면 위험합니다.",
    "신뢰 경계를 넘는 데이터는 JSON 등 안전한 형식을 사용하세요. 꼭 필요하면 서명/검증을 추가하세요.",
    cwe="CWE-502",
    extensions=PY,
)

make_regex_rule(
    "VG-EXEC-005",
    "yaml.load 에 SafeLoader 미사용",
    Severity.HIGH,
    "dangerous",
    r"yaml\.load\s*\((?:(?!Loader\s*=\s*(?:yaml\.)?SafeLoader).)*\)",
    "yaml.load 는 기본적으로 임의 파이썬 객체를 생성할 수 있어 코드 실행 위험이 있습니다.",
    "yaml.safe_load(...) 를 사용하거나 Loader=yaml.SafeLoader 를 명시하세요.",
    cwe="CWE-502",
    extensions=PY,
)

# JS eval / Function / child_process exec with template string
make_regex_rule(
    "VG-EXEC-006",
    "JavaScript eval()/new Function() 사용",
    Severity.HIGH,
    "dangerous",
    r"\b(?:eval\s*\(|new\s+Function\s*\()",
    "문자열을 코드로 실행합니다. 외부 입력이 섞이면 클라이언트/서버에서 코드 주입이 가능합니다.",
    "eval/new Function 을 제거하세요. JSON 은 JSON.parse 로, 동적 분기는 객체 매핑으로 처리하세요.",
    cwe="CWE-95",
    extensions=JS,
)

make_regex_rule(
    "VG-EXEC-007",
    "child_process.exec 에 템플릿 문자열 사용",
    Severity.HIGH,
    "dangerous",
    r"(?:child_process\.)?exec(?:Sync)?\s*\(\s*`[^`]*\$\{",
    "셸 명령에 변수를 끼워 넣고 있습니다. 명령어 주입(command injection) 위험이 큽니다.",
    "execFile 또는 spawn 으로 인자를 배열 형태로 전달하고, 셸 보간을 사용하지 마세요.",
    cwe="CWE-78",
    extensions=JS,
)


# 압축 파일을 검증 없이 전체 해제 (zip slip / 경로 조작)
make_regex_rule(
    "VG-EXEC-008",
    "압축 파일을 검증 없이 전체 해제(zip/tar)",
    Severity.MEDIUM,
    "path",
    r"\.extractall\s*\(",
    "항목 경로를 검증하지 않고 압축을 풀면, 악성 아카이브가 상위 경로(../)로 파일을 덮어쓸 수 있습니다(zip slip).",
    "각 항목이 대상 폴더를 벗어나지 않는지 확인 후 해제하세요. Python 3.12+ 는 filter='data' 옵션을 사용하세요.",
    cwe="CWE-22",
    extensions=PY,
)
