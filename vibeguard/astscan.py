"""AST 기반 정밀도 향상.

Python 소스의 문자열 리터럴 위치를 ast 로 파악해, 코드성 규칙(eval/SQL/약한 해시 등)이
'문자열 안'의 텍스트에 잘못 매칭되는 가짜 양성(false positive)을 걸러낸다.
시크릿 규칙은 문자열 자체가 탐지 대상이므로 이 필터를 적용하지 않는다.

파싱이 안 되는 파일은 빈 목록을 돌려주어 필터가 적용되지 않게(안전) 한다.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

# (시작줄, 시작열, 끝줄, 끝열) — 줄은 1-based, 열은 0-based(ast 기준)
Span = Tuple[int, int, int, int]


def string_literal_spans(source: str) -> List[Span]:
    """소스 내 모든 문자열 리터럴의 위치 범위 목록."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    spans: List[Span] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.end_lineno is not None and node.end_col_offset is not None:
                spans.append(
                    (node.lineno, node.col_offset, node.end_lineno, node.end_col_offset)
                )
    return spans


def in_string_span(spans: List[Span], line: int, col: int) -> bool:
    """(line: 1-based, col: 0-based) 위치가 어떤 문자열 리터럴 범위 안에 있는지."""
    for sl, sc, el, ec in spans:
        if line < sl or line > el:
            continue
        if sl == el:
            if sc <= col < ec:
                return True
        elif line == sl:
            if col >= sc:
                return True
        elif line == el:
            if col < ec:
                return True
        else:
            return True
    return False
