"""AST 문자열-리터럴 필터(정밀도) 테스트."""

from vibeguard import astscan
from vibeguard.scanner import Scanner


def _ids(tmp_path, text):
    p = tmp_path / "a.py"
    p.write_text(text, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan_file(str(p))}


def test_code_pattern_inside_string_is_suppressed(tmp_path):
    # 문자열 안의 "eval(" 은 실행 코드가 아니므로 탐지하지 않는다.
    ids = _ids(tmp_path, 'doc = "use eval() with care"\n')
    assert "VG-EXEC-001" not in ids


def test_real_call_still_flagged(tmp_path):
    code = 'msg = "hello"\nout = ev' + "al(user_input)\n"
    assert "VG-EXEC-001" in _ids(tmp_path, code)


def test_weak_hash_in_docstring_suppressed(tmp_path):
    code = '"""md5(x) 는 약하다"""\nimport os\n'
    ids = _ids(tmp_path, code)
    assert "VG-CRYPTO-001" not in ids
    assert "VG-CRYPTO-002" not in ids


def test_secret_in_string_still_detected(tmp_path):
    # 시크릿은 문자열 자체가 대상이므로 필터에서 제외 -> 여전히 탐지된다.
    key = "sk-" + "a" * 30
    assert "VG-SECRET-001" in _ids(tmp_path, 'OPENAI = "%s"\n' % key)


def test_span_helpers():
    spans = astscan.string_literal_spans('x = "abc"\n')
    assert spans
    assert astscan.in_string_span(spans, 1, 5) is True
    assert astscan.in_string_span(spans, 1, 0) is False


def test_unparsable_source_returns_no_spans():
    assert astscan.string_literal_spans("def (oops\n") == []
