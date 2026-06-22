"""규칙 탐지 단위 테스트."""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from vibeguard.scanner import Scanner  # noqa: E402
from vibeguard.finding import Severity  # noqa: E402


def _scan_text(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return Scanner().scan_file(str(p))


def _ids(findings):
    return {f.rule_id for f in findings}


def test_detects_openai_key(tmp_path):
    f = _scan_text(tmp_path, "a.py", 'KEY = "sk-abcdefghijklmnopqrstuvwxyz1234567890"\n')
    assert "VG-SECRET-001" in _ids(f)
    assert any(x.severity == Severity.CRITICAL for x in f)


def test_detects_aws_key(tmp_path):
    f = _scan_text(tmp_path, "a.py", 'k = "AKIAIOSFODNN7EXAMPLE"\n')
    assert "VG-SECRET-003" in _ids(f)


def test_detects_private_key(tmp_path):
    f = _scan_text(tmp_path, "a.py", "-----BEGIN RSA PRIVATE KEY-----\n")
    assert "VG-SECRET-008" in _ids(f)


def test_password_assignment(tmp_path):
    f = _scan_text(tmp_path, "a.py", 'password = "hunter2secret"\n')
    assert "VG-SECRET-009" in _ids(f)


def test_placeholder_password_ignored(tmp_path):
    # placeholder 값은 무시되어야 함
    f = _scan_text(tmp_path, "a.py", 'password = "your-password-here"\n')
    assert "VG-SECRET-009" not in _ids(f)


def test_sql_fstring(tmp_path):
    f = _scan_text(
        tmp_path, "a.py", 'cur.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    )
    assert "VG-SQLI-001" in _ids(f)


def test_eval(tmp_path):
    f = _scan_text(tmp_path, "a.py", "eval(user_input)\n")
    assert "VG-EXEC-001" in _ids(f)


def test_subprocess_shell_true(tmp_path):
    f = _scan_text(tmp_path, "a.py", "subprocess.run(cmd, shell=True)\n")
    assert "VG-EXEC-002" in _ids(f)


def test_pickle(tmp_path):
    f = _scan_text(tmp_path, "a.py", "pickle.loads(data)\n")
    assert "VG-EXEC-004" in _ids(f)


def test_verify_false(tmp_path):
    f = _scan_text(tmp_path, "a.py", "requests.get(url, verify=False)\n")
    assert "VG-WEB-003" in _ids(f)


def test_debug_true(tmp_path):
    f = _scan_text(tmp_path, "a.py", "app.run(debug=True)\n")
    assert "VG-WEB-001" in _ids(f)


def test_md5(tmp_path):
    f = _scan_text(tmp_path, "a.py", "hashlib.md5(pw).hexdigest()\n")
    assert "VG-CRYPTO-001" in _ids(f)


def test_math_random_js(tmp_path):
    f = _scan_text(tmp_path, "a.js", "const t = Math.random();\n")
    assert "VG-CRYPTO-004" in _ids(f)


def test_js_sql_template(tmp_path):
    f = _scan_text(
        tmp_path, "a.js", "db.query(`SELECT * FROM u WHERE id = ${id}`)\n"
    )
    assert "VG-SQLI-003" in _ids(f)


def test_ignore_comment(tmp_path):
    f = _scan_text(tmp_path, "a.py", "eval(x)  # vibeguard: ignore\n")
    assert "VG-EXEC-001" not in _ids(f)


def test_clean_file_no_findings(tmp_path):
    f = _scan_text(tmp_path, "a.py", "def add(a, b):\n    return a + b\n")
    assert f == []
