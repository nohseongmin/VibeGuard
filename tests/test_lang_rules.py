"""Go/PHP 다국어 규칙 테스트.

주의: PHP 웹셸 시그니처는 백신이 소스/임시 파일을 격리할 수 있어,
(1) 소스에는 토큰을 조합해 완전한 리터럴을 남기지 않고,
(2) 임시 파일에는 <?php 래퍼 없이 일반 변수를 써서 '완전한 웹셸'이 되지 않게 한다.
규칙은 라인 단위 매칭이라 래퍼 없이도 정상 탐지된다.
"""

from vibeguard.scanner import Scanner


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan_file(str(p))}


def test_go_insecure_skip_verify(tmp_path):
    code = "cfg := &tls.Config{Insecure" + "SkipVerify: true}\n"
    assert "VG-GO-001" in _scan(tmp_path, "a.go", code)


def test_go_command_sprintf(tmp_path):
    code = 'exec.Command("sh", fmt.' + 'Sprintf("ls %s", x))\n'
    assert "VG-GO-002" in _scan(tmp_path, "a.go", code)


def test_go_sql_sprintf(tmp_path):
    code = 'db.Query(fmt.' + 'Sprintf("SELECT * FROM u WHERE id=%s", id))\n'
    assert "VG-GO-003" in _scan(tmp_path, "a.go", code)


def test_php_eval(tmp_path):
    code = "ev" + "al($code);\n"
    assert "VG-PHP-001" in _scan(tmp_path, "a.php", code)


def test_php_shell_with_var(tmp_path):
    code = "sys" + "tem($cmd);\n"
    assert "VG-PHP-002" in _scan(tmp_path, "a.php", code)


def test_php_sql_user_input(tmp_path):
    code = "mysqli_query($c, $_" + "GET['n']);\n"
    assert "VG-PHP-003" in _scan(tmp_path, "a.php", code)


def test_go_php_rules_not_applied_to_python(tmp_path):
    code = "Insecure" + "SkipVerify: true\n"
    assert "VG-GO-001" not in _scan(tmp_path, "a.py", code)
