"""Ruby/Java 규칙 테스트. (위험 토큰은 백신 격리 방지를 위해 조합)"""

from vibeguard.scanner import Scanner


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan_file(str(p))}


def test_ruby_eval(tmp_path):
    code = "ev" + "al(params[:x])\n"
    assert "VG-RB-001" in _scan(tmp_path, "a.rb", code)


def test_ruby_system_interpolation(tmp_path):
    code = "sys" + 'tem("ls #{dir}")\n'
    assert "VG-RB-002" in _scan(tmp_path, "a.rb", code)


def test_ruby_marshal(tmp_path):
    assert "VG-RB-003" in _scan(tmp_path, "a.rb", "obj = Marshal.load(data)\n")


def test_java_runtime_exec(tmp_path):
    code = 'Runtime.getRuntime().ex' + 'ec("sh -c " + cmd);\n'
    assert "VG-JV-001" in _scan(tmp_path, "a.java", code)


def test_java_sql_concat(tmp_path):
    code = 'stmt.executeQuery("SELECT * FROM u WHERE id=" + id);\n'
    assert "VG-JV-002" in _scan(tmp_path, "a.java", code)


def test_java_weak_hash(tmp_path):
    code = 'MessageDigest.getInstance("MD5");\n'
    assert "VG-JV-003" in _scan(tmp_path, "a.java", code)
