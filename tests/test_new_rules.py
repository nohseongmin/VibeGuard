"""라운드 2에서 추가한 규칙(SSL/zip-slip/JWT/SSTI) 탐지 테스트."""

from vibeguard.scanner import Scanner


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan_file(str(p))}


def test_python_ssl_verification_off(tmp_path):
    ids = _scan(tmp_path, "a.py", "ctx = ssl._create_unverified_context()\n")
    assert "VG-WEB-009" in ids


def test_check_hostname_false(tmp_path):
    ids = _scan(tmp_path, "a.py", "ctx.check_hostname = False\n")
    assert "VG-WEB-009" in ids


def test_zip_slip_extractall(tmp_path):
    ids = _scan(tmp_path, "a.py", "import tarfile\ntarfile.open(p).extractall(dest)\n")
    assert "VG-EXEC-008" in ids


def test_jwt_verify_signature_false(tmp_path):
    ids = _scan(tmp_path, "a.py", 'jwt.decode(tok, key, options={"verify_signature": False})\n')
    assert "VG-CRYPTO-006" in ids


def test_jwt_algorithm_none(tmp_path):
    ids = _scan(tmp_path, "a.py", 'data = jwt.decode(tok, algorithms=["none"])\n')
    assert "VG-CRYPTO-006" in ids


def test_ssti_render_template_string(tmp_path):
    ids = _scan(tmp_path, "a.py", 'render_template_string(f"<h1>{name}</h1>")\n')
    assert "VG-SSTI-001" in ids


def test_clean_code_no_findings(tmp_path):
    ids = _scan(tmp_path, "a.py", "x = 1 + 2\nname = 'world'\nprint('hello', name)\n")
    assert ids == set()
