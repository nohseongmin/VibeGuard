"""라운드 6 추가 규칙(SendGrid/Twilio/Django DEBUG/오픈 리다이렉트) 테스트."""

from vibeguard.scanner import Scanner


def _scan(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return {f.rule_id for f in Scanner().scan_file(str(p))}


def test_sendgrid_key(tmp_path):
    key = "SG." + "a" * 22 + "." + "b" * 43
    ids = _scan(tmp_path, "a.py", 'SENDGRID = "%s"\n' % key)
    assert "VG-SECRET-011" in ids


def test_twilio_sid(tmp_path):
    sid = "SK" + "0123456789abcdef" * 2  # 소스에 키 리터럴을 두지 않도록 조합
    ids = _scan(tmp_path, "a.py", 'TW = "%s"\n' % sid)
    assert "VG-SECRET-012" in ids


def test_django_debug(tmp_path):
    ids = _scan(tmp_path, "settings.py", "DEBUG = True\n")
    assert "VG-WEB-010" in ids


def test_open_redirect(tmp_path):
    ids = _scan(tmp_path, "a.py", "return redirect(request.args.get('next'))\n")
    assert "VG-WEB-011" in ids


def test_lowercase_debug_not_flagged_as_django(tmp_path):
    # Flask 의 debug=True 는 Django 규칙(VG-WEB-010)에 걸리면 안 됨
    ids = _scan(tmp_path, "a.py", "app.run(debug=True)\n")
    assert "VG-WEB-010" not in ids
