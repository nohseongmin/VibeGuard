"""GUI 로컬 서버(vibeguard.server) 테스트.

네트워크 없이(offline) 동작하며, 임시 포트(0)로 스레드 서버를 띄워 HTTP 계층을 확인한다.
"""

import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request

from http.server import ThreadingHTTPServer

from vibeguard import server as S

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "examples", "vibe_coded_app"
)


def test_build_scan_payload_detects_demo():
    p = S.build_scan_payload(DEMO, offline=True)
    assert p["total"] > 0
    assert p["score"] < 100
    assert p["grade"] in ("A", "B", "C", "D", "F")
    assert sum(p["counts"].values()) == p["total"]
    # 슬롭스쿼팅/오타스쿼팅 항목이 포함되어야 함(차별 기능)
    assert any("SLOP" in f["rule_id"] for f in p["findings"])
    # 직렬화 가능해야 함(JSON 응답에 사용)
    json.dumps(p, ensure_ascii=False)


def _start_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), S._Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, httpd.server_address[1]


def test_http_index_serves_html():
    httpd, port = _start_server()
    try:
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read().decode("utf-8")
        assert "VibeGuard" in html and "<script>" in html
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_http_api_scan_returns_findings():
    httpd, port = _start_server()
    try:
        q = urllib.parse.urlencode({"path": DEMO, "offline": "1"})
        raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/scan?{q}").read()
        d = json.loads(raw.decode("utf-8"))
        assert d["total"] > 0
        assert isinstance(d["findings"], list)
        assert d["score"] < 100
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_http_bad_path_returns_400():
    httpd, port = _start_server()
    try:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/scan?path=__no_such_dir__")
            assert False, "존재하지 않는 경로는 400 이어야 함"
        except urllib.error.HTTPError as e:
            assert e.code == 400
    finally:
        httpd.shutdown()
        httpd.server_close()
