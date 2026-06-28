"""VibeGuard 로컬 웹 GUI.

외부 프레임워크 없이 표준 라이브러리 http.server 만으로 동작하는 단일 페이지 GUI.
`vibeguard gui` 로 실행하면 127.0.0.1 의 로컬 서버가 떠서 브라우저로 결과를 보여준다.
(우리 규칙 VG-WEB-006 에 따라 0.0.0.0 이 아닌 루프백 주소에만 바인딩한다.)
"""

from __future__ import annotations

import json
import os
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import List
from urllib.parse import urlparse, parse_qs

from .finding import Finding, Severity
from .scanner import Scanner, ScanResult
from .slopsquat import check_project
from .score import summary as score_summary


def build_scan_payload(
    path: str,
    offline: bool = False,
    no_deps: bool = False,
    timeout: float = 4.0,
) -> dict:
    """경로를 스캔하고 GUI/JSON 용 직렬화 가능한 결과 dict 를 만든다."""
    scanner = Scanner()
    result: ScanResult = scanner.scan(path)
    if not no_deps:
        dep_findings: List[Finding] = check_project(path, offline=offline, timeout=timeout)
        result.findings.extend(dep_findings)

    findings = result.sorted_findings()
    score, grade, verdict = score_summary(findings)
    counts = {sev.name: 0 for sev in Severity}
    for f in findings:
        counts[f.severity.name] += 1

    return {
        "path": os.path.abspath(path),
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "files_scanned": result.files_scanned,
        "total": len(findings),
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "VibeGuard"

    # 로그 소음 억제(요청마다 한 줄만 간단히)
    def log_message(self, fmt, *args):  # noqa: N802
        return

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # 로컬 전용 도구: 외부 임베드 차단
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, obj: dict):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path
        if route in ("/", "/index.html"):
            self._send(200, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if route == "/api/scan":
            q = parse_qs(parsed.query)
            path = (q.get("path", ["."])[0] or ".").strip()
            offline = q.get("offline", ["0"])[0] in ("1", "true", "on")
            no_deps = q.get("no_deps", ["0"])[0] in ("1", "true", "on")
            if not os.path.exists(path):
                self._send_json(400, {"error": f"경로를 찾을 수 없습니다: {path}"})
                return
            try:
                payload = build_scan_payload(path, offline=offline, no_deps=no_deps)
            except Exception as exc:  # 방어적: GUI 가 죽지 않도록
                self._send_json(500, {"error": f"스캔 중 오류: {exc}"})
                return
            self._send_json(200, payload)
            return
        self._send(404, b"Not Found", "text/plain; charset=utf-8")


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> int:
    """로컬 GUI 서버를 실행한다. Ctrl+C 로 종료."""
    httpd = ThreadingHTTPServer((host, port), _Handler)
    url = f"http://{host}:{port}/"
    print(f"VibeGuard GUI 실행 중 → {url}")
    print("브라우저에서 폴더 경로를 입력하고 '스캔'을 누르세요. (종료: Ctrl+C)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nGUI 서버를 종료합니다.")
    finally:
        httpd.server_close()
    return 0


INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeGuard — 바이브코딩 보안 스캐너</title>
<style>
  :root{
    --bg:#0B0B0F; --panel:#15161A; --panel2:#1B1D22; --border:#25272E;
    --text:#FFFFFF; --muted:#9BA0A8; --accent:#29D17F; --accent2:#22B86E;
    --crit:#FF4D4D; --high:#FF8A3D; --med:#FFC53D; --low:#5AA2FF; --info:#8A8F99;
    --shadow:none;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);
    color:var(--text);font-family:"Malgun Gothic","맑은 고딕",system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
    line-height:1.55;min-height:100vh}
  a{color:#6cb6ff;text-decoration:none}
  a:hover{text-decoration:underline}
  header{padding:26px 22px 10px;max-width:1040px;margin:0 auto}
  .brand{display:flex;align-items:center;gap:12px}
  .logo{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;
    background:#000;border:1px solid var(--border)}
  .brand h1{font-size:22px;margin:0;letter-spacing:.3px}
  .brand .tag{color:var(--muted);font-size:13px;margin-top:2px}
  main{max-width:1040px;margin:0 auto;padding:8px 22px 60px}
  .bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:var(--panel);
    border:1px solid var(--border);border-radius:14px;padding:12px;margin:14px 0 8px;box-shadow:var(--shadow)}
  .bar input[type=text]{flex:1;min-width:240px;background:#0E0F13;border:1px solid var(--border);
    color:var(--text);border-radius:10px;padding:11px 13px;font-size:14px;font-family:ui-monospace,Consolas,monospace}
  .bar input[type=text]:focus{outline:none;border-color:var(--accent)}
  .chk{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;user-select:none;cursor:pointer}
  button{background:var(--accent);color:#062012;border:0;
    font-weight:700;font-size:14px;padding:11px 22px;border-radius:11px;cursor:pointer;transition:filter .15s}
  button:hover{filter:brightness(1.08)} button:disabled{opacity:.55;cursor:default}
  .hint{color:var(--muted);font-size:12.5px;margin:2px 2px 0}
  #status{margin:14px 2px;color:var(--muted);min-height:20px}
  .spinner{display:inline-block;width:15px;height:15px;border:2px solid #3a4756;border-top-color:var(--accent);
    border-radius:50%;animation:spin .8s linear infinite;vertical-align:-2px;margin-right:8px}
  @keyframes spin{to{transform:rotate(360deg)}}
  .summary{display:none;gap:18px;align-items:center;flex-wrap:wrap;background:var(--panel);
    border:1px solid var(--border);border-radius:16px;padding:20px;margin:12px 0 18px;box-shadow:var(--shadow)}
  .ring{width:118px;height:118px;border-radius:50%;display:grid;place-items:center;flex:0 0 auto;
    background:conic-gradient(var(--gradeColor) calc(var(--pct)*1%),#222d39 0)}
  .ring .inner{width:94px;height:94px;border-radius:50%;background:var(--panel);display:grid;place-items:center;text-align:center}
  .ring .score{font-size:30px;font-weight:800;line-height:1}
  .ring .of{font-size:11px;color:var(--muted)}
  .sumtext{flex:1;min-width:240px}
  .grade{display:inline-block;font-weight:800;font-size:15px;padding:2px 12px;border-radius:999px;color:#05210f}
  .verdict{margin-top:8px;font-size:15px}
  .meta{color:var(--muted);font-size:13px;margin-top:6px}
  .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
  .chip{display:inline-flex;align-items:center;gap:7px;background:var(--panel2);border:1px solid var(--border);
    border-radius:999px;padding:6px 13px;font-size:13px;cursor:pointer;user-select:none;transition:transform .1s}
  .chip:hover{transform:translateY(-1px)} .chip.off{opacity:.4}
  .chip b{font-variant-numeric:tabular-nums}
  .dot{width:9px;height:9px;border-radius:50%}
  .cards{display:flex;flex-direction:column;gap:12px}
  .card{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:12px;
    padding:14px 16px;box-shadow:var(--shadow)}
  .card .top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .badge{font-size:11.5px;font-weight:800;padding:3px 9px;border-radius:6px;color:#0b0f15}
  .ttl{font-weight:700;font-size:15px}
  .ruleid{font-family:ui-monospace,Consolas,monospace;font-size:11.5px;color:var(--muted);
    background:var(--panel2);border:1px solid var(--border);padding:2px 7px;border-radius:6px}
  .sloptag{font-size:11px;font-weight:700;color:#0b0f15;background:#c8a2ff;padding:2px 8px;border-radius:6px}
  .loc{color:var(--muted);font-size:12.5px;font-family:ui-monospace,Consolas,monospace;margin:8px 0 0}
  pre.snip{margin:8px 0;background:#0E0F13;border:1px solid var(--border);border-radius:8px;
    padding:9px 12px;overflow:auto;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;color:#d6dee7}
  .row{margin-top:7px;font-size:13.5px}
  .row .k{color:var(--muted);margin-right:6px}
  .empty{text-align:center;padding:50px 10px;color:var(--muted)}
  .empty .big{font-size:46px;margin-bottom:8px}
  footer{max-width:1040px;margin:0 auto;padding:0 22px 40px;color:var(--muted);font-size:12.5px}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo"><svg width="25" height="25" viewBox="0 0 1024 1024" aria-hidden="true"><path d="M300 256 Q284 256 284 272 L284 528 C284 612 372 700 512 786 C652 700 740 612 740 528 L740 272 Q740 256 724 256 Z" fill="#fff"/><path d="M430 508 L492 566 L612 438" fill="none" stroke="#29D17F" stroke-width="62" stroke-linecap="round" stroke-linejoin="round"/></svg></div>
    <div>
      <h1>VibeGuard</h1>
      <div class="tag">바이브코딩 보안 스캐너 · AI 생성 코드의 취약점과 환각 패키지를 잡아냅니다</div>
    </div>
  </div>
</header>
<main>
  <div class="bar">
    <input id="path" type="text" value="." spellcheck="false" placeholder="스캔할 파일 또는 폴더 경로 (예: examples/vibe_coded_app)">
    <label class="chk"><input type="checkbox" id="offline"> 오프라인(레지스트리 조회 생략)</label>
    <button id="scanBtn">스캔</button>
  </div>
  <div class="hint">서버가 실행 중인 컴퓨터의 경로를 입력하세요. 입력 후 Enter 또는 '스캔' 클릭.</div>
  <div id="status"></div>
  <section class="summary" id="summary">
    <div class="ring" id="ring"><div class="inner"><div><div class="score" id="scoreNum">–</div><div class="of">/ 100</div></div></div></div>
    <div class="sumtext">
      <span class="grade" id="gradeBadge">–</span>
      <div class="verdict" id="verdict"></div>
      <div class="meta" id="meta"></div>
      <div class="chips" id="chips"></div>
    </div>
  </section>
  <section class="cards" id="cards"></section>
</main>
<footer>
  VibeGuard · 런타임 외부 의존성 0 (Python 표준 라이브러리만 사용) ·
  <a href="https://github.com/nohseongmin/VibeGuard" target="_blank" rel="noopener">github.com/nohseongmin/VibeGuard</a>
</footer>
<script>
  const SEV = {
    CRITICAL:{label:"치명적",color:"var(--crit)"},
    HIGH:{label:"높음",color:"var(--high)"},
    MEDIUM:{label:"중간",color:"var(--med)"},
    LOW:{label:"낮음",color:"var(--low)"},
    INFO:{label:"정보",color:"var(--info)"},
  };
  const ORDER = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
  let DATA = null;
  let hidden = new Set();   // 숨길 심각도

  const $ = (id)=>document.getElementById(id);

  function gradeColor(g){
    if(g==="A"||g==="B") return "var(--accent)";
    if(g==="C"||g==="D") return "var(--med)";
    return "var(--crit)";
  }

  async function scan(){
    const path = $("path").value.trim() || ".";
    const offline = $("offline").checked ? "1" : "0";
    $("scanBtn").disabled = true;
    $("summary").style.display = "none";
    $("cards").innerHTML = "";
    $("status").innerHTML = '<span class="spinner"></span>스캔 중… (' + path + ')';
    try{
      const res = await fetch("/api/scan?path=" + encodeURIComponent(path) + "&offline=" + offline);
      const data = await res.json();
      if(!res.ok){ $("status").textContent = "⚠️ " + (data.error || "스캔 실패"); return; }
      DATA = data; hidden = new Set();
      $("status").textContent = "";
      render();
    }catch(e){
      $("status").textContent = "⚠️ 서버 연결 실패: " + e;
    }finally{
      $("scanBtn").disabled = false;
    }
  }

  function render(){
    const d = DATA;
    $("summary").style.display = "flex";
    $("scoreNum").textContent = d.score;
    $("ring").style.setProperty("--pct", d.score);
    $("ring").style.setProperty("--gradeColor", gradeColor(d.grade));
    const gb = $("gradeBadge");
    gb.textContent = "등급 " + d.grade;
    gb.style.background = gradeColor(d.grade);
    $("verdict").textContent = d.verdict;
    $("meta").textContent = "스캔 경로: " + d.path + "  ·  파일 " + d.files_scanned + "개  ·  발견 " + d.total + "건";

    const chips = $("chips"); chips.innerHTML = "";
    ORDER.forEach(s=>{
      const c = document.createElement("div");
      c.className = "chip" + (hidden.has(s) ? " off" : "");
      const dot = document.createElement("span"); dot.className="dot"; dot.style.background=SEV[s].color;
      const txt = document.createElement("span");
      txt.innerHTML = SEV[s].label + " <b>" + (d.counts[s]||0) + "</b>";
      c.appendChild(dot); c.appendChild(txt);
      c.onclick = ()=>{ if(hidden.has(s)) hidden.delete(s); else hidden.add(s); render(); };
      chips.appendChild(c);
    });

    const wrap = $("cards"); wrap.innerHTML = "";
    const shown = d.findings.filter(f=>!hidden.has(f.severity));
    if(d.total === 0){
      wrap.innerHTML = '<div class="empty"><div class="big">✅</div>발견된 문제가 없습니다. 안전합니다!</div>';
      return;
    }
    if(shown.length === 0){
      wrap.innerHTML = '<div class="empty">선택한 심각도 항목이 없습니다. 칩을 다시 눌러 표시하세요.</div>';
      return;
    }
    shown.forEach(f=>wrap.appendChild(cardOf(f)));
  }

  function cardOf(f){
    const sev = SEV[f.severity] || SEV.INFO;
    const card = document.createElement("div");
    card.className = "card";
    card.style.borderLeftColor = sev.color;

    const top = document.createElement("div"); top.className="top";
    const badge = document.createElement("span"); badge.className="badge";
    badge.style.background = sev.color; badge.textContent = sev.label;
    const ttl = document.createElement("span"); ttl.className="ttl"; ttl.textContent = f.title;
    const rid = document.createElement("span"); rid.className="ruleid"; rid.textContent = f.rule_id;
    top.appendChild(badge); top.appendChild(ttl); top.appendChild(rid);
    if((f.rule_id||"").indexOf("SLOP")>=0 || f.category==="supply-chain"){
      const st = document.createElement("span"); st.className="sloptag"; st.textContent="공급망/슬롭스쿼팅";
      top.appendChild(st);
    }
    card.appendChild(top);

    const loc = document.createElement("div"); loc.className="loc";
    loc.textContent = "📄 " + f.file + ":" + f.line + (f.column ? (":" + f.column) : "");
    card.appendChild(loc);

    if(f.snippet){
      const pre = document.createElement("pre"); pre.className="snip"; pre.textContent = f.snippet;
      card.appendChild(pre);
    }
    card.appendChild(rowOf("설명", f.explanation));
    card.appendChild(rowOf("해결", f.fix));
    if(f.cwe){
      const r = document.createElement("div"); r.className="row";
      const k = document.createElement("span"); k.className="k"; k.textContent="참고";
      const num = (f.cwe.match(/\d+/)||[])[0];
      const a = document.createElement("a"); a.textContent = f.cwe;
      a.href = "https://cwe.mitre.org/data/definitions/" + (num||"") + ".html";
      a.target="_blank"; a.rel="noopener";
      r.appendChild(k); r.appendChild(a); card.appendChild(r);
    }
    return card;
  }

  function rowOf(k, v){
    const r = document.createElement("div"); r.className="row";
    const ks = document.createElement("span"); ks.className="k"; ks.textContent = k;
    const vs = document.createElement("span"); vs.textContent = v || "";
    r.appendChild(ks); r.appendChild(vs);
    return r;
  }

  $("scanBtn").addEventListener("click", scan);
  $("path").addEventListener("keydown", e=>{ if(e.key==="Enter") scan(); });
  // 첫 진입 시 현재 폴더 자동 스캔
  scan();
</script>
</body>
</html>
"""
