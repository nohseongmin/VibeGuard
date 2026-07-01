"""의존성의 '알려진 취약점(CVE)' 검사 — OSV.dev 실시간 조회.

requirements.txt / package.json 의 (패키지, 버전)을 OSV(Open Source Vulnerabilities,
구글이 운영하는 오픈소스 취약점 DB)에 조회해, 그 버전에 알려진 취약점(CVE/GHSA)을
보고한다. OSV 가 데이터베이스를 계속 갱신하므로, 로컬 DB 를 갱신하지 않아도 항상 최신
취약점을 반영한다. 외부 의존성 없이 표준 라이브러리(urllib)로 호출하며, 오프라인
(--offline)에서는 아무것도 하지 않는다.

54개의 코드 패턴 규칙(어떻게 코드를 짜면 위험한가)과 달리, 이 검사는 '무엇을 쓰면
위험한가(알려진 취약 버전)'를 다룬다.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import List, Optional, Tuple

from .finding import Finding, Severity

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/"
_MAX_VULNS = 20  # 조회/보고 상한(과도한 네트워크 호출 방지)
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)")

_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _post_json(url: str, payload: dict, timeout: float) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json", "User-Agent": "VibeGuard"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _get_json(url: str, timeout: float) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "VibeGuard"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    """requirements.txt 에서 == 로 고정된 (이름, 버전)만 추출."""
    out: List[Tuple[str, str]] = []
    for line in text.splitlines():
        m = _REQ_RE.match(line.split("#")[0])
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _clean_ver(spec: str) -> Optional[str]:
    """'^1.2.3', '~1.2', '>=1.0.0', 'v1.2.3' 등에서 기준 버전 숫자만 추출."""
    s = re.sub(r"^[\^~>=<\s v]+", "", str(spec))
    m = re.match(r"(\d+(?:\.\d+){0,2})", s)
    return m.group(1) if m else None


def parse_package_json(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if not isinstance(data, dict):
        return out
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                cv = _clean_ver(ver)
                if cv:
                    out.append((name, cv))
    return out


def _map_severity(vuln: dict) -> Severity:
    ds = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(ds, str) and ds.upper() in _SEV:
        return _SEV[ds.upper()]
    for s in vuln.get("severity") or []:
        try:
            f = float(s.get("score"))
        except (TypeError, ValueError):
            continue
        if f >= 9:
            return Severity.CRITICAL
        if f >= 7:
            return Severity.HIGH
        if f >= 4:
            return Severity.MEDIUM
        return Severity.LOW
    return Severity.HIGH  # 알려진 취약점은 기본적으로 '높음'으로 취급


def _fixed_version(vuln: dict, name: str) -> Optional[str]:
    for aff in vuln.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name")
        if pkg and pkg.lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def _cve_alias(vuln: dict) -> str:
    for a in vuln.get("aliases") or []:
        if isinstance(a, str) and a.upper().startswith("CVE-"):
            return a
    return vuln.get("id", "")


def _collect_manifests(root: str) -> List[Tuple[str, str, str, str, int]]:
    """(ecosystem, name, version, 상대파일, 라인) 목록을 모은다."""
    targets: List[Tuple[str, str, str, str, int]] = []

    def handle(fp: str, rel: str):
        base = os.path.basename(fp).lower()
        try:
            text = open(fp, "r", encoding="utf-8", errors="ignore").read()
        except OSError:
            return
        if base.startswith("requirements") and base.endswith(".txt"):
            for i, line in enumerate(text.splitlines(), 1):
                m = _REQ_RE.match(line.split("#")[0])
                if m:
                    targets.append(("PyPI", m.group(1), m.group(2), rel, i))
        elif base == "package.json":
            for n, v in parse_package_json(text):
                targets.append(("npm", n, v, rel, 1))

    if os.path.isfile(root):
        handle(root, os.path.basename(root))
        return targets
    for dp, dirs, fns in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in fns:
            low = fn.lower()
            if low == "package.json" or (low.startswith("requirements") and low.endswith(".txt")):
                fp = os.path.join(dp, fn)
                handle(fp, os.path.relpath(fp, root))
    return targets


def check_project_cve(root: str, offline: bool = False, timeout: float = 6.0) -> List[Finding]:
    """프로젝트 의존성을 OSV 에 조회해 알려진 취약점(CVE) Finding 목록을 만든다."""
    if offline:
        return []
    targets = _collect_manifests(root)
    if not targets:
        return []

    queries = [
        {"version": v, "package": {"name": n, "ecosystem": eco}}
        for (eco, n, v, _, _) in targets
    ]
    try:
        res = _post_json(_BATCH_URL, {"queries": queries}, timeout)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        return []  # 네트워크 실패 시 조용히 건너뜀

    results = res.get("results") or []
    # 같은 CVE 가 여러 OSV 레코드(GHSA·PYSEC 등)로 중복 반환되므로 CVE 별칭 기준으로
    # 합친다. 요약(summary)이 있는 더 풍부한 레코드를 우선한다.
    best: "dict[tuple, Finding]" = {}
    calls = 0
    for (eco, name, ver, rel, line), r in zip(targets, results):
        for vu in (r.get("vulns") or []):
            vid = vu.get("id")
            if not vid:
                continue
            detail = {}
            if calls < _MAX_VULNS:
                try:
                    detail = _get_json(_VULN_URL + vid, timeout)
                    calls += 1
                except (urllib.error.URLError, OSError, ValueError, TimeoutError):
                    detail = {}
            sev = _map_severity(detail) if detail else Severity.HIGH
            cve = _cve_alias(detail) if detail else vid
            fixed = _fixed_version(detail, name) if detail else None
            summary = (detail.get("summary") or "").strip() if detail else ""

            key = (rel, name.lower(), ver, cve)
            prev = best.get(key)
            # 이미 있고, 기존이 요약을 가졌거나 이번에 요약이 없으면 유지
            if prev is not None and (bool(prev.metadata.get("summary")) or not summary):
                continue

            best[key] = Finding(
                rule_id="VG-CVE-001",
                title=f"의존성 {name} {ver} — 알려진 취약점 {cve}",
                severity=sev,
                category="vulnerable-dependency",
                file=rel,
                line=line,
                snippet=f"{name}=={ver}",
                explanation=(
                    (summary[:160] + " " if summary else "")
                    + f"이 버전에 알려진 보안 취약점이 있습니다({cve})."
                ),
                fix=(
                    (f"{fixed} 이상으로 업그레이드하세요. " if fixed
                     else "취약점이 수정된 최신 버전으로 업그레이드하세요. ")
                    + f"자세히: https://osv.dev/vulnerability/{vid}"
                ),
                cwe="CWE-1395",
                metadata={"ecosystem": eco, "osv": vid, "cve": cve,
                          "fixed": fixed, "summary": bool(summary)},
            )

    findings = sorted(best.values(), key=lambda f: (-int(f.severity), f.file, f.title))
    return findings[:_MAX_VULNS]
