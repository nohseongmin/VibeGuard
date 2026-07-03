"""의존성의 '알려진 취약점(CVE)' 검사 — OSV.dev 실시간 조회.

requirements.txt / package.json / 락파일(package-lock.json·Pipfile.lock·poetry.lock)의
(패키지, 버전)을 OSV(Open Source Vulnerabilities, 구글이 운영하는 오픈소스 취약점 DB)에
조회해, 그 버전에 알려진 취약점(CVE/GHSA)을 보고한다. OSV 가 데이터베이스를 계속
갱신하므로, 로컬 DB 를 갱신하지 않아도 항상 최신 취약점을 반영한다. 외부 의존성 없이
표준 라이브러리(urllib)로 호출하며, 오프라인(--offline)에서는 아무것도 하지 않는다.

락파일이 있으면 선언 파일보다 우선한다: package.json 의 "^4.17.1" 은 범위 추정이지만
package-lock.json 에는 실제 설치된 정확한 버전이 있기 때문이다.

54개의 코드 패턴 규칙(어떻게 코드를 짜면 위험한가)과 달리, 이 검사는 '무엇을 쓰면
위험한가(알려진 취약 버전)'를 다룬다.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from .finding import Finding, Severity

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/"
_MAX_VULNS = 20    # 보고 상한
_MAX_DETAIL = 30   # 상세 조회 상한(같은 CVE 가 GHSA·PYSEC 로 중복되므로 보고 상한보다 넉넉히)
_WORKERS = 8       # 상세 조회 병렬 수
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build",
}

# pkg==1.2.3 및 extras 표기 pkg[extra1,extra2]==1.2.3 지원
_REQ_RE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)"
)
# poetry.lock 의 [[package]] 블록에서 name/version 추출(TOML 파서 없이 — 3.8 호환)
_POETRY_RE = re.compile(
    r'\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"'
)

_SEV = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

# (ecosystem, name, version, 상대파일, 라인)
Target = Tuple[str, str, str, str, int]


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
    """requirements.txt 에서 == 로 고정된 (이름, 버전)만 추출(extras 표기 지원)."""
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


def parse_package_lock(text: str) -> List[Tuple[str, str]]:
    """package-lock.json(v1/v2/v3)에서 실제 설치된 (이름, 정확한 버전)을 추출."""
    out: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if not isinstance(data, dict):
        return out

    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # v2/v3: "node_modules/이름" 키
        for key, info in pkgs.items():
            if not key or not isinstance(info, dict):
                continue  # "" 키는 루트 프로젝트 자신
            if "node_modules/" not in key:
                continue
            name = key.rsplit("node_modules/", 1)[1]
            ver = info.get("version")
            if name and isinstance(ver, str) and ver:
                out.append((name, ver))
        if out:
            return out

    def walk_v1(deps: dict):  # v1: dependencies 트리
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            ver = info.get("version")
            if isinstance(ver, str) and ver:
                out.append((name, ver))
            sub = info.get("dependencies")
            if isinstance(sub, dict):
                walk_v1(sub)

    deps = data.get("dependencies")
    if isinstance(deps, dict):
        walk_v1(deps)
    return out


def parse_pipfile_lock(text: str) -> List[Tuple[str, str]]:
    """Pipfile.lock 에서 (이름, 정확한 버전)을 추출."""
    out: List[Tuple[str, str]] = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if not isinstance(data, dict):
        return out
    for key in ("default", "develop"):
        deps = data.get(key)
        if isinstance(deps, dict):
            for name, info in deps.items():
                ver = info.get("version") if isinstance(info, dict) else None
                if isinstance(ver, str) and ver.startswith("=="):
                    out.append((name, ver[2:]))
    return out


def parse_poetry_lock(text: str) -> List[Tuple[str, str]]:
    """poetry.lock([[package]] 블록)에서 (이름, 정확한 버전)을 추출."""
    return [(n, v) for n, v in _POETRY_RE.findall(text)]


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


def _collect_manifests(root: str) -> List[Target]:
    """(ecosystem, name, version, 상대파일, 라인) 목록을 모은다.

    같은 디렉터리에 락파일이 있으면 선언 파일(package.json)은 건너뛴다 —
    락파일의 버전이 실제 설치본이기 때문이다. 전체 결과는 (생태계, 이름, 버전)
    기준으로 중복 제거된다.
    """
    targets: List[Target] = []

    def read(fp: str) -> Optional[str]:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                return fh.read()
        except OSError:
            return None

    def handle_dir(dp: str, fns: List[str], rel_of) -> None:
        low = {f.lower(): f for f in fns}
        has_npm_lock = "package-lock.json" in low

        for fn in fns:
            base = fn.lower()
            fp = os.path.join(dp, fn)
            if base.startswith("requirements") and base.endswith(".txt"):
                text = read(fp)
                if text is None:
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    m = _REQ_RE.match(line.split("#")[0])
                    if m:
                        targets.append(("PyPI", m.group(1), m.group(2), rel_of(fp), i))
            elif base == "package-lock.json":
                text = read(fp)
                if text is None:
                    continue
                for n, v in parse_package_lock(text):
                    targets.append(("npm", n, v, rel_of(fp), 1))
            elif base == "package.json" and not has_npm_lock:
                text = read(fp)
                if text is None:
                    continue
                for n, v in parse_package_json(text):
                    targets.append(("npm", n, v, rel_of(fp), 1))
            elif base == "pipfile.lock":
                text = read(fp)
                if text is None:
                    continue
                for n, v in parse_pipfile_lock(text):
                    targets.append(("PyPI", n, v, rel_of(fp), 1))
            elif base == "poetry.lock":
                text = read(fp)
                if text is None:
                    continue
                for n, v in parse_poetry_lock(text):
                    targets.append(("PyPI", n, v, rel_of(fp), 1))

    if os.path.isfile(root):
        handle_dir(os.path.dirname(root) or ".", [os.path.basename(root)],
                   lambda fp: os.path.basename(fp))
    else:
        for dp, dirs, fns in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
            handle_dir(dp, fns, lambda fp: os.path.relpath(fp, root))

    seen = set()
    unique: List[Target] = []
    for t in targets:
        key = (t[0], t[1].lower(), t[2])
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def _fetch_details(vids: List[str], timeout: float) -> Dict[str, dict]:
    """취약점 상세를 병렬로 가져온다(실패한 건은 빈 dict)."""
    details: Dict[str, dict] = {}

    def one(vid: str) -> None:
        try:
            details[vid] = _get_json(_VULN_URL + vid, timeout)
        except (urllib.error.URLError, OSError, ValueError, TimeoutError):
            details[vid] = {}

    with ThreadPoolExecutor(max_workers=min(_WORKERS, max(len(vids), 1))) as ex:
        list(ex.map(one, vids))
    return details


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

    # (대상, OSV id) 쌍과 상세 조회 대상 id 목록을 먼저 모은다
    pairs: List[Tuple[Target, str]] = []
    vids: List[str] = []
    for target, r in zip(targets, results):
        for vu in (r.get("vulns") or []):
            vid = vu.get("id")
            if not vid:
                continue
            pairs.append((target, vid))
            if vid not in vids and len(vids) < _MAX_DETAIL:
                vids.append(vid)

    details = _fetch_details(vids, timeout) if vids else {}

    # 같은 CVE 가 여러 OSV 레코드(GHSA·PYSEC 등)로 중복 반환되므로 CVE 별칭 기준으로
    # 합친다. 요약(summary)이 있는 더 풍부한 레코드를 우선한다.
    best: Dict[tuple, Finding] = {}
    for (eco, name, ver, rel, line), vid in pairs:
        detail = details.get(vid) or {}
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
