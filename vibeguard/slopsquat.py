"""슬롭스쿼팅(slopsquatting) 및 오타스쿼팅(typosquatting) 탐지.

AI 코딩 어시스턴트는 존재하지 않는 패키지 이름을 그럴듯하게 '환각(hallucinate)'한다.
공격자는 이렇게 자주 환각되는 이름을 미리 레지스트리에 등록해 악성코드를 심어 두고,
개발자가 의심 없이 설치하기를 기다린다(= 슬롭스쿼팅, 공급망 공격).

이 모듈은:
  1) 소스코드/의존성 파일에서 import·의존성 목록을 추출하고,
  2) 표준 라이브러리를 제외한 외부 패키지가 실제 레지스트리(PyPI/npm)에 있는지 확인하며,
  3) 유명 패키지와 편집거리 1~2 로 유사한 '오타스쿼팅' 후보를 찾아낸다.

네트워크가 없으면(--offline) 레지스트리 조회는 건너뛰고 오타 휴리스틱만 수행한다.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Set, Tuple

from .finding import Finding, Severity

# ---------------------------------------------------------------------------
# 표준 라이브러리 판별
# ---------------------------------------------------------------------------
try:
    _PY_STDLIB = set(sys.stdlib_module_names)  # Python 3.10+
except AttributeError:  # pragma: no cover - 구버전 폴백
    _PY_STDLIB = set()

# 구버전/누락 대비 최소 보강 + 자주 쓰는 표준 모듈
_PY_STDLIB |= {
    "os", "sys", "re", "json", "math", "time", "datetime", "random", "secrets",
    "hashlib", "subprocess", "typing", "dataclasses", "collections", "itertools",
    "functools", "pathlib", "logging", "argparse", "urllib", "http", "socket",
    "asyncio", "enum", "io", "csv", "sqlite3", "unittest", "abc", "base64",
    "threading", "multiprocessing", "shutil", "tempfile", "glob", "pickle",
}

# Node.js 내장 모듈
_NODE_BUILTINS = {
    "fs", "path", "http", "https", "crypto", "os", "util", "events", "stream",
    "child_process", "url", "querystring", "zlib", "buffer", "net", "dns",
    "assert", "process", "readline", "cluster", "tls", "dgram", "vm", "module",
    "perf_hooks", "worker_threads", "async_hooks", "timers", "string_decoder",
}

# import 이름 -> 실제 PyPI 패키지 이름 매핑(흔한 불일치)
_PY_IMPORT_TO_PKG = {
    "cv2": "opencv-python", "bs4": "beautifulsoup4", "PIL": "Pillow",
    "sklearn": "scikit-learn", "yaml": "PyYAML", "dotenv": "python-dotenv",
    "jwt": "PyJWT", "dateutil": "python-dateutil", "Crypto": "pycryptodome",
    "google": "google-api-python-client", "serial": "pyserial",
    "OpenSSL": "pyOpenSSL", "win32com": "pywin32",
}

# 오타스쿼팅 비교 대상: 매우 인기 있는 패키지들
_POPULAR_PYPI = {
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "pytest",
    "scipy", "matplotlib", "scikit-learn", "tensorflow", "torch", "pillow",
    "beautifulsoup4", "selenium", "sqlalchemy", "pydantic", "openai",
    "anthropic", "boto3", "click", "rich", "httpx", "aiohttp", "pyyaml",
    "python-dotenv", "cryptography", "redis", "celery", "uvicorn", "gunicorn",
    "transformers", "langchain", "tqdm", "jinja2", "werkzeug", "urllib3",
}
_POPULAR_NPM = {
    "react", "react-dom", "express", "lodash", "axios", "next", "vue",
    "typescript", "webpack", "eslint", "jest", "vite", "tailwindcss",
    "dotenv", "mongoose", "chalk", "commander", "zod", "prisma", "bcrypt",
    "jsonwebtoken", "cors", "body-parser", "socket.io", "moment", "uuid",
}


# ---------------------------------------------------------------------------
# import / 의존성 추출
# ---------------------------------------------------------------------------
_PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([a-zA-Z0-9_]+)|import\s+([a-zA-Z0-9_]+))", re.M)
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]+\s+from\s+)?|require\s*\(\s*)['"]([^'"]+)['"]"""
)


def _top_pkg_js(spec: str) -> Optional[str]:
    """JS 모듈 스펙에서 최상위 패키지명 추출. 상대경로는 무시."""
    if spec.startswith(".") or spec.startswith("/"):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):  # scoped: @scope/name
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return parts[0]


def extract_python_imports(text: str) -> Set[str]:
    names: Set[str] = set()
    for m in _PY_IMPORT_RE.finditer(text):
        name = m.group(1) or m.group(2)
        if name:
            names.add(name.split(".")[0])
    return names


def extract_js_imports(text: str) -> Set[str]:
    names: Set[str] = set()
    for m in _JS_IMPORT_RE.finditer(text):
        pkg = _top_pkg_js(m.group(1))
        if pkg:
            names.add(pkg)
    return names


def parse_requirements_txt(text: str) -> Set[str]:
    names: Set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name==ver, name>=ver, name[extra], name; marker
        m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
        if m:
            names.add(m.group(1))
    return names


def parse_package_json(text: str) -> Set[str]:
    names: Set[str] = set()
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return names
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            names.update(deps.keys())
    return names


# ---------------------------------------------------------------------------
# 편집거리(typosquat 휴리스틱)
# ---------------------------------------------------------------------------
def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def nearest_popular(name: str, popular: Set[str]) -> Optional[Tuple[str, int]]:
    """이름과 가장 가까운 인기 패키지와 편집거리. 동일하면 None."""
    name = name.lower()
    if name in popular:
        return None
    best: Optional[Tuple[str, int]] = None
    for p in popular:
        d = levenshtein(name, p)
        if best is None or d < best[1]:
            best = (p, d)
    return best


# ---------------------------------------------------------------------------
# 레지스트리 조회 (캐시 포함)
# ---------------------------------------------------------------------------
class RegistryClient:
    """PyPI / npm 존재 여부 조회. 결과를 메모리에 캐시한다."""

    def __init__(self, timeout: float = 4.0, offline: bool = False):
        self.timeout = timeout
        self.offline = offline
        self._cache: Dict[str, Optional[bool]] = {}

    def _head_ok(self, url: str) -> Optional[bool]:
        """존재하면 True, 404 면 False, 판단 불가(네트워크 오류 등)면 None."""
        if self.offline:
            return None
        if url in self._cache:
            return self._cache[url]
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "VibeGuard"})
        result: Optional[bool]
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = 200 <= resp.status < 300
        except urllib.error.HTTPError as e:
            result = False if e.code == 404 else None
        except (urllib.error.URLError, OSError, ValueError):
            result = None
        self._cache[url] = result
        return result

    def exists_pypi(self, name: str) -> Optional[bool]:
        return self._head_ok(f"https://pypi.org/pypi/{name}/json")

    def exists_npm(self, name: str) -> Optional[bool]:
        return self._head_ok(f"https://registry.npmjs.org/{name}")


# ---------------------------------------------------------------------------
# 메인 검사
# ---------------------------------------------------------------------------
def _check_one(
    name: str,
    ecosystem: str,
    registry: RegistryClient,
    popular: Set[str],
    where: str,
) -> List[Finding]:
    findings: List[Finding] = []

    # 1) 오타스쿼팅 휴리스틱(네트워크 불필요)
    near = nearest_popular(name, popular)
    if near and near[1] in (1, 2) and len(name) >= 4:
        findings.append(
            Finding(
                rule_id="VG-SLOP-002",
                title=f"유명 패키지와 매우 유사한 이름: '{name}'",
                severity=Severity.MEDIUM,
                category="supply-chain",
                file=where,
                line=1,
                snippet=name,
                explanation=(
                    f"'{name}' 은(는) 인기 패키지 '{near[0]}' 와 철자가 거의 같습니다"
                    f"(편집거리 {near[1]}). 오타스쿼팅(가짜 패키지) 가능성이 있습니다."
                ),
                fix=f"정말 '{near[0]}' 을(를) 쓰려던 것은 아닌지 철자를 확인하세요. 설치 전 패키지 공개자/다운로드 수를 검토하세요.",
                cwe="CWE-1357",
                metadata={"ecosystem": ecosystem, "suspect": name, "similar_to": near[0]},
            )
        )

    # 2) 레지스트리 존재 여부
    exists = registry.exists_pypi(name) if ecosystem == "pypi" else registry.exists_npm(name)
    if exists is False:
        findings.append(
            Finding(
                rule_id="VG-SLOP-001",
                title=f"레지스트리에 존재하지 않는 패키지: '{name}'",
                severity=Severity.HIGH,
                category="supply-chain",
                file=where,
                line=1,
                snippet=name,
                explanation=(
                    f"'{name}' 은(는) {ecosystem.upper()} 에 존재하지 않습니다. "
                    "AI 가 지어낸 이름일 수 있으며(슬롭스쿼팅), 공격자가 이 이름을 선점해 "
                    "악성 패키지를 올리면 설치 시 그대로 감염됩니다."
                ),
                fix=(
                    "이 import/의존성이 정말 필요한지 확인하세요. 실제로 쓰는 라이브러리의 "
                    "정확한 패키지명으로 교체하고, 출처가 불확실하면 절대 설치하지 마세요."
                ),
                cwe="CWE-1357",
                metadata={"ecosystem": ecosystem, "suspect": name},
            )
        )
    return findings


def check_project(root: str, offline: bool = False, timeout: float = 4.0) -> List[Finding]:
    """프로젝트 전체에서 의존성/ import 를 모아 슬롭스쿼팅·오타스쿼팅을 검사."""
    registry = RegistryClient(timeout=timeout, offline=offline)

    py_pkgs: Dict[str, str] = {}   # 패키지명 -> 발견 위치
    npm_pkgs: Dict[str, str] = {}

    def add(d: Dict[str, str], name: str, where: str):
        if name and name not in d:
            d[name] = where

    if os.path.isfile(root):
        files = [root]
    else:
        files = []
        for dp, dirs, fns in os.walk(root):
            dirs[:] = [x for x in dirs if x not in {".git", "node_modules", "venv", ".venv", "__pycache__"} and not x.startswith(".")]
            for fn in fns:
                files.append(os.path.join(dp, fn))

    for path in files:
        base = os.path.basename(path).lower()
        ext = os.path.splitext(path)[1].lower()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue

        if ext == ".py":
            for imp in extract_python_imports(text):
                if imp in _PY_STDLIB:
                    continue
                pkg = _PY_IMPORT_TO_PKG.get(imp, imp)
                add(py_pkgs, pkg, path)
        elif ext in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
            for imp in extract_js_imports(text):
                if imp in _NODE_BUILTINS:
                    continue
                add(npm_pkgs, imp, path)
        elif base in ("requirements.txt", "requirements-dev.txt") or base.startswith("requirements"):
            for name in parse_requirements_txt(text):
                add(py_pkgs, name, path)
        elif base == "package.json":
            for name in parse_package_json(text):
                add(npm_pkgs, name, path)

    findings: List[Finding] = []
    for name, where in sorted(py_pkgs.items()):
        findings.extend(_check_one(name, "pypi", registry, _POPULAR_PYPI, where))
    for name, where in sorted(npm_pkgs.items()):
        findings.extend(_check_one(name, "npm", registry, _POPULAR_NPM, where))
    return findings
