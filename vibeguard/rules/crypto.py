"""약한 암호화/해시/난수 사용 탐지."""

from __future__ import annotations

import re

from ..finding import Severity
from .base import make_regex_rule

PY = (".py",)
JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")

# 비밀번호 해시에 MD5/SHA1
make_regex_rule(
    "VG-CRYPTO-001",
    "약한 해시(MD5/SHA1) 사용",
    Severity.MEDIUM,
    "crypto",
    r"\bhashlib\.(?:md5|sha1)\s*\(",
    "MD5/SHA1 은 충돌·역산이 가능해 비밀번호 해싱이나 무결성 검증에 부적합합니다.",
    "비밀번호는 bcrypt/argon2/scrypt 를 쓰세요. 무결성에는 SHA-256 이상을 사용하세요.",
    cwe="CWE-327",
    extensions=PY,
)

make_regex_rule(
    "VG-CRYPTO-002",
    "약한 해시(MD5/SHA1) 사용",
    Severity.MEDIUM,
    "crypto",
    r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
    "MD5/SHA1 은 비밀번호/무결성 용도로 안전하지 않습니다.",
    "비밀번호는 bcrypt/argon2 를, 무결성에는 SHA-256 이상을 사용하세요.",
    cwe="CWE-327",
    extensions=JS,
)

# 예측 가능한 난수로 토큰/비밀번호 생성
make_regex_rule(
    "VG-CRYPTO-003",
    "보안 토큰에 예측 가능한 난수(random) 사용",
    Severity.MEDIUM,
    "crypto",
    r"\brandom\.(?:random|randint|choice|randrange)\s*\(",
    "random 모듈은 예측 가능합니다. 토큰·비밀번호·OTP 생성에 쓰면 추측당할 수 있습니다.",
    "보안 값 생성에는 secrets 모듈(secrets.token_hex, secrets.choice)을 사용하세요.",
    cwe="CWE-330",
    extensions=PY,
)

make_regex_rule(
    "VG-CRYPTO-004",
    "보안 토큰에 Math.random() 사용",
    Severity.MEDIUM,
    "crypto",
    r"Math\.random\s*\(\s*\)",
    "Math.random() 은 암호학적으로 안전하지 않습니다. 토큰·세션ID 생성에 부적합합니다.",
    "crypto.randomBytes() 또는 crypto.randomUUID() / Web Crypto 의 getRandomValues() 를 사용하세요.",
    cwe="CWE-330",
    extensions=JS,
)

# DES / ECB 모드
make_regex_rule(
    "VG-CRYPTO-005",
    "취약한 암호 알고리즘/모드(DES, ECB) 사용",
    Severity.MEDIUM,
    "crypto",
    r"\b(?:DES\.new|MODE_ECB|algorithms\.(?:DES|Blowfish|ARC4))\b",  # vibeguard: ignore
    "DES/ECB/RC4 등은 현대 기준으로 안전하지 않은 암호 방식입니다.",
    "AES-GCM 같은 인증 암호(AEAD)와 안전한 모드를 사용하세요.",
    cwe="CWE-327",
    extensions=PY,
)
