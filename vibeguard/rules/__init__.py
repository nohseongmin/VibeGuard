"""규칙 패키지. import 시 모든 규칙 모듈을 불러와 전역 레지스트리에 등록한다."""

from __future__ import annotations

from . import crypto, dangerous, golang, injection, php, secrets, web  # noqa: F401
from .base import Rule, all_rules, register

__all__ = ["Rule", "all_rules", "register"]
