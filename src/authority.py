"""Object authority matrix — default-deny typed mutations."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum


def digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class Verb(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    LINK = "LINK"
    DELETE = "DELETE"


@dataclass(frozen=True)
class AuthDecision:
    allowed: bool
    reason: str
    fingerprint: str


class ObjectAuthorityMatrix:
    def __init__(self, grants: set[tuple[str, str, str]]):
        """grants: (actor_role, object_type, verb)"""
        self._grants = set(grants)

    def check(self, actor_role: str, object_type: str, verb: Verb) -> AuthDecision:
        key = (actor_role, object_type, verb.value)
        wild = (actor_role, "*", verb.value)
        if key in self._grants or wild in self._grants:
            body = {"ok": True, "key": list(key)}
            return AuthDecision(True, "GRANT", digest(body))
        body = {"ok": False, "key": list(key)}
        return AuthDecision(False, "DEFAULT_DENY", digest(body))
