"""Object authority matrix — explicit default-deny object-type/verb grants.

This module decides authorization only. It does not execute mutations, validate
causal lineage, authenticate external identities, or implement property-level
policy.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum


def digest(obj: object) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


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
    matched_grant: tuple[str, str, str] | None = None


class ObjectAuthorityMatrix:
    def __init__(self, grants: set[tuple[str, str, str]]):
        """Create a matrix from explicit ``(actor_role, object_type, verb)`` grants."""
        normalized: set[tuple[str, str, str]] = set()
        for grant in grants:
            if len(grant) != 3:
                raise ValueError("every grant must contain actor_role, object_type, verb")
            actor_role, object_type, verb = grant
            if not actor_role or not object_type or verb not in {item.value for item in Verb}:
                raise ValueError(f"invalid authority grant: {grant!r}")
            normalized.add((actor_role, object_type, verb))
        self._grants = frozenset(normalized)

    @staticmethod
    def _deny(reason: str, actor_role: str, object_type: str, verb: object) -> AuthDecision:
        verb_value = verb.value if isinstance(verb, Verb) else str(verb)
        body = {
            "ok": False,
            "reason": reason,
            "request": [actor_role, object_type, verb_value],
            "matched_grant": None,
        }
        return AuthDecision(False, reason, digest(body), None)

    def check(self, actor_role: str, object_type: str, verb: Verb) -> AuthDecision:
        if not actor_role:
            return self._deny("INVALID_ACTOR_ROLE", actor_role, object_type, verb)
        if not object_type:
            return self._deny("INVALID_OBJECT_TYPE", actor_role, object_type, verb)
        if not isinstance(verb, Verb):
            return self._deny("INVALID_VERB", actor_role, object_type, verb)

        exact = (actor_role, object_type, verb.value)
        wildcard = (actor_role, "*", verb.value)

        if exact in self._grants:
            body = {
                "ok": True,
                "reason": "GRANT_EXACT",
                "request": list(exact),
                "matched_grant": list(exact),
            }
            return AuthDecision(True, "GRANT_EXACT", digest(body), exact)

        if wildcard in self._grants:
            body = {
                "ok": True,
                "reason": "GRANT_WILDCARD",
                "request": list(exact),
                "matched_grant": list(wildcard),
            }
            return AuthDecision(True, "GRANT_WILDCARD", digest(body), wildcard)

        return self._deny("DEFAULT_DENY", actor_role, object_type, verb)
