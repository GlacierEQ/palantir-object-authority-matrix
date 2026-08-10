import { createHash } from "node:crypto";

const VERBS = new Set(["READ", "WRITE", "LINK", "DELETE"]);

function fingerprint(body) {
  return createHash("sha256").update(JSON.stringify(body)).digest("hex");
}

function deny(reason, actorRole, objectType, verb) {
  const body = {
    ok: false,
    reason,
    request: [actorRole, objectType, String(verb)],
    matched_grant: null,
  };
  return { allowed: false, reason, matchedGrant: null, fingerprint: fingerprint(body) };
}

export function check(grants, actorRole, objectType, verb) {
  if (!actorRole) return deny("INVALID_ACTOR_ROLE", actorRole, objectType, verb);
  if (!objectType) return deny("INVALID_OBJECT_TYPE", actorRole, objectType, verb);
  if (!VERBS.has(verb)) return deny("INVALID_VERB", actorRole, objectType, verb);

  const exact = `${actorRole}|${objectType}|${verb}`;
  const wildcard = `${actorRole}|*|${verb}`;

  if (grants.has(exact)) {
    const body = {
      ok: true,
      reason: "GRANT_EXACT",
      request: [actorRole, objectType, verb],
      matched_grant: [actorRole, objectType, verb],
    };
    return {
      allowed: true,
      reason: "GRANT_EXACT",
      matchedGrant: exact,
      fingerprint: fingerprint(body),
    };
  }

  if (grants.has(wildcard)) {
    const body = {
      ok: true,
      reason: "GRANT_WILDCARD",
      request: [actorRole, objectType, verb],
      matched_grant: [actorRole, "*", verb],
    };
    return {
      allowed: true,
      reason: "GRANT_WILDCARD",
      matchedGrant: wildcard,
      fingerprint: fingerprint(body),
    };
  }

  return deny("DEFAULT_DENY", actorRole, objectType, verb);
}
