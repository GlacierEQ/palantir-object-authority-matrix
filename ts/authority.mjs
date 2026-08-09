export function check(grants, actorRole, objectType, verb) {
  const key = `${actorRole}|${objectType}|${verb}`;
  const wild = `${actorRole}|*|${verb}`;
  if (grants.has(key) || grants.has(wild)) return { allowed: true, reason: "GRANT" };
  return { allowed: false, reason: "DEFAULT_DENY" };
}
