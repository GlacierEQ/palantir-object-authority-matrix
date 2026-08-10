import assert from "node:assert/strict";
import { check } from "./authority.mjs";

const grants = new Set([
  "analyst|Aircraft|READ",
  "ops|Aircraft|WRITE",
  "ops|*|READ",
]);

const denied = check(grants, "analyst", "Aircraft", "WRITE");
assert.equal(denied.allowed, false);
assert.equal(denied.reason, "DEFAULT_DENY");

const exact = check(grants, "ops", "Aircraft", "WRITE");
assert.equal(exact.allowed, true);
assert.equal(exact.reason, "GRANT_EXACT");
assert.equal(exact.matchedGrant, "ops|Aircraft|WRITE");

const wildcard = check(grants, "ops", "Pilot", "READ");
assert.equal(wildcard.allowed, true);
assert.equal(wildcard.reason, "GRANT_WILDCARD");
assert.equal(wildcard.matchedGrant, "ops|*|READ");
assert.notEqual(exact.fingerprint, wildcard.fingerprint);

assert.equal(check(grants, "", "Aircraft", "READ").reason, "INVALID_ACTOR_ROLE");
assert.equal(check(grants, "ops", "", "READ").reason, "INVALID_OBJECT_TYPE");
assert.equal(check(grants, "ops", "Aircraft", "EXECUTE").reason, "INVALID_VERB");

console.log("ok");
