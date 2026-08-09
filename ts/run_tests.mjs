import { check } from "./authority.mjs";
import assert from "node:assert/strict";
const g = new Set(["analyst|Aircraft|READ", "ops|Aircraft|WRITE"]);
assert.equal(check(g, "analyst", "Aircraft", "WRITE").allowed, false);
assert.equal(check(g, "ops", "Aircraft", "WRITE").allowed, true);
console.log("ok");
