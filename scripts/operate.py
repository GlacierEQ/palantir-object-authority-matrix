#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from authority import ObjectAuthorityMatrix, Verb

def main() -> int:
    m = ObjectAuthorityMatrix({("ops", "Aircraft", "WRITE"), ("ops", "Aircraft", "READ")})
    allow = m.check("ops", "Aircraft", Verb.WRITE)
    deny = m.check("ops", "Aircraft", Verb.DELETE)
    out = {"write_allowed": allow.allowed, "delete_allowed": deny.allowed, "deny_reason": deny.reason,
           "ok": allow.allowed and (not deny.allowed) and deny.reason == "DEFAULT_DENY"}
    print(json.dumps(out, sort_keys=True))
    return 0 if out["ok"] else 1
if __name__ == "__main__":
    raise SystemExit(main())
