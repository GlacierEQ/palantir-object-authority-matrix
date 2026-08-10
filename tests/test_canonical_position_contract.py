from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path: str):
    return json.loads((ROOT / path).read_text())


CANONICAL = load("machine/canonical-position.json")
CAPABILITIES = load("machine/capabilities.json")
TARGET = load("machine/target-contract.json")


class CanonicalPositionContractTests(unittest.TestCase):
    def test_repository_owns_only_object_type_verb_authorization(self):
        self.assertEqual(CANONICAL["role"], "CANONICAL_SPECIALIST")
        self.assertEqual(CANONICAL["owns"], "object_type_verb_authorization")
        self.assertIn("property-level authorization", CANONICAL["does_not_own"])
        self.assertIn("causal action provenance", CANONICAL["does_not_own"])
        self.assertIn("ontology mutation/writeback execution", CANONICAL["does_not_own"])

    def test_sibling_relationships_do_not_claim_integration(self):
        for edge in CANONICAL["relationships"]:
            self.assertFalse(edge["integration_exercised"])

    def test_capabilities_are_repository_native(self):
        capabilities = set(CAPABILITIES["capabilities"])
        self.assertNotIn("hyper-scaling", capabilities)
        self.assertIn("default_deny_object_verb_authority", capabilities)
        self.assertIn("wildcard_grant_audit_binding", capabilities)
        self.assertIn("deterministic_authorization_fingerprint", capabilities)

    def test_target_contract_is_valid_and_waits_for_exact_head_proof(self):
        self.assertEqual(TARGET["current"]["state"], "PROMOTED")
        self.assertTrue(TARGET["current"]["canonical_position_pending_exact_head_proof"])
        self.assertTrue(TARGET["promotion"]["require_exact_source_sha"])
        self.assertEqual(TARGET["promotion"]["next_gate"], "CANONICAL_POSITION_RESOLVED")

    def test_truth_boundary_is_narrow(self):
        boundary = CAPABILITIES["truth_boundary"]
        self.assertIn("does not implement property-level policy", boundary)
        self.assertIn("authenticate external identities", boundary)
        self.assertIn("execute/write back mutations", boundary)


if __name__ == "__main__":
    unittest.main()
