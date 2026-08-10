from __future__ import annotations

import unittest

from src.authority import ObjectAuthorityMatrix, Verb


class AuthTests(unittest.TestCase):
    def test_default_deny(self):
        matrix = ObjectAuthorityMatrix({("analyst", "Aircraft", "READ")})
        decision = matrix.check("analyst", "Aircraft", Verb.WRITE)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "DEFAULT_DENY")
        self.assertIsNone(decision.matched_grant)

    def test_exact_grant_is_auditable(self):
        matrix = ObjectAuthorityMatrix({("ops", "Aircraft", "WRITE")})
        decision = matrix.check("ops", "Aircraft", Verb.WRITE)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_EXACT")
        self.assertEqual(decision.matched_grant, ("ops", "Aircraft", "WRITE"))

    def test_wildcard_grant_identifies_actual_matched_rule(self):
        matrix = ObjectAuthorityMatrix({("ops", "*", "READ")})
        decision = matrix.check("ops", "Aircraft", Verb.READ)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason, "GRANT_WILDCARD")
        self.assertEqual(decision.matched_grant, ("ops", "*", "READ"))

    def test_exact_and_wildcard_decisions_have_distinct_fingerprints(self):
        exact = ObjectAuthorityMatrix({("ops", "Aircraft", "READ")}).check(
            "ops", "Aircraft", Verb.READ
        )
        wildcard = ObjectAuthorityMatrix({("ops", "*", "READ")}).check(
            "ops", "Aircraft", Verb.READ
        )
        self.assertNotEqual(exact.fingerprint, wildcard.fingerprint)

    def test_unknown_object_does_not_inherit_exact_grant(self):
        matrix = ObjectAuthorityMatrix({("ops", "Aircraft", "WRITE")})
        self.assertFalse(matrix.check("ops", "Pilot", Verb.WRITE).allowed)

    def test_empty_actor_refuses(self):
        decision = ObjectAuthorityMatrix(set()).check("", "Aircraft", Verb.READ)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "INVALID_ACTOR_ROLE")

    def test_empty_object_refuses(self):
        decision = ObjectAuthorityMatrix(set()).check("ops", "", Verb.READ)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "INVALID_OBJECT_TYPE")

    def test_invalid_verb_refuses_without_throwing_open(self):
        decision = ObjectAuthorityMatrix(set()).check("ops", "Aircraft", "EXECUTE")  # type: ignore[arg-type]
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "INVALID_VERB")

    def test_invalid_grant_is_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            ObjectAuthorityMatrix({("ops", "Aircraft", "EXECUTE")})


if __name__ == "__main__":
    unittest.main()
