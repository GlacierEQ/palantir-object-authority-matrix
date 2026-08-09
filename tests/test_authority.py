from __future__ import annotations
import unittest
from src.authority import ObjectAuthorityMatrix, Verb

class AuthTests(unittest.TestCase):
    def test_default_deny(self):
        m = ObjectAuthorityMatrix({("analyst", "Aircraft", "READ")})
        d = m.check("analyst", "Aircraft", Verb.WRITE)
        self.assertFalse(d.allowed)
        self.assertEqual(d.reason, "DEFAULT_DENY")

    def test_grant(self):
        m = ObjectAuthorityMatrix({("ops", "Aircraft", "WRITE")})
        self.assertTrue(m.check("ops", "Aircraft", Verb.WRITE).allowed)

if __name__ == "__main__":
    unittest.main()
