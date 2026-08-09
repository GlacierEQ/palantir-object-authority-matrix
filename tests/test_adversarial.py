from __future__ import annotations
import unittest
from src.authority import ObjectAuthorityMatrix, Verb

class Adv(unittest.TestCase):
    def test_default_deny_unknown_type(self):
        m = ObjectAuthorityMatrix({("ops", "Aircraft", "WRITE")})
        self.assertFalse(m.check("ops", "Ship", Verb.WRITE).allowed)
    def test_read_not_imply_write(self):
        m = ObjectAuthorityMatrix({("ops", "Aircraft", "READ")})
        self.assertFalse(m.check("ops", "Aircraft", Verb.WRITE).allowed)
    def test_wildcard_type(self):
        m = ObjectAuthorityMatrix({("admin", "*", "READ")})
        self.assertTrue(m.check("admin", "Anything", Verb.READ).allowed)

