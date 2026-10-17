import unittest
import os
import json

from jam_impl.util import fisher_yates_shuffle_from_hash32

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SHUFFLE_JSON = os.path.join(REPO, "jamtestvectors", "shuffle", "shuffle_tests.json")

class ShuffleTests(unittest.TestCase):
    def test_all_shuffle_testcases(self):
        with open(SHUFFLE_JSON, "r") as f:
            tests = json.load(f)
        for test in tests:
            lst = list(range(test["input"]))
            entropy = bytes.fromhex(test["entropy"])
            expected = test["output"]
            output = fisher_yates_shuffle_from_hash32(lst, entropy)
            self.assertEqual(output, expected)            

if __name__ == "__main__":
    unittest.main()
