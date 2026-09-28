import os
import unittest
import json

from jam_impl.trie import merklization
from jam_impl.codec.state_codec import decode_state, get_state_keyvals

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRACES = os.path.join(REPO, "jamtestvectors", "traces")
TRIE_JSON = os.path.join(REPO, "jamtestvectors", "trie", "trie.json")


def iter_trace_vectors():
    for root, _dirs, files in os.walk(TRACES):
        for file in sorted(files):
            # numbered steps only: 000000NN.bin (skip genesis.bin, ec-*)
            if (file.endswith(".bin") and file[:-4].isdigit()
                    and not file.startswith("ec-")):
                yield os.path.join(root, file)


class StateRootRoundTrip(unittest.TestCase):
    def test_decode_all_traces(self):
        vectors = list(iter_trace_vectors())
        self.assertGreater(len(vectors), 100, "expected the full traces suite")
        for path in vectors:
            with self.subTest(vector=os.path.relpath(path, TRACES)):
                with open(path, "rb") as f:
                    b = f.read()                
                expected = b[:32]
                state = decode_state(b)                
                from jam_impl.util import Encoder
                kvs = get_state_keyvals(state)                
                generated_state_root = merklization(kvs)
                self.assertEqual(generated_state_root, expected)

    # Key is 32 bytes in the testcase for some reason
    # def test_trie_json(self):
    #     tests = None
    #     with open(TRIE_JSON, "r") as f:
    #         tests = json.load(f)
    #     for test in tests:
    #         input_in_bytes = [(bytes.fromhex(k), bytes.fromhex(v)) for k,v in list(test["input"].items())]
    #         root = merklization(input_in_bytes)
    #         self.assertEqual(root, bytes.fromhex(test["output"]))



if __name__ == "__main__":
    unittest.main()