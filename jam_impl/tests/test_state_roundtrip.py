"""
State codec round-trip tests against the official jamtestvectors traces.

For every numbered step vector in traces/ (each .bin is one TraceStep:
pre_state, block, post_state):
  1. decode_state(bin) parses the embedded pre-state          (parse)
  2. semantic State -> get_state_keyvals() reproduces the wire byte-exact
     (keys RE-DERIVED from components via key()/encode(), not cloned;
      entries key-sorted, matching the RawState wire order)

Form-3 entries (service storage/preimages/requests) are parked in
`State.undecoded` — not decoded yet, but never dropped.
"""

import os
import unittest

from jam_impl.util import Decoder
from jam_impl.codec.state_codec import decode_state, get_state_keyvals
from jam_impl.models.State import RegistrarState, ServiceDefinition

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TRACES = os.path.join(REPO, "jamtestvectors", "traces")


def iter_trace_vectors():
    for root, _dirs, files in os.walk(TRACES):
        for file in sorted(files):
            # numbered steps only: 000000NN.bin (skip genesis.bin, ec-*)
            if (file.endswith(".bin") and file[:-4].isdigit()
                    and not file.startswith("ec-")):
                yield os.path.join(root, file)


def raw_state_bytes(b: bytes) -> bytes:
    """Slice the embedded pre-state's wire span (root + keyvals) out of a
    TraceStep .bin."""
    d = Decoder(b)
    d.take(32)                      # state root
    n = d.decode_compact()
    for _ in range(n):
        d.take(31)                  # key
        d.blob()                    # ↕-prefixed value
    return b[32:d.o]


class StateRoundTrip(unittest.TestCase):
    """bin -> semantic State -> re-derived keyvals -> bin, byte-exact."""

    def test_decode_all_traces(self):
        """Every step .bin decodes; the semantic State re-encodes byte-exact
        (keys derived from the components, not cloned from the wire)."""
        vectors = list(iter_trace_vectors())
        self.assertGreater(len(vectors), 100, "expected the full traces suite")
        for path in vectors:
            with self.subTest(vector=os.path.relpath(path, TRACES)):
                with open(path, "rb") as f:
                    b = f.read()
                state = decode_state(b)
                expected = raw_state_bytes(b)
                from jam_impl.util import Encoder
                kvs = get_state_keyvals(state)
                e = Encoder()
                e.compact(len(kvs))
                for key, value in kvs:
                    e.raw(key)
                    e.compact(len(value))
                    e.raw(value)
                self.assertEqual(e.finish(), expected)

    def test_keys_are_derived_not_cloned(self):
        """The semantic State carries no raw keys: every keyval comes from a
        component's key()/encode() pair."""
        path = os.path.join(TRACES, "storage", "00000002.bin")
        with open(path, "rb") as f:
            state = decode_state(f.read())
        # the genesis account (service 0) round-trips its key
        account = state.accounts[0]
        self.assertIsInstance(account.definition, ServiceDefinition)
        self.assertEqual(
            account.definition.key().hex(),
            "ff" + "00" * 30,  # C(255, s=0): one constant byte + 31 octets total
        )
        # form-2 service id is read from ODD key positions (GP D.1): the old
        # decoder folded the constant 255 into the id — regression guard
        self.assertEqual(account.definition.service_index, 0)

    def test_registrar_matches_known_compact_layout(self):
        """C(13) statistics decode as compact naturals (the 0.7.2 wire)."""
        path = os.path.join(TRACES, "fuzzy", "00000026.bin")
        with open(path, "rb") as f:
            state = decode_state(f.read())
        reg = state.registrar
        self.assertIsInstance(reg, RegistrarState)
        self.assertEqual(len(reg.vals_curr_stats), 6)   # tiny: 6 validators
        self.assertEqual(len(reg.vals_last_stats), 6)
        self.assertEqual(len(reg.cores_stats), 2)        # tiny: 2 cores
        self.assertEqual(len(reg.services_stats), 6)
        # core 1's gas_used is 105391 — hand-verified when the compact layout
        # was fixed (fixed-width decoding misread it as count=100 services).
        self.assertEqual(reg.cores_stats[1].gas_used, 105391)


class StrictSetSemantics(unittest.TestCase):
    """GP sets must reject duplicates; dataclass members compare field-wise."""

    def test_rejects_duplicates(self):
        from jam_impl.util import StrictSet
        with self.assertRaises(ValueError):
            StrictSet([b"\x01" * 32, b"\x01" * 32])
        # and accepts distinct members
        s = StrictSet([b"\x01" * 32, b"\x02" * 32])
        self.assertEqual(len(s), 2)

    def test_validator_data_compares_field_wise(self):
        from jam_impl.util import StrictSet
        from jam_impl.models.State import ValidatorData
        a = ValidatorData(bandersnatch=b"\x01" * 32, ed25519=b"\x02" * 32,
                          bls=b"\x03" * 144, metadata=b"\x04" * 128)
        # full duplicate (every field equal) is rejected by a StrictSet
        a2 = ValidatorData(bandersnatch=b"\x01" * 32, ed25519=b"\x02" * 32,
                           bls=b"\x03" * 144, metadata=b"\x04" * 128)
        with self.assertRaises(ValueError):
            StrictSet([a, a2])
        # same keys, different opaque metadata: a DISTINCT member (GP C.11
        # dedups on the full element encoding, not on the key triple)
        b = ValidatorData(bandersnatch=b"\x01" * 32, ed25519=b"\x02" * 32,
                          bls=b"\x03" * 144, metadata=b"\x99" * 128)
        s = StrictSet([a, b])
        self.assertEqual(len(s), 2)
        self.assertIn(b, s)


if __name__ == "__main__":
    unittest.main()