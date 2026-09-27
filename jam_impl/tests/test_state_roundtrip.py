"""
For every numbered step vector in traces/ (each .bin is one TraceStep:
pre_state, block, post_state - decode_state parses the embedded pre-state):
  1. decode_state(bin) consumes the pre-state without error            (parse)
  2. every DECODED component re-encodes to its original value bytes   (round trip)

Form-3 entries (service storage/preimages/requests) are not
decoded yet
"""

import os
import unittest

from jam_impl.util import encode_compact
from jam_impl.codec.state_codec import decode_state, encode_state_entry
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


class StateRoundTrip(unittest.TestCase):
    """bin -> State -> component bytes -> bin, byte-exact per entry."""

    def test_decode_all_traces(self):
        """Every step .bin decodes; every decoded entry round-trips byte-exact."""
        vectors = list(iter_trace_vectors())
        self.assertGreater(len(vectors), 100, "expected the full traces suite")
        for path in vectors:
            with self.subTest(vector=os.path.relpath(path, TRACES)):
                with open(path, "rb") as f:
                    b = f.read()
                state = decode_state(b)
                self.assertGreater(len(state.entries), 0, "empty pre-state")
                for entry in state.entries:
                    if entry.component is None:
                        continue  # form-3: not decoded yet (by design)
                    expected = entry.key + encode_compact(len(entry.value)) + entry.value
                    self.assertEqual(
                        encode_state_entry(entry), expected,
                        f"round trip failed for key {entry.key.hex()}",
                    )

    def test_registrar_matches_known_compact_layout(self):
        """C(13) statistics decode as compact naturals (the 0.7.2 wire)."""
        path = os.path.join(TRACES, "fuzzy", "00000026.bin")
        with open(path, "rb") as f:
            state = decode_state(f.read())
        registrar = [e.component for e in state.entries
                     if isinstance(e.component, RegistrarState)]
        self.assertEqual(len(registrar), 1)
        reg = registrar[0]
        self.assertEqual(len(reg.vals_curr_stats), 6)   # tiny: 6 validators
        self.assertEqual(len(reg.vals_last_stats), 6)
        self.assertEqual(len(reg.cores_stats), 2)        # tiny: 2 cores
        self.assertEqual(len(reg.services_stats), 6)
        # core 1's gas_used is 105391 — hand-verified when the compact layout
        # was fixed (fixed-width decoding misread it as count=100 services).
        self.assertEqual(reg.cores_stats[1].gas_used, 105391)

    def test_service_definitions_decode(self):
        """Form-2 keys decode into ServiceDefinition models."""
        # step 2's pre-state == step 1's post-state, which carries a service
        # account header (C(255, 0)) — verified in the storage suite JSONs.
        path = os.path.join(TRACES, "storage", "00000002.bin")
        with open(path, "rb") as f:
            state = decode_state(f.read())
        services = [e.component for e in state.entries
                    if isinstance(e.component, ServiceDefinition)]
        self.assertGreater(len(services), 0, "storage step 2 pre-state has a service")
        for service in services:
            self.assertEqual(len(service.data.service.code_hash), 32)


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