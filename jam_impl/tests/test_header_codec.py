"""
bin-vs-json: parse the .bin with decode_header, load the .json with
Header.from_dict, require equality. encode(parse(bin)) == bin is covered in
test_codec_roundtrip.py.
"""

import os
import unittest

from jam_impl.codec.header_codec import decode_header, load_vector
from jam_impl.models import Header

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _json_header(spec: str, name: str) -> Header:
    _, j = load_vector(spec, name)
    return Header.from_dict(j)


class BinMatchesJson(unittest.TestCase):
    """Every codec header vector: binary parse must equal JSON sidecar parse."""

    def test_tiny_header_0(self):
        b, j = load_vector("tiny", "header_0")
        self.assertEqual(decode_header(b, spec="tiny"), Header.from_dict(j))

    def test_tiny_header_1(self):
        b, j = load_vector("tiny", "header_1")
        self.assertEqual(decode_header(b, spec="tiny"), Header.from_dict(j))

    def test_full_header_0(self):
        b, j = load_vector("full", "header_0")
        self.assertEqual(decode_header(b, spec="full"), Header.from_dict(j))

    def test_full_header_1(self):
        b, j = load_vector("full", "header_1")
        self.assertEqual(decode_header(b, spec="full"), Header.from_dict(j))

    def test_all_codec_headers(self):
        """Catch new header fixtures automatically (both specs)."""
        total = 0
        for spec in ("tiny", "full"):
            d = os.path.join(REPO, "jamtestvectors", "codec", spec)
            for f in sorted(os.listdir(d)):
                if f.startswith("header") and f.endswith(".bin"):
                    name = f[:-4]
                    b, j = load_vector(spec, name)
                    self.assertEqual(
                        decode_header(b, spec=spec), Header.from_dict(j),
                        msg=f"{spec}/{name}",
                    )
                    total += 1
        self.assertGreaterEqual(total, 4)


class TinyHeader0Details(unittest.TestCase):
    """Spot-checks tying the model to the verified byte layout (100..549 marker)."""

    def setUp(self):
        b, _ = load_vector("tiny", "header_0")
        self.h = decode_header(b, spec="tiny")

    def test_fixed_front_fields(self):
        self.assertEqual(self.h.slot, 42)
        self.assertEqual(self.h.author_index, 3)
        for name in ("parent", "parent_state_root", "extrinsic_hash"):
            self.assertEqual(len(getattr(self.h, name)), 32, name)
        self.assertEqual(len(self.h.entropy_source), 96)
        self.assertEqual(len(self.h.seal), 96)

    def test_epoch_mark(self):
        em = self.h.epoch_mark
        self.assertIsNotNone(em)
        self.assertEqual(len(em.entropy), 32)
        self.assertEqual(len(em.tickets_entropy), 32)
        self.assertEqual(len(em.validators), 6)  # tiny validators-count
        for v in em.validators:
            self.assertEqual(len(v.bandersnatch), 32)
            self.assertEqual(len(v.ed25519), 32)

    def test_tickets_mark_absent(self):
        self.assertIsNone(self.h.tickets_mark)  # disc 0x00 in header_0

    def test_offenders_mark(self):
        # compact prefix 0x20 = 32 octets of key data -> exactly one 32-octet key
        self.assertEqual(len(self.h.offenders_mark), 1)
        self.assertEqual(len(self.h.offenders_mark[0]), 32)


class TinyHeader1Markers(unittest.TestCase):
    """header_1: epoch_mark absent, tickets_mark present with 12 tickets."""

    def setUp(self):
        self.h = _json_header("tiny", "header_1")

    def test_epoch_mark_absent(self):
        self.assertIsNone(self.h.epoch_mark)

    def test_tickets_mark_present(self):
        self.assertIsNotNone(self.h.tickets_mark)
        self.assertEqual(len(self.h.tickets_mark), 12)  # tiny epoch-length
        for t in self.h.tickets_mark:
            self.assertEqual(len(t.id), 32)
            self.assertTrue(0 <= t.attempt < 256)


if __name__ == "__main__":
    unittest.main()
