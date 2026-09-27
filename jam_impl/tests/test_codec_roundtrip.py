"""
For every codec vector of every kind (both specs):
  1. decode(bin) models == json sidecar          (semantic fidelity)
  2. encode(decode(bin)) == bin                  (byte-exact round trip)
"""

import os
import unittest

from jam_impl.util import Decoder
from jam_impl.codec.header_codec import (
    decode_header, encode_header, load_vector, spec_globals,
)
from jam_impl.codec.extrinsic_codec import (
    decode_extrinsic, encode_extrinsic,
    decode_tickets, decode_preimages, decode_guarantees,
    decode_assurances, decode_disputes,
    encode_tickets, encode_preimages, encode_guarantees,
    encode_assurances, encode_disputes,
)
from jam_impl.models import Header, Extrinsic, hex_to_bytes

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# normalization: bytes -> hex, hex strings lowercased without 0x, ints as-is
def norm(x):
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, str):
        return x[2:].lower() if x.startswith("0x") else x.lower()
    return x


def eq(a, w) -> bool:
    """Typed model vs JSON sidecar comparison, name-by-name."""
    if isinstance(w, dict):
        return isinstance(a, dict) and all(eq(a.get(k), v) for k, v in w.items())
    if isinstance(w, list):
        return isinstance(a, list) and len(a) == len(w) and all(eq(x, y) for x, y in zip(a, w))
    return norm(a) == norm(w)


def model_to_dict(x):
    """Typed model -> nested plain dict with hex strings (mirrors the sidecar).

    ResultItem is special-cased: its WorkResult tag + ResultOk payload
    collapse into the sidecar's single {"ok": ...} / {"panic": null}
    outcome object (GP C.34 wire: tag then optional ↕blob).
    """
    from jam_impl.models.Extrinsic import ResultItem, WorkResult
    if isinstance(x, (list, tuple)):
        return [model_to_dict(v) for v in x]
    if isinstance(x, ResultItem):
        d = {k: model_to_dict(v) for k, v in x.__dict__.items()
             if k not in ("result", "result_payload")}
        tag = x.result.value if isinstance(x.result, WorkResult) else int(x.result)
        if tag == WorkResult.OK.value and x.result_payload is not None:
            d["result"] = {"ok": "0x" + x.result_payload.ok.hex()}
        else:
            names = {
                1: "panic", 2: "out_of_gas", 3: "invalid_exports_count",
                4: "digest_size_limit_exceeded", 5: "BAD", 6: "BIG",
            }
            d["result"] = {names.get(tag, str(tag)): None}
        return d
    if hasattr(x, "__dataclass_fields__"):
        return {k: model_to_dict(v) for k, v in x.__dict__.items()}
    if isinstance(x, (bytes, bytearray)):
        return "0x" + x.hex()
    return x


DECODE_MAP = {
    "tickets_extrinsic": decode_tickets,
    "preimages_extrinsic": decode_preimages,
    "guarantees_extrinsic": decode_guarantees,
    "assurances_extrinsic": decode_assurances,
    "disputes_extrinsic": decode_disputes,
}
ENCODE_MAP = {
    "tickets_extrinsic": encode_tickets,
    "preimages_extrinsic": encode_preimages,
    "guarantees_extrinsic": encode_guarantees,
    "assurances_extrinsic": encode_assurances,
    "disputes_extrinsic": encode_disputes,
}

COMPONENT_VECTORS = list(DECODE_MAP)


class HeaderRoundTrip(unittest.TestCase):
    """bin -> Header -> bytes -> bin, byte-exact; bin fields == json fields."""

    def _check(self, spec: str, name: str):
        b, j = load_vector(spec, name)
        h = decode_header(b, spec=spec)
        self.assertTrue(eq(model_to_dict(h), j), f"{spec}/{name}: model != json")
        self.assertEqual(encode_header(h), b, f"{spec}/{name}: encode(parse(bin)) != bin")

    def test_tiny_header_0(self):
        self._check("tiny", "header_0")

    def test_tiny_header_1(self):
        self._check("tiny", "header_1")

    def test_full_header_0(self):
        self._check("full", "header_0")

    def test_full_header_1(self):
        self._check("full", "header_1")


class ExtrinsicTupleRoundTrip(unittest.TestCase):
    """bin -> models -> bytes -> bin for the whole extrinsic tuple (GP C.16)."""

    def _check(self, spec: str, name: str):
        b, j = load_vector(spec, name)
        with spec_globals(spec):
            ext = decode_extrinsic(b, spec=spec)
            self.assertTrue(eq(model_to_dict(ext), j), f"{spec}/{name}: model != json")
            self.assertEqual(encode_extrinsic(ext), b, f"{spec}/{name}: encode != bin")

    def test_tiny_extrinsic(self):
        self._check("tiny", "extrinsic")

    def test_full_extrinsic(self):
        self._check("full", "extrinsic")


class ComponentRoundTrip(unittest.TestCase):
    """Individual component vectors, both specs."""

    def _check(self, spec: str, name: str):
        b, j = load_vector(spec, name)
        with spec_globals(spec):
            value = DECODE_MAP[name](Decoder(b))
            self.assertTrue(eq(model_to_dict(value), j), f"{spec}/{name}: model != json")
            self.assertEqual(ENCODE_MAP[name](value), b, f"{spec}/{name}: encode != bin")

    def test_tiny_components(self):
        for name in COMPONENT_VECTORS:
            with self.subTest(vector=name):
                self._check("tiny", name)

    def test_full_components(self):
        for name in COMPONENT_VECTORS:
            with self.subTest(vector=name):
                self._check("full", name)


if __name__ == "__main__":
    unittest.main()