"""
Checks, for both specs:
  1. decode_block(bin) == block.json (header == header JSON, extrinsic == extrinsic JSON)
  2. encode_block(decode_block(bin)) == bin                  (byte-exact round trip)
  3. structural identity: block.bin == header_bytes || extrinsic.bin
  4. block.json["extrinsic"] == extrinsic.json (sidecar consistency)
"""

import json
import os
import unittest

from jam_impl.codec.header_codec import decode_header, spec_globals
from jam_impl.codec.extrinsic_codec import decode_extrinsic
from jam_impl.codec.block_codec import decode_block, encode_block
from jam_impl.models import Header

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load(spec: str, name: str) -> tuple[bytes, dict]:
    base = os.path.join(REPO, "jamtestvectors", "codec", spec, name)
    with open(f"{base}.bin", "rb") as f:
        b = f.read()
    with open(f"{base}.json") as f:
        j = json.load(f)
    return b, j


def norm(x):
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, str):
        return x[2:].lower() if x.startswith("0x") else x.lower()
    return x


def eq(a, w) -> bool:
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


class BlockRoundTrip(unittest.TestCase):

    def _check(self, spec: str):
        b, j = _load(spec, "block")
        ej = _load(spec, "extrinsic")[1]

        # -- boundary identity: header || extrinsic -------------------------
        ext_bytes = _load(spec, "extrinsic")[0]
        boundary = b.find(ext_bytes)
        self.assertGreater(boundary, 0, "extrinsic.bin is not a suffix of block.bin")

        # -- decode: models must match the sidecars ------------------------
        header, ext = decode_block(b, spec=spec)
        self.assertTrue(eq(model_to_dict(header), j["header"]), f"{spec}: header != json")
        self.assertTrue(eq(model_to_dict(ext), ej), f"{spec}: extrinsic != json")
        self.assertEqual(j["extrinsic"], ej, f"{spec}: block.json.extrinsic != extrinsic.json")

        # -- encode: byte-exact round trip ---------------------------------
        self.assertEqual(encode_block(header, ext, spec=spec), b, f"{spec}: encode_block != bin")

        # -- the models' own methods are the production paths --------------
        self.assertEqual(header.encode(), b[:boundary], f"{spec}: header.encode != bin prefix")
        self.assertEqual(ext.encode(spec=spec), b[boundary:], f"{spec}: ext.encode != bin suffix")

        # -- boundary is exactly the encoded header length ------------------
        self.assertEqual(boundary, len(header.encode()),
                         f"{spec}: header/extrinsic boundary != len(header.encode)")

        # -- decode_header on the prefix and decode_extrinsic on the suffix
        #    agree with decode_block -----------------------------------------
        with spec_globals(spec):
            self.assertEqual(decode_header(b[:boundary], spec=spec), header)
            self.assertEqual(decode_extrinsic(b[boundary:], spec=spec), ext)

    def test_tiny_block(self):
        self._check("tiny")

    def test_full_block(self):
        self._check("full")


if __name__ == "__main__":
    unittest.main()