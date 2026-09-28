"""
Block codec: bytes <-> (models.Header, models.Extrinsic) (GP 4.2, C.16).

E(B) = E(header, E_T tickets, E_P preimages, E_G guarantees, E_A assurances,
         E_D disputes) — header first, then the extrinsic tuple in wire order.

Verified: block.bin = header_prefix || extrinsic.bin, with the header prefix
777 (tiny) / 65865 (full) octets and the extrinsic section byte-identical to
extrinsic.bin (itself the exact concatenation of the five component vectors).

The header is self-delimiting: its structure (fixed front + option markers +
fixed tail) determines its length, so a single Decoder can walk the whole
block: parse the header fields, note the cursor, then decode the extrinsic.

Spec note: several wire sizes are spec-dependent (validators-super-majority
in disputes, epoch-length in the tickets marker, bitfield octets in
assurances). decode_block and encode_block therefore wrap their work in
spec_globals(spec) — nested spec_globals are safe (save/restore).
"""

import jam_impl.util as util
from jam_impl.util import Decoder
from jam_impl.codec.header_codec import (
    decode_header, spec_globals,
    decode_epoch_marker, decode_winning_tickets_marker, decode_offenders_marker,
)
from jam_impl.codec.extrinsic_codec import decode_extrinsic, encode_extrinsic
from jam_impl.models import Header, Extrinsic


def header_length(b: bytes, spec: str = "full") -> int:
    """Length of the header prefix of a block buffer (self-delimiting scan)."""
    with spec_globals(spec):
        d = Decoder(b)
        d.hash32()                        # parent            H_P
        d.hash32()                        # parent_state_root H_R
        d.hash32()                        # extrinsic_hash    H_X
        d.u32()                           # timeslot          H_T
        decode_epoch_marker(d)            # [H_E] (consumes inside)
        decode_winning_tickets_marker(d)  # [H_W]
        d.u16()                           # author index      H_I
        d.take(96)                        # entropy source    H_V
        decode_offenders_marker(d)        # [H_O]
        d.take(96)                        # seal              H_S
        return d.o


def decode_block(b: bytes, spec: str = "full") -> tuple[Header, Extrinsic]:
    """Decode a full block: header then extrinsic (GP C.16)."""
    with spec_globals(spec):
        boundary = header_length(b, spec)
        header = decode_header(b[:boundary], spec=spec)
        ext = decode_extrinsic(b[boundary:], spec=spec)
        return header, ext


def encode_block(header: Header, ext: Extrinsic, spec: str = "full") -> bytes:
    """Encode a full block: header then extrinsic (GP C.16)."""
    with spec_globals(spec):
        return header.encode() + ext.encode(spec=spec)