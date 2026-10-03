"""
Header codec: bytes <-> models.Header (GP C.22–C.25), driven by the codec vectors.

Layout verified byte-exact against jamtestvectors/codec/{tiny,full}/header_0
and header_1 and their JSON sidecars (GP 0.7.2 vector wire: no length prefix
on epoch-marker validators, seal last; GP 0.8.0 adds a ↕ prefix — not
byte-compatible with these fixtures).

The Decoder (util.py) is spec-parameterized through util.py's module globals
(NUM_VALIDATORS_IN_EPOCH_MARK, LENGTH_OF_EPOCH_IN_TIMESLOTS); spec_globals()
swaps them for the duration of a parse/encode.
"""

import json
import os
from contextlib import contextmanager

import jam_impl.util as util
from jam_impl.util import Decoder, Encoder
from jam_impl.models import Header, EpochMarker, TicketBody, ValidatorKeys, hex_to_bytes

# Spec constants — jamtestvectors/lib/{tiny,full}-const.asn,
# jam-types-py jam_types/spec.py, and util.py's own globals.
VALIDATORS_COUNT = {"tiny": 6, "full": 1023}   # validators-count
EPOCH_LENGTH = {"tiny": 12, "full": 600}       # epoch-length

# jamtestvectors/codec/<spec>/<name>.{bin,json} — repo root is this file's
# parent's parent's parent (jam_impl/codec/header_codec.py -> repo root).
VECTOR_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "jamtestvectors", "codec",
)


def vector_path(spec: str, name: str, ext: str = "bin") -> str:
    return os.path.join(VECTOR_DIR, spec, f"{name}.{ext}")


def load_vector(spec: str, name: str) -> tuple[bytes, dict]:
    """Return (binary vector, JSON sidecar dict) for a codec vector."""
    with open(vector_path(spec, name, "bin"), "rb") as f:
        b = f.read()
    with open(vector_path(spec, name, "json")) as f:
        j = json.load(f)
    return b, j


@contextmanager
def spec_globals(spec: str):
    """Point util.py's spec constants at the chosen spec, then restore.

    'full' is util.py's default; 'tiny' switches to 6 validators / 12 tickets
    per epoch. No Decoder code is touched. Nested use is safe (save/restore).
    """
    saved = (util.NUM_VALIDATORS_IN_EPOCH_MARK, util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
    util.NUM_VALIDATORS_IN_EPOCH_MARK = VALIDATORS_COUNT[spec]
    util.LENGTH_OF_EPOCH_IN_TIMESLOTS = EPOCH_LENGTH[spec]
    try:
        yield
    finally:
        util.NUM_VALIDATORS_IN_EPOCH_MARK, util.LENGTH_OF_EPOCH_IN_TIMESLOTS = saved


# ---------------------------------------------------------------------------
# Header markers (GP 6.28 epoch mark H_E, 6.29 winning-tickets mark H_W,
# offenders mark H_O) — 0.7.2 wire shapes, as encoded by the 0.7.1 vectors.
# These were Reader methods; they belong to the header, so they live here.
# ---------------------------------------------------------------------------

def decode_epoch_marker(d: Decoder) -> EpochMarker | None:
    """H_E = ¿(eta0, eta1, validators). 0.7.2 wire: NO length prefix on the
    V×(bandersnatch, ed25519) key pairs (GP 0.8.0 C.25 adds ↕k)."""
    if d.u8() == 0:
        return None
    entropy = d.hash32()
    tickets_entropy = d.hash32()
    validators = [
        ValidatorKeys(bandersnatch=d.hash32(), ed25519=d.hash32())
        for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)
    ]
    return EpochMarker(entropy=entropy, tickets_entropy=tickets_entropy, validators=validators)


def encode_epoch_marker(epoch_mark: EpochMarker | None) -> bytes:
    if epoch_mark is None:
        return b"\x00"
    e = Encoder().u8(1).raw(epoch_mark.entropy).raw(epoch_mark.tickets_entropy)
    for validator in epoch_mark.validators:
        e.raw(validator.bandersnatch).raw(validator.ed25519)
    return e.finish()


def decode_winning_tickets_marker(d: Decoder) -> list[TicketBody] | None:
    """H_W = ¿(epoch-length × (id 32 + attempt E1)) — GP 6.29, C.33."""
    if d.u8() == 0:
        return None
    return [
        TicketBody(id=d.hash32(), attempt=d.u8())
        for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
    ]


def encode_tickets_marker(winning_tickets: list[TicketBody] | None) -> bytes:
    if winning_tickets is None:
        return b"\x00"
    e = Encoder().u8(1)
    for ticket in winning_tickets:
        e.raw(ticket.id).u8(ticket.attempt)
    return e.finish()


def decode_offenders_marker(d: Decoder) -> list[bytes]:
    """H_O = ↕(n × 32-octet Ed25519 keys) — GP 5.11."""
    n = d.decode_compact()
    return [d.hash32() for _ in range(n)]


def encode_offenders_marker(offenders_mark: list[bytes]) -> bytes:
    e = Encoder().compact(len(offenders_mark))
    for key in offenders_mark:
        e.raw(key)
    return e.finish()


def decode_header(b: bytes, spec: str = "full") -> Header:
    """Decode a serialized header (GP C.22–C.25; 0.7.1 vector layout).

    Wire order: parent(32) parent_state_root(32) extrinsic_hash(32)
    slot(4) [epoch_mark] [tickets_mark] author_index(2) entropy_source(96)
    [offenders_mark] seal(96).
    """
    with spec_globals(spec):
        d = Decoder(b)
        h = Header(
            parent=d.hash32(),
            parent_state_root=d.hash32(),
            extrinsic_hash=d.hash32(),
            slot=d.u32(),
            epoch_mark=decode_epoch_marker(d),
            tickets_mark=decode_winning_tickets_marker(d),
            author_index=d.u16(),
            entropy_source=d.take(96),
            offenders_mark=decode_offenders_marker(d),
            seal=d.take(96),
        )
        d.finish()
        return h

def encode_header_unsigned(h: Header) -> bytes:
    e = Encoder()
    e.raw(h.parent).raw(h.parent_state_root).raw(h.extrinsic_hash)
    e.u32(h.slot)
    if h.epoch_mark is None:
        e.u8(0)
    else:
        e.u8(1).raw(h.epoch_mark.entropy).raw(h.epoch_mark.tickets_entropy)
        for validator in h.epoch_mark.validators:
            e.raw(validator.bandersnatch).raw(validator.ed25519)
    if h.tickets_mark is None:
        e.u8(0)
    else:
        e.u8(1)
        for ticket in h.tickets_mark:
            e.raw(ticket.id).u8(ticket.attempt)
    e.u16(h.author_index)
    e.raw(h.entropy_source)
    e.compact(len(h.offenders_mark))
    for key in h.offenders_mark:
        e.raw(key)
    return e.finish()

def encode_header(h: Header) -> bytes:
    """Encode a Header back to wire bytes (inverse of decode_header)."""
    e = Encoder()
    e.raw(encode_header_unsigned(h))
    e.raw(h.seal)
    return e.finish()