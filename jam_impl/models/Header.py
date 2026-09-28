"""
JAM Header model — GP 5.1 (H), 6.28 (H_E), 6.29 (H_W), C.22–C.25.

Field spellings follow the codec test-vector JSON sidecars
(jamtestvectors/codec/*/header_*.json) so that the vectors, the codec
(header_codec.py) and this model share one vocabulary.
GP symbols live in the comments. All byte fields are raw `bytes`;
hex strings only at the JSON/printing edge.

Field order below is the wire/serialization order (GP C.23):
P, R, X, T, E, W, I, V, O, S — not the GP 5.1 tuple order.
"""

from dataclasses import dataclass

from jam_impl.util import Encoder


def hex_to_bytes(s: str) -> bytes:
    """Hex string -> bytes; tolerates an optional 0x prefix."""
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


# The header codec's encoder, resolved lazily like the other model methods
# (header_codec imports these models at load, so a top-level import cycles).
def _codec(name):
    import jam_impl.codec.header_codec as hc
    return getattr(hc, name)


@dataclass
class ValidatorKeys:  # EpochMarkValidatorKeys (GP 6.28; jam-types.asn:777)
    bandersnatch: bytes  # 32-octet compressed Bandersnatch public key
    ed25519: bytes       # 32-octet Ed25519 public key


@dataclass
class EpochMarker:  # H_E (GP 6.28); present iff the block opens a new epoch
    entropy: bytes           # eta0, 32 octets
    tickets_entropy: bytes   # eta1, 32 octets
    # Exactly V entries (6 tiny / 1023 full) — fixed size, NOT length-prefixed
    # on the 0.7.1 vector wire; GP 0.8.0 C.25 adds a compact length prefix.
    validators: list[ValidatorKeys]


@dataclass
class TicketBody:  # TicketBody (GP 6.6, C.33; jam-types.asn)
    id: bytes      # y, 32-octet ticket identifier (ring-VRF output)
    attempt: int   # e, 1-octet attempt counter (E1)


@dataclass
class Header:  # H = (H_P, H_R, H_X, H_T, H_E, H_W, H_O, H_I, H_V, H_S), GP 5.1
    parent: bytes                          # H_P = H(E(parent header)), 32
    parent_state_root: bytes               # H_R, 32
    extrinsic_hash: bytes                  # H_X, 32
    slot: int                              # H_T, E4 little-endian
    epoch_mark: EpochMarker | None         # H_E
    tickets_mark: list[TicketBody] | None  # H_W: epoch-length entries when present
    author_index: int                      # H_I, E2 LE, index into kappa'
    entropy_source: bytes                  # H_V, 96-octet Bandersnatch VRF signature
    offenders_mark: list[bytes]            # H_O, compact-prefixed Vec of 32-octet Ed25519 keys
    seal: bytes                            # H_S, 96-octet Bandersnatch VRF signature over E_U(H)

    # ---- converters -------------------------------------------------------
    # The dict shapes below are shared by two sources that agree on keys and
    # differ only in hex formatting: the vector JSON sidecars (0x-prefixed)
    # and the header codec's marker readers (plain .hex()).

    def encode(self) -> bytes:
        """Serialize the header to its wire form (GP C.22–C.25)."""
        return _codec('encode_header')(self)

    @classmethod
    def epoch_mark_from_dict(cls, d: dict) -> EpochMarker:
        return EpochMarker(
            entropy=hex_to_bytes(d["entropy"]),
            tickets_entropy=hex_to_bytes(d["tickets_entropy"]),
            validators=[
                ValidatorKeys(bandersnatch=hex_to_bytes(v["bandersnatch"]), ed25519=hex_to_bytes(v["ed25519"]))
                for v in d["validators"]
            ],
        )

    @classmethod
    def tickets_mark_from_list(cls, tickets: list[dict]) -> list[TicketBody]:
        return [TicketBody(id=hex_to_bytes(t["id"]), attempt=t["attempt"]) for t in tickets]

    @classmethod
    def from_dict(cls, d: dict) -> "Header":
        """Vector JSON sidecar (or any dict with the same keys) -> Header."""
        return cls(
            parent=hex_to_bytes(d["parent"]),
            parent_state_root=hex_to_bytes(d["parent_state_root"]),
            extrinsic_hash=hex_to_bytes(d["extrinsic_hash"]),
            slot=d["slot"],
            epoch_mark=cls.epoch_mark_from_dict(d["epoch_mark"]) if d.get("epoch_mark") else None,
            tickets_mark=cls.tickets_mark_from_list(d["tickets_mark"]) if d.get("tickets_mark") else None,
            author_index=d["author_index"],
            entropy_source=hex_to_bytes(d["entropy_source"]),
            offenders_mark=[hex_to_bytes(k) for k in (d.get("offenders_mark") or [])],
            seal=hex_to_bytes(d["seal"]),
        )