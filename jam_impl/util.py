import hashlib

HASH_LEN_IN_BYTES = 32
ZERO_HASH = bytes(HASH_LEN_IN_BYTES)

# Spec constants (swapped temporarily by spec_globals() in codec/header_codec.py)
# Tiny Config:  NUM_VALIDATORS_IN_EPOCH_MARK = 6,  LENGTH_OF_EPOCH_IN_TIMESLOTS = 12
# Full Config:  NUM_VALIDATORS_IN_EPOCH_MARK = 1023, LENGTH_OF_EPOCH_IN_TIMESLOTS = 600
NUM_VALIDATORS_IN_EPOCH_MARK = 1023
LENGTH_OF_EPOCH_IN_TIMESLOTS = 600

def hash_via_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, HASH_LEN_IN_BYTES).digest()

# TO-DO
def hash_via_keccak256(data: bytes) -> bytes:
    pass


def encode_fixed(x: int, length: int) -> bytes:
    assert 0 <= x < (1 << 8*length)
    return x.to_bytes(length=length, byteorder="little")

def decode_fixed(b: bytes, length: int) -> int:
    assert len(b) == length, f"E_{length} expected {length} octets, got {len(b)}"
    return int.from_bytes(b, byteorder="little")

def u8(x): return encode_fixed(x, 1)
def u16(x): return encode_fixed(x, 2)
def u32(x): return encode_fixed(x, 4)
def u64(x): return encode_fixed(x, 8)
def u128(x): return encode_fixed(x, 16)


def encode_compact(x: int) -> bytes:
    # GP C.5
    assert x >= 0 and x < 2**64, f"{x} is outside valid compact range i.e between 0 and 2^64"
    if x < 128:
        return bytes([x])
    for l in range(1, 9):
        if 2**(7*l) <= x and x < 2**(7*(l+1)):
            size_tag = 2**8 - 2**(8-l) + x//2**(8*l)
            return bytes([size_tag]) + encode_fixed(x % 2**(8*l), l)
    return bytes([2**8-1]) + u64(x)


class Decoder():
    """Cursor over a serialized byte string (the decode side of GP appendix C)."""

    def __init__(self, data: bytes):
        self.b, self.o = data, 0

    def take(self, n: int) -> bytes:
        assert self.o + n <= len(self.b), "Premature end of Input."
        s = self.b[self.o:self.o+n]
        self.o += n
        return s

    def u8(self) -> int: return self.take(1)[0]
    def u16(self) -> int: return decode_fixed(self.take(2), 2)
    def u32(self) -> int: return decode_fixed(self.take(4), 4)
    def u64(self) -> int: return decode_fixed(self.take(8), 8)
    def hash32(self) -> bytes: return self.take(32)

    def decode_compact(self) -> int:
        """Read one compact-encoded natural (GP C.5) and advance the cursor."""
        first_octet = self.b[self.o]
        if first_octet < 128:
            self.o += 1
            return first_octet
        table = [(128, 192, 1), (192, 224, 2), (224, 240, 3), (240, 248, 4),
                 (248, 252, 5), (252, 254, 6), (254, 255, 7), (255, 256, 8)]
        for low, high, l in table:
            if low <= first_octet < high:
                high_part = first_octet - (2**8 - 2**(8-l))
                payload = self.b[self.o+1 : self.o+1+l]
                self.o += 1 + l
                return high_part * 2**(8*l) + int.from_bytes(payload, "little")
        raise ValueError(f"Invalid compact. Tag: {first_octet}")

    def blob(self) -> bytes:
        """Length-prefixed (↕) variable-size octet sequence."""
        n = self.decode_compact()
        return self.take(n)

    def finish(self):
        assert self.o == len(self.b), f"{len(self.b) - self.o} octets left"


class Encoder():
    """Builder producing the serialized byte string (the encode side of GP appendix C)."""

    def __init__(self):
        self.parts: list[bytes] = []

    def _add(self, b: bytes) -> "Encoder":
        self.parts.append(b)
        return self

    def raw(self, b: bytes) -> "Encoder": return self._add(b)          # blobs / hashes as-is (C.2)
    def u8(self, x: int) -> "Encoder": return self._add(encode_fixed(x, 1))   # E1
    def u16(self, x: int) -> "Encoder": return self._add(encode_fixed(x, 2))  # E2
    def u32(self, x: int) -> "Encoder": return self._add(encode_fixed(x, 4))  # E4
    def u64(self, x: int) -> "Encoder": return self._add(encode_fixed(x, 8))  # E8
    def hash32(self, h: bytes) -> "Encoder":
        assert len(h) == 32, f"hash32 expects 32 octets, got {len(h)}"
        return self._add(h)

    def compact(self, x: int) -> "Encoder": return self._add(encode_compact(x))  # C.5
    def blob(self, b: bytes) -> "Encoder": return self.compact(len(b))._add(b)   # ↕ (C.7)
    def boolean(self, v: bool) -> "Encoder": return self._add(b"\x01" if v else b"\x00")  # C.1.1 (tex) / C.5
    def maybe(self, x: bytes | None) -> "Encoder":                        # ¿ (C.8)
        return self._add(b"\x00") if x is None else self._add(b"\x01") .raw(x)

    def finish(self) -> bytes:
        return b"".join(self.parts)


# Reader -> Decoder; decode_compact_length_prefix -> module function kept for
# compatibility

Reader = Decoder


class StrictSet(set):
    """A set that refuses duplicates"""

    def __init__(self, iterable=None):
        if iterable is not None:
            for item in iterable:
                self.add(item)

    def add(self, item):
        if item in self:
            raise ValueError(f"Duplicate item found: {item!r}")
        super().add(item)


def decode_compact_length_prefix(b: bytes, offset: int) -> tuple[int, int]:
    first_octet = b[offset]
    if first_octet < 128: return first_octet, offset + 1
    table = [(128, 192, 1), (192, 224, 2), (224, 240, 3), (240, 248, 4),
            (248, 252, 5), (252, 254, 6), (254, 255, 7), (255, 256, 8)]
    for low, high, l in table:
        if low <= first_octet < high:
            high_part = first_octet - (2**8 - 2**(8-l))
            payload = b[offset+1 : offset+1+l]
            return high_part * 2**(8*l) + int.from_bytes(payload, "little"), offset + 1 + l
    raise ValueError(f"Invalid compact. Tag: {first_octet}")

def decode_compact(b: bytes, offset: int = 0) -> tuple[int, int]:
    """Standalone form of Decoder.decode_compact: returns (value, new_offset)."""
    first_octet = b[offset]
    if first_octet < 128: return first_octet, offset + 1
    table = [(128, 192, 1), (192, 224, 2), (224, 240, 3), (240, 248, 4),
            (248, 252, 5), (252, 254, 6), (254, 255, 7), (255, 256, 8)]
    for low, high, l in table:
        if low <= first_octet < high:
            high_part = first_octet - (2**8 - 2**(8-l))
            payload = b[offset+1 : offset+1+l]
            return high_part * 2**(8*l) + int.from_bytes(payload, "little"), offset + 1 + l
    raise ValueError(f"Invalid compact. Tag: {first_octet}")

def maybe_bytes(blob: bytes | None) -> bytes:
    return b"\x00" if blob is None else b"\x01" + blob

if __name__ == "__main__":    
    from jam_impl.codec.header_codec import decode_header
    with open("/home/arsalan/repos/JAM_Implementation/jamtestvectors/codec/full/header_0.bin", "rb") as f:
        h = decode_header(f.read(), spec="full")
    print(h)