"""
JAM extrinsic models — GP 4.3 (E), C.17–C.21, plus the work-report
sub-structures (C.26–C.30) that guarantees and availability assignments embed.

Field spellings follow the codec test-vector JSON sidecars
(jamtestvectors/codec/*/*_extrinsic.json, work_result_*.json). All
byte/signature fields are raw `bytes`; hex strings only at the JSON edge.

Work-result outcomes are one enum (GP C.34 tags): OK carries the output
blob, the six failure tags carry nothing.
"""

from dataclasses import dataclass
from enum import Enum

from jam_impl.util import Encoder


# Wire codecs the model methods delegate to. Imported lazily at call time to
# break the module cycle (extrinsic_codec imports these models at load).
def _codec(name):
    import jam_impl.codec.extrinsic_codec as xc
    return getattr(xc, name)


def _spec_globals(spec: str):
    from jam_impl.codec.header_codec import spec_globals
    return spec_globals(spec)


# ---------------------------------------------------------------------------
# E_T tickets (GP C.17)
# ---------------------------------------------------------------------------

@dataclass
class Ticket:  # TicketEnvelope (GP C.17/C.33; jam-types.asn)
    attempt: int     # TicketAttempt, 1 octet (E1)
    signature: bytes  # BandersnatchRingVrfSignature, fixed 784 octets

    def encode(self) -> bytes:
        return _codec('encode_tickets')([self])


# ---------------------------------------------------------------------------
# E_P preimages (GP C.18)
# ---------------------------------------------------------------------------

@dataclass
class Preimage:  # GP C.18
    requester: int  # service id, E4
    blob: bytes     # ↕-prefixed preimage data

    def encode(self) -> bytes:
        return _codec('encode_preimages')([self])


# ---------------------------------------------------------------------------
# E_A assurances (GP C.20)
# ---------------------------------------------------------------------------

@dataclass
class Assurance:  # AvailAssurance, GP 11.11/C.20
    anchor: bytes         # 32 (header hash)
    bitfield: bytes       # ⌈core-count/8⌉ octets, one bit per core
    validator_index: int  # E2
    signature: bytes      # 64

    def encode(self) -> bytes:
        return _codec('encode_assurances')([self])


# ---------------------------------------------------------------------------
# E_D disputes (GP C.21)
# ---------------------------------------------------------------------------

@dataclass
class Judgment:  # GP 10.2: one validator's vote on a work report
    vote: bool        # one octet: 0x00/0x01
    index: int        # judge index, E2
    signature: bytes  # 64


@dataclass
class Verdict:  # GP 10.2: super-majority judgments on one work report
    target: bytes            # disputed work-report hash, 32
    age: int                 # epoch index, E4
    votes: list[Judgment]    # fixed size = validators-super-majority (0.7.2 wire: no length prefix)


@dataclass
class Culprit:  # GP 10.2: validator who guaranteed an invalid report
    target: bytes     # 32
    key: bytes        # ed25519 public key, 32
    signature: bytes  # 64


@dataclass
class Fault:  # GP 10.2: validator who signed an incorrect judgment
    target: bytes     # 32
    vote: bool        # the incorrect vote, one octet
    key: bytes        # ed25519 public key, 32
    signature: bytes  # 64


@dataclass
class Disputes:  # E_D = (verdicts, culprits, faults), GP 10.2/C.21
    verdicts: list[Verdict]
    culprits: list[Culprit]
    faults: list[Fault]

    def encode(self, spec: str = "tiny") -> bytes:
        # spec-sensitive (judgments-per-verdict = validators-super-majority):
        # enter the spec context the same way encode_extrinsic does
        with _spec_globals(spec):
            return _codec('encode_disputes')(self)


# ---------------------------------------------------------------------------
# Work report (GP C.29) — embedded by guarantees (E_G, C.19) and
# availability assignments (C(10) state component)
# ---------------------------------------------------------------------------

@dataclass
class PackageSpec:  # availability specification prefix, GP 11.5/C.27
    hash: bytes          # work-package hash, 32
    length: int          # bundle length, E4 (N_2^32)
    erasure_root: bytes  # 32
    exports_root: bytes  # 32
    exports_count: int   # E2


@dataclass
class Context:  # refine context, GP C.26
    anchor: bytes               # 32
    state_root: bytes           # 32
    beefy_root: bytes            # 32
    lookup_anchor: bytes         # 32
    lookup_anchor_slot: int      # E4
    prerequisites: list[bytes]  # ↕-prefixed sequence of 32-octet hashes


@dataclass
class SegmentRootLookupEntry:  # work-package hash -> segment tree root
    work_package_hash: bytes    # 32
    segment_tree_root: bytes    # 32


@dataclass
class RefineLoad:  # the digest tail — five compact counters, GP C.28
    gas_used: int
    imports: int
    extrinsic_count: int
    extrinsic_size: int
    exports: int


class WorkResult(Enum):  # outcome tags, GP C.34 (0.7.2) / C.36 (0.8.0)
    OK = 0                      # ↕-prefixed output blob follows the tag
    OUT_OF_GAS = 1
    PANIC = 2
    INVALID_EXPORTS_COUNT = 3
    DIGEST_SIZE_LIMIT_EXCEEDED = 4
    BAD_CODE = 5                # "BAD": code not found
    BIG = 6                     # "BIG": oversize


@dataclass
class ResultOk:  # pairs with WorkResult.OK — the payload the tag introduces
    ok: bytes  # ↕-prefixed output blob


@dataclass
class ResultItem:  # WorkDigest, GP C.28
    service_id: int          # E4
    code_hash: bytes         # 32
    payload_hash: bytes      # 32
    accumulate_gas: int      # E8 gas LIMIT (the used value is in refine_load, compact)
    result: WorkResult       # outcome tag (GP C.34)
    result_payload: ResultOk | None  # present iff result is WorkResult.OK
    refine_load: RefineLoad  # five compact counters


@dataclass
class Report:  # WorkReport, GP C.29
    package_spec: PackageSpec
    context: Context
    core_index: int                                 # u8
    authorizer_hash: bytes                          # 32
    auth_gas_used: int                              # compact N (NOT E8 — verified)
    auth_output: bytes                              # ↕-prefixed
    segment_root_lookup: list[SegmentRootLookupEntry]  # ↕ (empty ↕ = single 0x00)
    results: list[ResultItem]                        # ↕-prefixed

    def encode(self) -> bytes:
        e = Encoder()
        _codec('encode_report')(e, self)
        return e.finish()


@dataclass
class ValidatorSignature:  # (validator index, ed25519 signature), GP C.30
    validator_index: int  # E2
    signature: bytes     # 64


@dataclass
class Guarantee:  # GP 11.24/C.30
    report: Report
    slot: int                                # E4 timeslot following production
    signatures: list[ValidatorSignature]     # 2–3 credentials, ordered by validator index

    def encode(self) -> bytes:
        return _codec('encode_guarantees')([self])


# ---------------------------------------------------------------------------
# Whole extrinsic tuple (GP C.16)
# ---------------------------------------------------------------------------

@dataclass
class Extrinsic:  # E = (E_T, E_D, E_P, E_A, E_G), GP 4.3; wire order T,P,G,A,D (C.16)
    assurances: list[Assurance]  # E_A
    tickets: list[Ticket]        # E_T
    preimages: list[Preimage]    # E_P
    guarantees: list[Guarantee]  # E_G
    disputes: Disputes           # E_D

    def encode(self, spec: str = "tiny") -> bytes:
        return _codec('encode_extrinsic')(self, spec)