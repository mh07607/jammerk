"""
JAM state component models — GP 4.4 (σ), D.1 (key constructor C), D.2 (values).

Each top-level component knows how to serialize itself:
  - `encode(self) -> bytes`  emits the ↕-prefixed D.2 value bytes;
  - `key(self) -> bytes`     emits its 31-octet D.1 state key
                             (form-1 C(n), or form-2 C(255, s) for accounts).
The wire codecs are plain functions in jam_impl/codec/state_codec.py; these
methods delegate, so a component's layout and its encoding stay adjacent.

`State` is the *semantic* state: every component laid out by name (no raw
keys, no raw values). Decoding raw bytes -> State is decode_state()'s job;
State -> trie keyvals is get_state_keyvals().
"""

from dataclasses import dataclass, field

from jam_impl.models.Extrinsic import Report
from jam_impl.util import StrictSet


# Wire codecs the model methods delegate to. Imported lazily at call time
# to break the module cycle: state_codec imports these models at load.
def _codec(name):
    import jam_impl.codec.state_codec as sc
    return getattr(sc, name)


# Form-1 state keys, C(1)..C(16): one byte of n then 30 zero octets (GP D.1).
def _form1(n: int) -> bytes:
    return bytes([n] + [0] * 30)

C1_KEY, C2_KEY, C3_KEY, C4_KEY = _form1(1), _form1(2), _form1(3), _form1(4)
C5_KEY, C6_KEY, C7_KEY, C8_KEY = _form1(5), _form1(6), _form1(7), _form1(8)
C9_KEY, C10_KEY, C11_KEY, C12_KEY = _form1(9), _form1(10), _form1(11), _form1(12)
C13_KEY, C14_KEY, C15_KEY, C16_KEY = _form1(13), _form1(14), _form1(15), _form1(16)


@dataclass(eq=True, frozen=True)
class ValidatorData:  # jam-types.asn: ValidatorData (one entry of ι/κ/λ/γ_P)
    bandersnatch: bytes  # 32-octet compressed Bandersnatch public key
    ed25519: bytes       # 32-octet Ed25519 public key
    bls: bytes           # 144-octet BLS public key
    metadata: bytes      # 128 octets, opaque
    # frozen=True generates hash+eq over ALL fields, so instances are set
    # members (GP C.11 dedups sets on the full element encoding: duplicates
    # only when every field matches).

@dataclass
class ValidatorStatistics:  # jam-types.asn: ValidatorActivityRecord (π_V/π_L entry)
    blocks: int              # blocks produced, u32
    tickets: int             # safrole tickets consumed, u32
    pre_images: int          # preimages introduced, u32
    pre_images_size: int    # total octets introduced, u32
    guarantees: int          # reports guaranteed, u32
    assurances: int          # availability assurances, u32

@dataclass
class CoreStatistics:  # jam-types.asn: CoreActivityRecord (π_C entry) — ALL fields compact
    da_load: int             # total DA bytes written (compact N)
    popularity: int          # assurance super-majority count (compact N)
    imports: int             # segments imported from DA (compact N)
    extrinsic_count: int     # extrinsics for reported work (compact N)
    extrinsic_size: int      # total extrinsic size (compact N)
    exports: int             # segments exported to DA (compact N)
    bundle_size: int         # serialized work bundle size (compact N)
    gas_used: int            # total gas consumed (compact N)

@dataclass
class ServiceStatistics:  # jam-types.asn: ServiceActivityRecord (π_S entry) — ALL fields compact
    provided_count: int      # preimages provided to this service (compact N)
    provided_size: int       # total preimage size (compact N)
    refinement_count: int    # work-items refined (compact N)
    refinement_gas_used: int # refinement gas (compact N)
    imports: int             # segments imported (compact N)
    extrinsic_count: int     # extrinsics used (compact N)
    extrinsic_size: int      # total extrinsic size (compact N)
    exports: int              # segments exported (compact N)
    accumulate_count: int    # work-items accumulated (compact N)
    accumulate_gas_used: int # accumulation gas (compact N)

@dataclass
class TicketBody:  # GP 6.6 (γ_A entry): ring-VRF output id + attempt
    id: bytes       # 32-octet ticket identifier
    attempt: int    # 1-octet attempt counter

@dataclass
class AlwaysAccumulate:  # jam-types.asn: AlwaysAccumulateMapEntry (χ_Z entry)
    service_id: int  # E4
    gas: int         # E8 basic gas limit

@dataclass
class ReportedWorkPackage:  # jam-types.asn: ReportedWorkPackage (β_H entry tail)
    hash: bytes          # 32-octet work-package hash
    exports_root: bytes  # 32-octet exported-data root

@dataclass
class BlockInfo:  # jam-types.asn: BlockInfo (one β_H history record)
    header_hash: bytes                  # 32
    beefy_root: bytes                   # 32 (MMR super-peak at that block)
    state_root: bytes                  # 32 (posterior state root)
    reported: list[ReportedWorkPackage] # ↕-prefixed

@dataclass
class ReadyRecord:  # jam-types.asn: ReadyRecord (ω entry): report + dependencies
    report: Report                  # work report ready for accumulation
    dependencies: StrictSet         # ↕-prefixed work-package hashes; GP: a set


# ---------------------------------------------------------------------------
# State components, C(1)…C(16) order
# ---------------------------------------------------------------------------

@dataclass
class AuthorizationPool:  # C(1): α — per-core authorizer pools
    pools: list[list[bytes]]  # core-count pools, each ↕-prefixed authorizer hashes

    def key(self) -> bytes:  # C(1)
        return C1_KEY

    def encode(self) -> bytes:
        return _codec('encode_authorization_pool')(self)

@dataclass
class AuthorizationQueue:  # C(2): ϕ — per-core authorizer queues
    queues: list[list[bytes]]  # core-count queues, each fixed 80 authorizer hashes

    def key(self) -> bytes:  # C(2)
        return C2_KEY

    def encode(self) -> bytes:
        return _codec('encode_authorization_queue')(self)

@dataclass
class RecentHistory:  # C(3): β = (β_H history, β_B MMR belt)
    history: list[BlockInfo]     # ↕-prefixed sequence (0..8 records)
    mmr_peaks: list[bytes | None]  # β_B: ↕ of ¿-peaks (None = empty slot)

    def key(self) -> bytes:  # C(3)
        return C3_KEY

    def encode(self) -> bytes:
        return _codec('encode_recent_history')(self)

@dataclass
class SafroleState:  # C(4): γ = (γ_P, γ_Z, γ_S disc, γ_S, γ_A)
    pending_validators: list[ValidatorData]     # γ_P, fixed V entries
    epoch_root: bytes                           # γ_Z, 144-octet ring commitment
    tickets_or_keys_flag: int                   # 0 = tickets, 1 = fallback keys
    tickets_or_keys: object                    # list[TicketBody] | list[bytes] (keys)
    ticket_accumulator: list[TicketBody]        # γ_A, ↕-prefixed

    def key(self) -> bytes:  # C(4)
        return C4_KEY

    def encode(self) -> bytes:
        return _codec('encode_safrole_state')(self)

@dataclass
class Disputes:  # C(5): ψ — dispute records (all four ↕-prefixed, key-sorted)
    good: list[bytes]       # reports deemed valid
    bad: list[bytes]        # reports deemed invalid
    wonky: list[bytes]      # conflicting judgments
    offenders: list[bytes]  # offending validators' Ed25519 keys

    def key(self) -> bytes:  # C(5)
        return C5_KEY

    def encode(self) -> bytes:
        return _codec('encode_disputes_state')(self)

@dataclass
class EntropyAccumulator:  # C(6): η — four 32-octet entropy values
    values: list[bytes]  # exactly 4 hashes

    def key(self) -> bytes:  # C(6)
        return C6_KEY

    def encode(self) -> bytes:
        return _codec('encode_entropy_accumulator')(self)

@dataclass
class UpcomingValidators:  # C(7): ι — next epoch's validator set
    validators: list[ValidatorData]

    def key(self) -> bytes:  # C(7)
        return C7_KEY

    def encode(self) -> bytes:
        return _codec('encode_upcoming_validators')(self)

@dataclass
class CurrentValidators:  # C(8): κ — this epoch's validator set
    validators: list[ValidatorData]

    def key(self) -> bytes:  # C(8)
        return C8_KEY

    def encode(self) -> bytes:
        return _codec('encode_current_validators')(self)

@dataclass
class PreviousValidators:  # C(9): λ — last epoch's validator set
    validators: list[ValidatorData]

    def key(self) -> bytes:  # C(9)
        return C9_KEY

    def encode(self) -> bytes:
        return _codec('encode_previous_validators')(self)

@dataclass
class AvailabilityAssignment:  # C(10) entry: ρ — some (report, timeout) | none
    report: Report  # guaranteed work report
    timeout: int    # E4 timeslot, meaningful iff report is not None

@dataclass
class AvailabilityAssignments:  # C(10): ρ — one entry per core
    assignments: list[AvailabilityAssignment | None]  # core-count ¿-entries

    def key(self) -> bytes:  # C(10)
        return C10_KEY

    def encode(self) -> bytes:
        return _codec('encode_availability_assignments')(self)

@dataclass
class MostRecentTimeslot:  # C(11): τ — E4
    timeslot: int

    def key(self) -> bytes:  # C(11)
        return C11_KEY

    def encode(self) -> bytes:
        return _codec('encode_most_recent_timeslot')(self)

@dataclass
class PrivilegedServices:  # C(12): χ = (χ_M, χ_A, χ_V, χ_R, χ_Z)
    bless: int                            # χ_M manager service, E4
    assign: list[int]                    # χ_A per-core assigner services, E4 each
    designate: int                       # χ_V upcoming-validator editor, E4
    register: int                        # χ_R service creator, E4
    always_acc: list[AlwaysAccumulate]   # χ_Z ↕-prefixed (service_id, gas)

    def key(self) -> bytes:  # C(12)
        return C12_KEY

    def encode(self) -> bytes:
        return _codec('encode_privileged_services')(self)

@dataclass
class RegistrarState:  # C(13): π_* — validator/core/service statistics
    vals_curr_stats: list[ValidatorStatistics]  # π_V accumulator (fixed u32 tables)
    vals_last_stats: list[ValidatorStatistics]  # π_L previous epoch
    cores_stats: list[CoreStatistics]           # π_C, core-count entries (all compact)
    services_stats: dict[int, ServiceStatistics] # π_S, ↕-prefixed pairs keyed by service id

    def key(self) -> bytes:  # C(13)
        return C13_KEY

    def encode(self) -> bytes:
        return _codec('encode_registrar_state')(self)

@dataclass
class AccumulationQueue:  # C(14): ω — ready records per slot (epoch-length)
    queue: list[list[ReadyRecord]]  # fixed epoch-length slots, each ↕-prefixed

    def key(self) -> bytes:  # C(14)
        return C14_KEY

    def encode(self) -> bytes:
        return _codec('encode_accumulation_queue')(self)

@dataclass
class AccumulationHistory:  # C(15): ξ — accumulated work-package hashes per slot
    history: list[StrictSet]  # fixed epoch-length slots, each ↕-prefixed; GP: sets

    def key(self) -> bytes:  # C(15)
        return C15_KEY

    def encode(self) -> bytes:
        return _codec('encode_accumulation_history')(self)

@dataclass
class Statistics:  # C(16): θ — accumulation outputs (service, work-report hash)
    outputs: list[tuple[int, bytes]]  # ↕-prefixed (E4 service id, 32-octet hash)


# ---------------------------------------------------------------------------
# Service accounts (C(255, s) form-2 keys)
# ---------------------------------------------------------------------------

    def key(self) -> bytes:  # C(16)
        return C16_KEY

    def encode(self) -> bytes:
        return _codec('encode_statistics')(self)

@dataclass
class ServiceDefinitionDataService:  # jam-types.asn: Service inner record
    version: int
    code_hash: bytes
    balance: int
    min_item_gas: int
    min_memo_gas: int
    bytes_count: int
    deposit_offset: int
    items: int
    creation_slot: int
    last_accumulation_slot: int
    parent_service: int

@dataclass
class ServiceDefinitionData:
    service: ServiceDefinitionDataService

@dataclass
class ServiceDefinition:  # C(255, s) account body — the 0.7.2 wire layout
    service_index: int
    data: ServiceDefinitionData

    def key(self) -> bytes:  # form-2: C(255, s) — GP D.1: i, n0, 0, n1, 0, n2, 0, n3
        s = self.service_index
        return bytes([255, s & 255, 0, (s >> 8) & 255, 0,
                      (s >> 16) & 255, 0, (s >> 24) & 255] + [0] * 23)

    def encode(self) -> bytes:
        return _codec('encode_service_definition')(self)

# ---------------------------------------------------------------------------
# Whole state — semantic form: every component laid out, no raw keys.
# Form-2 accounts are keyed by service id; form-3 material (storage /
# preimages / lookup) is kept in account buckets until its decoders exist.
# ---------------------------------------------------------------------------

@dataclass
class ServiceStorageItem:
    """One δ_s entry. The form-3 key is one-way hashed, so the raw 27-octet
    material is kept verbatim; on the write path the key is reconstructed
    as C(s, E4(2^32-1) ++ material) and matched, never inverted."""
    material: bytes   # the 27-octet hashed suffix of the form-3 key
    value: bytes


@dataclass
class PreimageBlob:
    """One a_p entry: 32-octet preimage hash -> blob."""
    hash: bytes       # 32-octet blake2b of the blob
    blob: bytes


@dataclass
class PreimageLookupEntry:
    """One a_l entry: (hash, len) -> lookup status (the E4 timeslots)."""
    hash: bytes       # 32-octet preimage hash
    length: int       # E4, the requested length
    timeslots: list[int]


@dataclass
class ServiceAccount:
    """Everything known about one service account, bucketed by service id."""
    definition: "ServiceDefinition | None" = None
    storage: list[ServiceStorageItem] = field(default_factory=list)
    preimages: list[PreimageBlob] = field(default_factory=list)
    lookup: list[PreimageLookupEntry] = field(default_factory=list)


@dataclass
class State:
    """The semantic state σ (GP 4.4). Form-1 components in C(1)..C(16) order,
    form-2 accounts keyed by service id, form-3 material nested per account.
    Undecoded (form-3) wire entries are parked in `undecoded` until their
    decoders exist — nothing is silently dropped."""
    authorization_pool: AuthorizationPool | None = None              # C(1) α
    authorization_queue: AuthorizationQueue | None = None            # C(2) φ
    recent_history: RecentHistory | None = None                      # C(3) β
    safrole: SafroleState | None = None                              # C(4) γ
    disputes: Disputes | None = None                                 # C(5) ψ
    entropy: EntropyAccumulator | None = None                        # C(6) η
    upcoming_validators: UpcomingValidators | None = None            # C(7) ι
    current_validators: CurrentValidators | None = None              # C(8) κ
    previous_validators: PreviousValidators | None = None            # C(9) λ
    availability_assignments: AvailabilityAssignments | None = None  # C(10) ρ
    most_recent_timeslot: MostRecentTimeslot | None = None           # C(11) τ
    privileged_services: PrivilegedServices | None = None            # C(12) χ
    registrar: RegistrarState | None = None                          # C(13) π
    accumulation_queue: AccumulationQueue | None = None              # C(14) ω
    accumulation_history: AccumulationHistory | None = None          # C(15) ξ
    statistics: Statistics | None = None                             # C(16) θ
    accounts: dict[int, ServiceAccount] = field(default_factory=dict)  # a_s
    undecoded: list[tuple[bytes, bytes]] = field(default_factory=list)

    def keyvals(self) -> list[tuple[bytes, bytes]]:
        """All trie keyvals this state produces, sorted by key (wire order)."""
        from jam_impl.codec.state_codec import get_state_keyvals
        return get_state_keyvals(self)