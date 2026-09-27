from dataclasses import dataclass, field

from jam_impl.models.Extrinsic import Report
from jam_impl.util import StrictSet


# ---------------------------------------------------------------------------
# Shared sub-structures
# ---------------------------------------------------------------------------

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


@dataclass
class AuthorizationQueue:  # C(2): ϕ — per-core authorizer queues
    queues: list[list[bytes]]  # core-count queues, each fixed 80 authorizer hashes


@dataclass
class RecentHistory:  # C(3): β = (β_H history, β_B MMR belt)
    history: list[BlockInfo]     # ↕-prefixed sequence (0..8 records)
    mmr_peaks: list[bytes | None]  # β_B: ↕ of ¿-peaks (None = empty slot)


@dataclass
class SafroleState:  # C(4): γ = (γ_P, γ_Z, γ_S disc, γ_S, γ_A)
    pending_validators: list[ValidatorData]     # γ_P, fixed V entries
    epoch_root: bytes                           # γ_Z, 144-octet ring commitment
    tickets_or_keys_flag: int                   # 0 = tickets, 1 = fallback keys
    tickets_or_keys: object                    # list[TicketBody] | list[bytes] (keys)
    ticket_accumulator: list[TicketBody]        # γ_A, ↕-prefixed


@dataclass
class Disputes:  # C(5): ψ — dispute records (all four ↕-prefixed, key-sorted)
    good: list[bytes]       # reports deemed valid
    bad: list[bytes]        # reports deemed invalid
    wonky: list[bytes]      # conflicting judgments
    offenders: list[bytes]  # offending validators' Ed25519 keys


@dataclass
class EntropyAccumulator:  # C(6): η — four 32-octet entropy values
    values: list[bytes]  # exactly 4 hashes


@dataclass
class UpcomingValidators:  # C(7): ι — next epoch's validator set
    validators: list[ValidatorData]


@dataclass
class CurrentValidators:  # C(8): κ — this epoch's validator set
    validators: list[ValidatorData]


@dataclass
class PreviousValidators:  # C(9): λ — last epoch's validator set
    validators: list[ValidatorData]


@dataclass
class AvailabilityAssignment:  # C(10) entry: ρ — some (report, timeout) | none
    report: Report  # guaranteed work report
    timeout: int    # E4 timeslot, meaningful iff report is not None


@dataclass
class AvailabilityAssignments:  # C(10): ρ — one entry per core
    assignments: list[AvailabilityAssignment | None]  # core-count ¿-entries


@dataclass
class MostRecentTimeslot:  # C(11): τ — E4
    timeslot: int


@dataclass
class PrivilegedServices:  # C(12): χ = (χ_M, χ_A, χ_V, χ_R, χ_Z)
    bless: int                            # χ_M manager service, E4
    assign: list[int]                    # χ_A per-core assigner services, E4 each
    designate: int                       # χ_V upcoming-validator editor, E4
    register: int                        # χ_R service creator, E4
    always_acc: list[AlwaysAccumulate]   # χ_Z ↕-prefixed (service_id, gas)


@dataclass
class RegistrarState:  # C(13): π_* — validator/core/service statistics
    vals_curr_stats: list[ValidatorStatistics]  # π_V accumulator (fixed u32 tables)
    vals_last_stats: list[ValidatorStatistics]  # π_L previous epoch
    cores_stats: list[CoreStatistics]           # π_C, core-count entries (all compact)
    services_stats: dict[int, ServiceStatistics] # π_S, ↕-prefixed pairs keyed by service id


@dataclass
class AccumulationQueue:  # C(14): ω — ready records per slot (epoch-length)
    queue: list[list[ReadyRecord]]  # fixed epoch-length slots, each ↕-prefixed


@dataclass
class AccumulationHistory:  # C(15): ξ — accumulated work-package hashes per slot
    history: list[StrictSet]  # fixed epoch-length slots, each ↕-prefixed; GP: sets


@dataclass
class Statistics:  # C(16): θ — accumulation outputs (service, work-report hash)
    outputs: list[tuple[int, bytes]]  # ↕-prefixed (E4 service id, 32-octet hash)


# ---------------------------------------------------------------------------
# Service accounts (C(255, s) form-2 keys)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Whole state
# ---------------------------------------------------------------------------

@dataclass
class StateEntry:  # one trie entry: the 31-octet key, its raw value, and the
    key: bytes               # decoded component when the key is a known form
    value: bytes
    component: object = None  # typed dataclass | int (form-2 service id) | None


@dataclass
class State:  # decoded RawState (traces schema): root + ordered entries
    state_root: bytes
    entries: list[StateEntry] = field(default_factory=list)