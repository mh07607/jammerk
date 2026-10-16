from jam_impl.models.State import (
    AvailabilityAssignments, CurrentValidators, PreviousValidators,
    EntropyAccumulator, Disputes, RecentHistory,
    CoreStatistics, ServiceStatistics, ServiceAccount,
)
from jam_impl.models.Extrinsic import Guarantee
from jam_impl.codec.extrinsic_codec import encode_report
import jam_impl.util as util
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError


type Reported = list[tuple[bytes, bytes]]  # (work_package_hash, exports_root)
type Reporters = list[bytes]               # ed25519 keys of guarantors
type ReportsVerdict = tuple[str, Reported, Reporters] | tuple[str, str]


def reports_stf(availability_assignments: AvailabilityAssignments,   # ρ (mutated)
                core_statistics_post: list[CoreStatistics],          # π_C (mutated)
                service_statistics_post: dict[int, ServiceStatistics],  # π_S (mutated)
                recent_history: RecentHistory,                       # β (read-only)
                current_validators: CurrentValidators,               # κ (read-only)
                previous_validators: PreviousValidators,             # λ (read-only)
                entropy: EntropyAccumulator,                         # η (read-only)
                disputes: Disputes,                                  # ψ (read-only)
                accounts: dict[int, ServiceAccount],                 # δ (read-only)
                guarantees: list[Guarantee],
                current_slot: int,
                known_packages: list[bytes],
                spec: str = "tiny") -> ReportsVerdict:
    X_GUARANTEE = b'jam_guarantee'

    guarantee_core_index = -1
    package_hashes = util.StrictSet()
    for guarantee in guarantees:        
        if guarantee.report.core_index not in range(util.CORE_SIZE):
            return "err", "bad_core_index", [], []
        if guarantee.report.core_index <= guarantee_core_index:
            return "err", "out_of_order_guarantee", [], []
        if len(guarantee.signatures) < 2/3 * util.CORE_SIZE:
            return "err", "insufficient_guarantees", [], []
        validator_index = -1
        for signature in guarantee.signatures:
            if signature.validator_index <= validator_index:
                return "err", "not_sorted_or_unique_guarantors", [], []
            key = current_validators.validators[signature.validator_index].ed25519            
            e = util.Encoder()
            encode_report(e, guarantee.report)            
            try:
                out = VerifyKey(key=key).verify(smessage=X_GUARANTEE + util.hash_via_blake2b(e.finish()), signature=signature.signature)
            except BadSignatureError as e:
                return "err", "bad_signature", [], []
            validator_index = signature.validator_index
        package_hashes.add(guarantee.report.package_spec.hash)
        guarantee_core_index = guarantee.report.core_index
    # 11.25 credentials must be ordered by their validator index.
    # 11.24 guarantees must be ordered by (unique) core index.
    # 11.32 no duplicate package hashes within the extrinsic.
    # 11.33 anchor (block hash/state-root/super-peak) must match a recent block.
    # 11.34/11.35 lookup anchor within L slots, recorded in the ancestor set.e
    # 11.36-11.38 pipeline uniqueness (recent history / accumulated / ρ / …).
    # 11.39 prerequisites ∪ lookup keys resolvable from extrinsic ∨ recent β.
    # 11.40-11.41 lookup keys hash↦exports_root verified against those sources.
    # 11.42 results' code hash == accounts[service_id].definition…code_hash.
    # 11.30 per-report gas ≤ 10,000,000; per-item ≥ min_item_gas (accounts).
    # 11.23-11.29 assignment check via P(η₂', τ') shuffle (+ prev-rotation M*),
    #       signature over $jam_guarantee ‖ H(report); offenders ∈ ψ_O excluded.
    # Seating: ρ[core] = (report, timeout=current_slot), replacing occupied slots.
    # Statistics π_C/π_S: refinement components only (GP §13).    