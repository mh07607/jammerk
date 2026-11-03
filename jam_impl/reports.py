from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from dataclasses import dataclass

from jam_impl.models.State import (
    AvailabilityAssignments, CurrentValidators, PreviousValidators,
    EntropyAccumulator, Disputes, RecentHistory,
    CoreStatistics, ServiceStatistics, ServiceAccount,
    AccumulationQueue, AccumulationHistory, AuthorizationPool,
    AvailabilityAssignment
)
# from jam_impl.tests.reports_stf_harness import ServiceRecord
from jam_impl.models.Extrinsic import Guarantee, WorkResult
from jam_impl.codec.extrinsic_codec import encode_report
from jam_impl.safrole import remove_offenders
import jam_impl.util as util


class ServiceRecord:
    """One account body (the reports-relevant slice of ServiceInfo, GP C(255,s)):
    version, code_hash, balance … parent_service — decoded via the repo's
    decode_service_definition over its exact 89-octet span."""

    SIZE = 89  # 1 + 32 + 4×8 + 5×4 - …: the fixed octet length of one record

    def __init__(self, service_id: int, record):
        self.service_id = service_id
        self.definition = record  # repo model (ServiceDefinition) or None

    def min_item_gas(self) -> int:
        return self.definition.data.service.min_item_gas if self.definition else 0

    def code_hash(self) -> bytes:
        return self.definition.data.service.code_hash

    def balance(self) -> int:
        return self.definition.data.service.balance


# The guarantor-assignment machinery (GP \guarantorassignments,
# \guarantorassignmentsunderlastrotation, eq:guarantorsig) now lives in
# jam_impl/guarantors.py — it is shared with the STATISTICS step, which
# consumes the reporters set this step produces.  The names are re-exported
# here so existing importers of jam_impl.reports keep working.
from jam_impl.guarantors import (   # noqa: E402
    GuarantorAssignments,
    guarantor_assignments as build_guarantor_assignments,
    prior_guarantor_assignments,    
)


type Reported = list[tuple[bytes, bytes]]  # (work_package_hash, exports_root)
type Reporters = list[bytes]               # ed25519 keys of guarantors
type ReportsVerdict = tuple[str, Reported, Reporters] | tuple[str, str]


def reports_stf(availability_assignments: AvailabilityAssignments,   # ρ (mutated)
                core_statistics_post: list[CoreStatistics],          # π_C (mutated)
                service_statistics_post: dict[int, ServiceStatistics],  # π_S (mutated)
                recent_history: RecentHistory,                       # β (read-only)
                authorization_pools: AuthorizationPool,              # α (read-only: 11.29 core_unauthorized)
                current_validators: CurrentValidators,               # κ (read-only)
                previous_validators: PreviousValidators,             # λ (read-only)
                entropy: EntropyAccumulator,                         # η (read-only)
                disputes: Disputes,                                  # ψ (read-only)
                accounts: list[ServiceRecord],                 # δ (read-only)
                accumulation_queue: AccumulationQueue,               # ω (read: pkg hashes for 11.38)
                accumulation_history: AccumulationHistory,           # ξ (read: pkg hashes for 11.38)
                guarantees: list[Guarantee],
                current_slot: int,
                spec: str = "tiny") -> ReportsVerdict:
    X_GUARANTEE = b'jam_guarantee'
    MAX_RESULTS_SIZE = 48 * 2 ** 10
    current_guarantor_assignments: GuarantorAssignments = build_guarantor_assignments(
        current_validators.validators, entropy.values[2], current_slot,
        disputes.offenders)
    previous_guarantor_assignments: GuarantorAssignments = prior_guarantor_assignments(
        current_validators.validators, previous_validators.validators,
        entropy.values[2], entropy.values[3], current_slot, disputes.offenders)

    # service_ids = [ service_record.service_id for service_record in accounts]
    accumulation_queue_package_hashes = [ ready_record.report.package_spec.hash for ready_record_slot in accumulation_queue.queue for ready_record in ready_record_slot  ]
    availability_assignments_package_hashes = [ assignment.report.package_spec.hash for assignment in availability_assignments.assignments if assignment is not None]    
    guarantee_core_index = -1
    package_hashes = util.StrictSet()        
    for guarantee in guarantees:        
        if guarantee.slot > current_slot:
            return "err", "future_report_slot"
        if guarantee.slot < current_slot - util.ROTATION_PERIOD:
            return "err", "report_epoch_before_last"
        if guarantee.report.core_index not in range(util.CORE_SIZE):
            return "err", "bad_core_index", [], []
        if availability_assignments.assignments[guarantee.report.core_index] is not None:
            return "err", "core_engaged", [], []    
        if not guarantee.report.authorizer_hash in authorization_pools.pools[guarantee.report.core_index]:
            return "err", "core_unauthorized", [], []
        if guarantee.report.core_index <= guarantee_core_index:            
            return "err", "out_of_order_guarantee", [], []
        if len(guarantee.signatures) < 2/3 * util.CORE_SIZE:
            return "err", "insufficient_guarantees", [], []   
        if len(guarantee.report.results) == 0:
            return "err", "missing_work_results"
        if len(guarantee.report.context.prerequisites) + len(guarantee.report.segment_root_lookup) > util.MAX_REPORT_DEPENDENCIES:            
            return "err", "too_many_dependencies"
        anchor_in_recent_history  = False        
        for block in recent_history.history:
            if block.header_hash == guarantee.report.context.anchor:
                if not block.beefy_root == guarantee.report.context.beefy_root:
                    return "err", "bad_beefy_mmr_root", [], []
                if not block.state_root == guarantee.report.context.state_root:
                    return "err", "bad_state_root", [], []
                anchor_in_recent_history = True
                break
        if not anchor_in_recent_history:
            return "err", "anchor_not_recent", [], []
        if guarantee.report.context.lookup_anchor_slot < current_slot - util.MAX_LOOKUP_ANCHOR_AGE_IN_TIMESLOTS:
            return "err", "lookup_anchor_not_recent", [], []
        for prerequisite in guarantee.report.context.prerequisites:
            prereq_found = False
            if prerequisite in [ g.report.package_spec.hash for g in guarantees ]:
                prereq_found = True                
            if not prereq_found:
                for block in recent_history.history:
                    reported = [report.hash for report in block.reported]
                    if prerequisite in reported:
                        prereq_found = True
                        break   
            if not prereq_found:
                return "err", "dependency_missing"
        for segment_root in guarantee.report.segment_root_lookup:
            segment_root_found = False
            for g in guarantees:
                if (g.report.package_spec.hash == segment_root.work_package_hash
                    and g.report.package_spec.exports_root == segment_root.segment_tree_root):
                    segment_root_found = True
                    break
            if not segment_root_found:
                for block in recent_history.history:
                    for report in block.reported:
                        if (report.hash == segment_root.work_package_hash
                            and report.exports_root == segment_root.segment_tree_root):
                            segment_root_found = True
                            break
                    if segment_root_found:
                        break
            if not segment_root_found:
                return "err", "segment_root_lookup_invalid"            
        if guarantee.slot // util.ROTATION_PERIOD == current_slot // util.ROTATION_PERIOD:
            guarantor_assignments = current_guarantor_assignments
        else:
            guarantor_assignments = previous_guarantor_assignments
        validator_index = -1
        for signature in guarantee.signatures:
            if not 0 <= signature.validator_index < util.NUM_VALIDATORS_IN_EPOCH_MARK:
                return "err", "bad_validator_index", [], []            
            if signature.validator_index <= validator_index:
                return "err", "not_sorted_or_unique_guarantors", [], []            
            if guarantor_assignments.permutation[signature.validator_index] != guarantee.report.core_index:
                return "err", "wrong_assignment", [], []
            key = guarantor_assignments.validators[signature.validator_index].ed25519               
            if key == b'\0' * 32:
                return "err", "banned_validator"
            e = util.Encoder()
            encode_report(e, guarantee.report)            
            try:
                out = VerifyKey(key=key).verify(smessage=X_GUARANTEE + util.hash_via_blake2b(e.finish()), signature=signature.signature)
            except BadSignatureError as e:
                return "err", "bad_signature", [], []
            validator_index = signature.validator_index
        # results_size = len(guarantee.report.auth_output) + sum([ len(result.result_payload.ok) for result in guarantee.report.results if result.result == WorkResult.OK ])                
        results_size = len(guarantee.report.auth_output)                
        total_accumulation_gas = 0
        for result in guarantee.report.results:            
            service_account = None
            for account in accounts:
                if account.service_id == result.service_id:
                    service_account = account
            if service_account is None:
                return "err", "bad_service_id", [], []
            if service_account.code_hash() != result.code_hash:
                return "err", "bad_code_hash", [], [] 
            if result.accumulate_gas < service_account.min_item_gas():
                return "err", "service_item_gas_too_low"
            if result.result == WorkResult.OK:
                results_size += len(result.result_payload.ok)
            total_accumulation_gas += result.accumulate_gas            
        if results_size > MAX_RESULTS_SIZE:
            return "err", "work_report_too_big", [], []
        if total_accumulation_gas > util.MAX_GAS:
            return "err", "work_report_gas_too_high"
        try:
            package_hashes.add(guarantee.report.package_spec.hash)
        except ValueError as e:
            return "err", "duplicate_package", [], []
        if (guarantee.report.package_spec.hash in accumulation_queue_package_hashes
            or guarantee.report.package_spec.hash in availability_assignments_package_hashes
            or guarantee.report.package_spec.hash in [ package_hash for package_hash in accumulation_history.history  ]
            or guarantee.report.package_spec.hash in [ reported_package.hash for history in recent_history.history for reported_package in history.reported  ]):
            return "err", "duplicate_package", [], []
        guarantee_core_index = guarantee.report.core_index
        
    # Mutating the state
    reported = []
    reporters = []
    for guarantee in guarantees:
        core_statistics_post[guarantee.report.core_index].bundle_size += guarantee.report.package_spec.length
        for result in guarantee.report.results:
            if result.service_id not in service_statistics_post:
                service_statistics_post[result.service_id] = ServiceStatistics()
            service_statistics_post[result.service_id].imports += result.refine_load.imports
            service_statistics_post[result.service_id].exports += result.refine_load.exports
            service_statistics_post[result.service_id].extrinsic_count += result.refine_load.extrinsic_count
            service_statistics_post[result.service_id].extrinsic_size += result.refine_load.extrinsic_size
            service_statistics_post[result.service_id].refinement_count += 1
            service_statistics_post[result.service_id].refinement_gas_used += result.refine_load.gas_used
            core_statistics_post[guarantee.report.core_index].imports += result.refine_load.imports
            core_statistics_post[guarantee.report.core_index].exports += result.refine_load.exports
            core_statistics_post[guarantee.report.core_index].gas_used += result.refine_load.gas_used
            core_statistics_post[guarantee.report.core_index].extrinsic_count += result.refine_load.extrinsic_count
            core_statistics_post[guarantee.report.core_index].extrinsic_size += result.refine_load.extrinsic_size 

        # for result in guarantee.report.results:
        #     service_statistics_post[result.service_id] 
        #     result.service_id
        availability_assignments.assignments[guarantee.report.core_index] = AvailabilityAssignment(
            report=guarantee.report,
            timeout=current_slot
        )        
        # reported.append({
        #     "work_package_hash": guarantee.report.package_spec.hash,
        #     "segment_tree_root": guarantee.report.package_spec.exports_root
        # })
        reported.append(
            (guarantee.report.package_spec.hash, guarantee.report.package_spec.exports_root)
        )
        if guarantee.slot // util.ROTATION_PERIOD == current_slot // util.ROTATION_PERIOD:
            guarantor_assignments = current_guarantor_assignments
        else:
            guarantor_assignments = previous_guarantor_assignments
        for signature in guarantee.signatures:            
            key = guarantor_assignments.validators[signature.validator_index].ed25519
            if key not in reporters:
                reporters.append(key)
    reporters.sort()
    reported.sort(key=lambda x: x[0])        
    # reported.sort(key=lambda x: x["work_package_hash"])
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
    return "ok", reported, reporters