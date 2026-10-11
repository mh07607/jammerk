from jam_impl.models.State import AvailabilityAssignments, CurrentValidators, MostRecentTimeslot
from jam_impl.models.Extrinsic import Assurance
from nacl.signing import VerifyKey
import jam_impl.util as util
from nacl.exceptions import BadSignatureError

X_A = b'jam_available'

def assurances_stf(availability_assignments: AvailabilityAssignments,
                current_validators: CurrentValidators,
                extrinsic_assurances: list[Assurance],                
                header_slot: int,
                header_parent: bytes,
                spec: str = "tiny"):
    total_cores = util.NUM_VALIDATORS_IN_EPOCH_MARK // util.CORE_SIZE
    validator_index = -1
    cores_set = [0] * total_cores
    for assurance in extrinsic_assurances:
        if not 0 <= assurance.validator_index < util.NUM_VALIDATORS_IN_EPOCH_MARK:
            return "err", "bad_validator_index", availability_assignments
        if assurance.validator_index <= validator_index:
            return "err", "not_sorted_or_unique_assurers", availability_assignments          
        if assurance.anchor != header_parent:
            return "err", "bad_attestation_parent", availability_assignments                          
        for i in range(total_cores):
            bit = (assurance.bitfield[i // 8] >> (i % 8)) & 1
            if bit and availability_assignments.assignments[i] == None:
                return "err", "core_not_engaged", availability_assignments
            cores_set[i] += bit
        try:
            out = VerifyKey(key=current_validators.validators[assurance.validator_index].ed25519).verify(
                smessage=X_A + util.hash_via_blake2b(header_parent + assurance.bitfield), signature=assurance.signature
            )        
        except BadSignatureError as e:            
            return "err", "bad_signature", availability_assignments
        validator_index = assurance.validator_index
    reports_evicted = []
    for i in range(total_cores):
        report_available = cores_set[i] > 2/3 * util.NUM_VALIDATORS_IN_EPOCH_MARK
        if availability_assignments.assignments[i] and (report_available or header_slot >= availability_assignments.assignments[i].timeout + 5):
            if report_available:
                reports_evicted.append(availability_assignments.assignments[i].report)
            availability_assignments.assignments[i] = None
    return "ok", reports_evicted, availability_assignments