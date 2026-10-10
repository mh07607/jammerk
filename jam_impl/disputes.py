# to pass the stf/disputes test vectors
from jam_impl.models.State import (    
    Disputes,
    AvailabilityAssignments,
    MostRecentTimeslot,
    CurrentValidators,
    PreviousValidators
)
from jam_impl.models.Extrinsic import Disputes as ExtrinsicDisputes
import jam_impl.util as util
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

X_TRUE = b'jam_valid'
X_FALSE = b'jam_invalid'
X_GUARANTEE = b'jam_guarantee'

def disputes_stf(disputes: Disputes, 
                availability_assignments: AvailabilityAssignments,
                most_recent_timeslot: MostRecentTimeslot,
                current_validators: CurrentValidators,
                previous_validators: PreviousValidators,
                extrinsic_disputes: ExtrinsicDisputes,
                spec: str = "tiny"):
    GOOD_SCORE = 2/3 * util.NUM_VALIDATORS_IN_EPOCH_MARK + 1
    BAD_SCORE = 0
    WONKY_SCORE = 1/3 * util.NUM_VALIDATORS_IN_EPOCH_MARK
    
    # error checking    
    target = int(0).to_bytes(util.HASH_LEN_IN_BYTES)
    reports_scores = { 
        BAD_SCORE: [],
        GOOD_SCORE: [],
        WONKY_SCORE: [],
    }
    for verdict in extrinsic_disputes.verdicts:
        if verdict.target <= target:
            return "err", "verdicts_not_sorted_unique", (disputes, availability_assignments, most_recent_timeslot)
        if verdict.target in disputes.good or verdict.target in disputes.bad or verdict.target in disputes.wonky:
            return "err", "already_judged", (disputes, availability_assignments, most_recent_timeslot)
        target = verdict.target
        vote_index = -1
        positive_score = 0        
        for vote in verdict.votes:
            if vote.index <= vote_index:
                return "err", "judgements_not_sorted_unique", (disputes, availability_assignments, most_recent_timeslot)            
            key = None
            if not 0 <= vote.index < util.NUM_VALIDATORS_IN_EPOCH_MARK:
                return "err", "bad_validator_index", (disputes, availability_assignments, most_recent_timeslot)            
            if verdict.age == most_recent_timeslot.timeslot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS:                
                key = current_validators.validators[vote.index].ed25519
            elif verdict.age == most_recent_timeslot.timeslot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS - 1:
                key = previous_validators.validators[vote.index].ed25519
            else:
                return "err", "bad_judgement_age", (disputes, availability_assignments, most_recent_timeslot)
            try:
                out = VerifyKey(key=key).verify(smessage=(X_TRUE if vote.vote else X_FALSE) + verdict.target, signature=vote.signature)
            except:
                return "err", "bad_signature", (disputes, availability_assignments, most_recent_timeslot)
            vote_index = vote.index
            positive_score += int(vote.vote)
        if positive_score not in list(reports_scores.keys()):
            return "err", "bad_vote_split", (disputes, availability_assignments, most_recent_timeslot)
        if positive_score == GOOD_SCORE:
            found_fault = False
            for fault in extrinsic_disputes.faults:
                if fault.target == verdict.target:
                    found_fault = True
                    break;
            if found_fault == False:
                return "err", "not_enough_faults", (disputes, availability_assignments, most_recent_timeslot)
        elif positive_score == BAD_SCORE:
            found_culprits = 0
            for culprit in extrinsic_disputes.culprits:
                if culprit.target == verdict.target:
                    found_culprits += 1
                    if found_culprits == 2:
                        break
            if found_culprits < 2:
                return "err", "not_enough_culprits", (disputes, availability_assignments, most_recent_timeslot)
        reports_scores[positive_score].append(verdict.target)
    previous_validators_ed25519 = [ validator.ed25519 for validator in previous_validators.validators ]
    current_validators_ed25519 = [ validator.ed25519 for validator in current_validators.validators ]
    good_post = set(disputes.good)   | set(reports_scores[GOOD_SCORE])
    bad_post  = set(disputes.bad)    | set(reports_scores[BAD_SCORE])
    # wonky_post = set(disputes.wonky) | set(reports_scores[WONKY_SCORE])
    key = int(0).to_bytes(util.HASH_LEN_IN_BYTES)
    for culprit in extrinsic_disputes.culprits:
        if culprit.key in disputes.offenders:
            return "err", "offender_already_reported", (disputes, availability_assignments, most_recent_timeslot)
        if culprit.key not in previous_validators_ed25519 or culprit.key not in current_validators_ed25519:
            return "err", "bad_guarantor_key", (disputes, availability_assignments, most_recent_timeslot)
        if culprit.key <= key:
            return "err", "culprits_not_sorted_unique", (disputes, availability_assignments, most_recent_timeslot)
        if culprit.target not in bad_post:
            return "err", "culprits_verdict_not_bad", (disputes, availability_assignments, most_recent_timeslot)
        try:
            out = VerifyKey(culprit.key).verify(smessage=X_GUARANTEE + culprit.target, signature=culprit.signature)
        except:
            return "err", "bad_signature", (disputes, availability_assignments, most_recent_timeslot)
        key = culprit.key
    key = int(0).to_bytes(util.HASH_LEN_IN_BYTES)
    for fault in extrinsic_disputes.faults:
        if fault.key in disputes.offenders:
            return "err", "offender_already_reported", (disputes, availability_assignments, most_recent_timeslot)
        if fault.key not in previous_validators_ed25519 or fault.key not in current_validators_ed25519:
            return "err", "bad_auditor_key", (disputes, availability_assignments, most_recent_timeslot)
        if fault.key <= key:
            return "err", "faults_not_sorted_unique", (disputes, availability_assignments, most_recent_timeslot)
        if (fault.vote and fault.target not in bad_post) or (not fault.vote and fault.target not in good_post):
            return "err", "fault_verdict_wrong", (disputes, availability_assignments, most_recent_timeslot)        
        try:
            out = VerifyKey(fault.key).verify(smessage=(X_TRUE if fault.vote else X_FALSE) + fault.target, signature=fault.signature)
        except:
            return "err", "bad_signature", (disputes, availability_assignments, most_recent_timeslot)
        key = fault.key

    for i in range(util.NUM_VALIDATORS_IN_EPOCH_MARK // 3):
        if availability_assignments.assignments[i] is not None:
            report_hash = util.hash_via_blake2b(availability_assignments.assignments[i].report.encode())
            if report_hash in reports_scores[BAD_SCORE] or report_hash in reports_scores[WONKY_SCORE]:
                availability_assignments.assignments[i] = None
            
    disputes.good.extend(reports_scores[GOOD_SCORE])
    disputes.good.sort()
    disputes.bad.extend(reports_scores[BAD_SCORE])
    disputes.bad.sort()
    disputes.wonky.extend(reports_scores[WONKY_SCORE])
    disputes.wonky.sort()
    # GP 10.19    
    new_offenders = [ culprit.key for culprit in extrinsic_disputes.culprits ]
    new_offenders.extend([ fault.key for fault in extrinsic_disputes.faults ])
    # The offenders marker is just the new_offenders list
    disputes.offenders.extend(new_offenders)
    disputes.offenders.sort()

    return "ok", new_offenders, (disputes, availability_assignments, most_recent_timeslot)