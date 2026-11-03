"""Guarantor assignments — GP 0.7.2/0.8.0 text/reporting_assurance.tex
(§"Guarantor Assignments", eq:guarantorsig, eq:priorassignments).

This is the machinery that decides WHICH validator is allowed to guarantee a
work-report on a given core in a given rotation, and WHICH Ed25519 key that
validator's guarantee credential must therefore carry.  It is shared by:

  * the REPORTS step (jam_impl/reports.py) — it checks that every guarantee
    credential was signed by the validator assigned to that core in the
    guarantee's rotation, and it produces the REPORTERS set as its output;
  * the STATISTICS step (jam_impl/statistics.py) — via the reporters set the
    reports step hands it (the statistics step does not re-derive it).

GP 0.7.2:

    R(c, n)   ≡ [(x + n) mod Ccorecount | x ∈ c]
    P(v, e, t) ≡ R(fy-shuffle([Ccorecount·i/Cvalcount | i ∈ valindex], e),
                   (t mod Cepochlen)/Crotationperiod)
    guarantorassignments ≡ (P(|activeset'|, entropy'_2, time'), Φ(activeset'))

    guarantorassignmentsunderlastrotation ≡ (P(|k|, e, time' - Crotationperiod),
                                              Φ(k))
      where (k, e) = (activeset', entropy'_2)  if (time'-Crotationperiod)/Cepochlen
                                                  = time'/Cepochlen
                    = (previousset', entropy'_3) otherwise

    eq:guarantorsig picks WHICH assignment applies per guarantee:

      (c, k) = guarantorassignments                 if time'/Crotationperiod
                                                    = g.timeslot/Crotationperiod
             = guarantorassignmentsunderlastrotation otherwise

      and the reporters set is

      k ∈ reporters ⟺ ∃ (workreport, timeslot, credential) ∈ E_G,
                        ∃ (v, s) ∈ credential : k = (k_v).ed25519

NOTE the reporters set is a set of KEYS, not validator indices — and the
statistics step's increment is a key-membership test against the CURRENT
validator set (κ'), so a validator is credited once no matter how many
guarantees they signed.

The 0.7.2 "previous rotation" assignment uses the CURRENT validator set with
the previous rotation's permutation when the rotation did not cross an epoch
boundary, and the PREVIOUS validator set (λ') with entropy'_3 otherwise
(see eq:priorassignments above).
"""
from dataclasses import dataclass

import jam_impl.util as util
from jam_impl.models.State import ValidatorData
from jam_impl.models.Extrinsic import Guarantee


@dataclass
class GuarantorAssignments:
    """The (core-per-validator permutation, validator set) pair of GP
    \\guarantorassignments — the permutation is indexed by validator index and
    holds the CORE that validator is assigned to guarantee on."""
    permutation: list[int]
    validators: list[ValidatorData]


def core_rotation(arr: list, n: int):
    """GP R(c, n): rotate the core indices by n (mod core count)."""
    return [(x + n) % util.core_count() for x in arr]


def core_permutation(entropy: bytes, slot: int):
    """GP P(v, e, t): the validator→core permutation for one rotation.

    The shuffle seed is the epochal entropy (η'_2) and the rotation is
    (slot mod Cepochlen) / Crotationperiod."""
    lst = [util.core_count() * i // util.NUM_VALIDATORS_IN_EPOCH_MARK
           for i in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)]
    return core_rotation(
        util.fisher_yates_shuffle_from_hash32(lst, entropy),
        (slot % util.LENGTH_OF_EPOCH_IN_TIMESLOTS) // util.ROTATION_PERIOD)


def guarantor_assignments(validators: list[ValidatorData], entropy: bytes,
                          slot: int, offenders: list[bytes]) -> GuarantorAssignments:
    """GP \\guarantorassignments for THIS block's rotation: the permutation
    from the epochal entropy (η'_2), and the validator set with the offenders
    removed (an offender may not guarantee)."""
    from jam_impl.safrole import remove_offenders   # lazy: keeps this module light
    return GuarantorAssignments(
        permutation=core_permutation(entropy, slot),
        validators=remove_offenders(validators, offenders))


def prior_guarantor_assignments(current_validators: list[ValidatorData],
                                previous_validators: list[ValidatorData],
                                entropy_same_epoch: bytes,
                                entropy_new_epoch: bytes,
                                slot: int,
                                offenders: list[bytes]) -> GuarantorAssignments:
    """GP \\guarantorassignmentsunderlastrotation (eq:priorassignments): the
    assignment as it was in the PREVIOUS rotation.

    Same epoch  → the CURRENT validator set, the previous rotation's
                  permutation, seeded with entropy_same_epoch (η'_2).
    New epoch   → the PREVIOUS validator set (λ'), the previous rotation's
                  permutation, seeded with entropy_new_epoch (η'_3).
    """
    from jam_impl.safrole import remove_offenders
    same_epoch = ((slot - util.ROTATION_PERIOD)
                  // util.LENGTH_OF_EPOCH_IN_TIMESLOTS
                  == slot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
    if same_epoch:
        return GuarantorAssignments(
            permutation=core_permutation(entropy_same_epoch,
                                         slot - util.ROTATION_PERIOD),
            validators=remove_offenders(current_validators, offenders))
    return GuarantorAssignments(
        permutation=core_permutation(entropy_new_epoch,
                                     slot - util.ROTATION_PERIOD),
        validators=remove_offenders(previous_validators, offenders))


def assignment_for_guarantee(guarantee: Guarantee, current_slot: int,
                              current: GuarantorAssignments,
                              prior: GuarantorAssignments) -> GuarantorAssignments:
    """Which assignment applies to this guarantee (eq:guarantorsig): the
    current one when the guarantee's timeslot is in this block's rotation,
    the previous-rotation one otherwise."""
    if guarantee.slot // util.ROTATION_PERIOD == current_slot // util.ROTATION_PERIOD:
        return current
    return prior


def reporters_from_guarantees(guarantees: list[Guarantee], current_slot: int,
                              current: GuarantorAssignments,
                              prior: GuarantorAssignments) -> list[bytes]:
    """The REPORTERS set of eq:guarantorsig: the sorted, de-duplicated Ed25519
    keys of the validators whose credentials appear in the guarantees.

    The key of a credential is read from the assignment that applies to THAT
    guarantee (its own timeslot decides the rotation), so a guarantee from
    the previous rotation is credited to the previous validator set.
    """
    reporters: list[bytes] = []
    for guarantee in guarantees:
        assignments = assignment_for_guarantee(
            guarantee, current_slot, current, prior)
        for signature in guarantee.signatures:
            if not 0 <= signature.validator_index < len(assignments.validators):
                continue
            key = assignments.validators[signature.validator_index].ed25519
            if key not in reporters:
                reporters.append(key)
    reporters.sort()
    return reporters


def reporters_from_validator_indices(guarantees: list[Guarantee],
                                     validators: list[ValidatorData]) -> list[bytes]:
    """The VECTOR-STANDALONE form of the reporters set: every credential
    signer's key read from a SINGLE validator set.

    Used only by the standalone stf/statistics harness, whose state leg ships
    one validator set (κ') and no rotation context.  In the total state
    transition the reporters set is the REPORTS step's output and is resolved
    rotation-aware (see reporters_from_guarantees)."""
    keys: list[bytes] = []
    for guarantee in guarantees:
        for signature in guarantee.signatures:
            if not 0 <= signature.validator_index < len(validators):
                continue
            key = validators[signature.validator_index].ed25519
            if key not in keys:
                keys.append(key)
    keys.sort()
    return keys
