"""Statistics STF — GP 0.7.2 §"Validator Activity" (text/statistics.tex),
the π_V accumulator / π_L previous-epoch table.

    statistics_stf(validators_curr_stats, validators_last_stats,
                   current_validators, reporters, tickets, preimages,
                   assurances, block_slot, author_index, prior_slot,
                   spec) -> None

Flat semantic args, mutating the repo's state models in place (house style of
reports_stf / preimages_stf / history_stf / authorizations_stf):

    validators_curr_stats: list[ValidatorStatistics] — π_V accumulator (mutated)
    validators_last_stats: list[ValidatorStatistics] — π_L previous (mutated)
    current_validators:    list[ValidatorData]       — κ' (read-only)
    reporters:             Collection[bytes]          — the REPORTERS KEY SET
                                                         (eq:guarantorsig)
    tickets:               list[Ticket]              — E_T (read-only)
    preimages:             list[Preimage]            — E_P (read-only)
    assurances:            list[Assurance]           — E_A (read-only)
    block_slot:            int                       — H_t (this block's timeslot)
    author_index:          int                       — H_i (the block author)
    prior_slot:            int                       — τ  (the state's prior timeslot)

The output leg is NULL — this step never errs, so the stub returns None.

GP equation map (0.7.2 text/statistics.tex — the version these vectors were
generated against; the 0.8.0 text orders the epoch switch AFTER the
assurance bump, the vectors require the 0.7.2 order — see the harness
docstring for the full discrepancy note):

    epoch switch:
        (a, previous') ≡ (accumulator, previous)   if e' = e
                         (zeros,     accumulator)  otherwise
        where e = τ // Cepochlen, e' = H_t // Cepochlen

    per validator v:
        accumulator'[v].blocks        = a[v].blocks + (v = H_i)
        accumulator'[v].tickets       = a[v].tickets + |E_T|          (if v = H_i)
        accumulator'[v].preimagecount = a[v].preimagecount + |E_P|   (if v = H_i)
        accumulator'[v].preimagesize  = a[v].preimagesize
                                        + Σ_{d ∈ E_P} |d|           (if v = H_i)
        accumulator'[v].guarantees    = a[v].guarantees + (κ'[v] ∈ reporters)
        accumulator'[v].assurances    = a[v].assurances
                                        + (∃ a ∈ E_A : a.assurer = v)

    reporters = the SET of Ed25519 keys of the guarantee credential signers
                (eq:guarantorsig).  It is an INPUT of this step, not
                something it derives: in the total state transition the
                reporters set is DEFINED by the guarantees step, which owns
                the rotation-aware key resolution (a credential signed in
                this block's rotation carries a κ' key, one from the previous
                rotation a λ' key — eq:guarantorsig / eq:priorassignments).
                The guarantees step already produces it as its output (the
                reports wire output leg carries the sorted reporter keys),
                so the total transition threads that output into this step.

                The guarantee increment is a membership indicator —
                (κ'[v] ∈ reporters) — so a validator that signed two
                guarantees in one block is credited ONCE.

    preimagesize counts the BLOB octets only (the ↕ length prefix is not
    part of the data).

    ALIASING PITFALL: on an epoch switch the OLD accumulator becomes the
    previous table — SNAPSHOT it (prev = list(curr)), because writing
    `curr[:] = acc` afterwards would otherwise destroy the very list `prev`
    names.  The harness catches this on the epoch-change vectors.

    No signature verification happens here: the statistics leg only counts
    what the extrinsic contains; validity of E_A / E_G is the assurances and
    reports legs' business.
"""
from collections.abc import Collection

import jam_impl.util as util
from jam_impl.models.State import ValidatorStatistics, ValidatorData
from jam_impl.models.Extrinsic import Ticket, Preimage, Assurance


def statistics_stf(validators_curr_stats: list[ValidatorStatistics],  # π_V (mutated)
                   validators_last_stats: list[ValidatorStatistics],  # π_L (mutated)
                   current_validators: list[ValidatorData],           # κ' (read-only)
                   reporters: Collection[bytes],                       # reporters (read-only)
                   tickets: list[Ticket],                              # E_T (read-only)
                   preimages: list[Preimage],                          # E_P (read-only)
                   assurances: list[Assurance],                        # E_A (read-only)
                   block_slot: int,                                    # H_t
                   author_index: int,                                  # H_i
                   prior_slot: int,                                    # τ
                   spec: str = "tiny") -> None:    
    if block_slot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS > prior_slot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS:
        validators_last_stats[:] = validators_curr_stats
        validators_curr_stats[:] = [ValidatorStatistics() for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)]    
    validators_curr_stats[author_index].blocks += 1
    validators_curr_stats[author_index].tickets += len(tickets)
    validators_curr_stats[author_index].pre_images += len(preimages)
    validators_curr_stats[author_index].pre_images_size += sum([len(preimage.blob) for preimage in preimages])
    for i in range(util.NUM_VALIDATORS_IN_EPOCH_MARK):
        validators_curr_stats[i].assurances += sum([1 for assurance in assurances if assurance.validator_index == i])
        if current_validators[i].ed25519 in reporters:
            validators_curr_stats[i].guarantees += 1    
    return None
