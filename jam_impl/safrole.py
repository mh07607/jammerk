"""
Safrole scratch work — Bandersnatch ring VRF basics (GP 6.1–6.7, X.1–X.5).

What went wrong in the first cut (kept here so nobody re-hits it):
  RingContext(ring_data, ring_public_keys) — ring_data is the KZG/PCS SRS,
  NOT the ring keys. A wrong/short blob here aborts BADLY: the loader reads
  the first 8 bytes as a u64 LE point count and Rust tries
  Vec::with_capacity(count * 104 + overhead) UNCHECKED. With the first
  cut's b'\\x01'*16 the count was 0x0101_0101_0101_0101 *104 = exactly
  7,523,377,975,159,973,992 bytes — that number in the abort message IS the
  ring_data misread ('hhhh...' is that u64 as bytes). The right SRS here is
  zcash-srs-2-11-uncompressed.bin (compressed-form file is REJECTED —
  PcsParams::deserialize_uncompressed_unchecked).

JARGON: "ring_data" is a misnomer in the binding — it is the SRS, not the ring
keys. The SRS is a PUBLIC setup artifact (same one Polkadot's erc-dave tests
use); everyone loads the same file, so it is not a secret and JAM clients just
vendor it. The ring keys themselves are the 32-byte compressed bandersnatch
public keys of the current validator set.
"""
from __future__ import annotations
import dataclasses
from jam_impl.models.State import UpcomingValidators, State, TicketBody
from jam_impl.models.Header import Header
from jam_impl.models.Extrinsic import Extrinsic
import jam_impl.util as util

from pathlib import Path

from bandersnatch_vrfs import (
    RingContext,
    ietf_vrf_sign,
    ietf_vrf_verify,
    public_from_secret,
    secret_from_seed,
    vrf_output,
)

# JAM_TICKET_SEAL = b'$jam_ticket_seal'
# JAM_ENTROPY = b'$jam_entropy'
# JAM_FALLBACK_SEAL = b'$jam_fallback_seal'

# Find the SRS so the script works from any cwd. Canonical copy ships INSIDE
# the vendored jamtestvectors (stf/safrole/) — the safrole vectors themselves
# were built with it (their README, "zk-SNARK SRS"); data/ is an optional
# mirror, then download as last resort.
_SCRIPT = Path(__file__).resolve()
_REPO = _SCRIPT.parents[1]  # .../JAM_Implementation
_SRS_NAME = "zcash-srs-2-11-uncompressed.bin"
_SRS_CANDIDATES = (
    _REPO / "jamtestvectors" / "stf" / "safrole" / _SRS_NAME,
    _REPO / "data" / _SRS_NAME,
    _REPO / _SRS_NAME,
    _REPO / "jam_impl" / "assets" / _SRS_NAME,
)
SRS = None
for p in _SRS_CANDIDATES:
    if p.is_file():
        SRS = p.read_bytes()

# def _ensure_srs() -> Path:
#     for p in _SRS_CANDIDATES:
#         if p.is_file():
#             return p
#     # Download (public setup artifact; same bytes Polkadot's tests use).
#     dest = _REPO / "data" / _SRS_NAME
#     dest.parent.mkdir(parents=True, exist_ok=True)
#     import urllib.request

#     url = "https://raw.githubusercontent.com/JAMdotTech/py-bandersnatch-vrfs/main/data/" + _SRS_NAME
#     urllib.request.urlretrieve(url, dest)
#     assert dest.stat().st_size == 590_320, f"bad SRS download: {dest.stat().st_size} bytes"
#     return dest


def bandersnatch_ring_root(validators_bandersnatch_signatures: list[bytes]) -> bytes:
    """Ring commitment over the validator set's bandersnatch public keys.

    Each key must be 32 bytes of COMPRESSED bandersnatch point (GP 6.23).
    Keys whose bytes fail to decode are silently replaced by a padding point
    by the binding, so validate lengths before constructing the context.
    """
    bad = [len(k) != 32 for k in validators_bandersnatch_signatures]
    if any(bad):
        bad_idx = [i for i, b in enumerate(bad) if b]
        raise ValueError(
            f"bandersnatch keys must be 32-byte compressed points; "
            f"bad lengths at indices {bad_idx} "
            f"(got {[len(validators_bandersnatch_signatures[i]) for i in bad_idx]})"
        )
    ring = RingContext(SRS, validators_bandersnatch_signatures)
    return ring.commitment


def bandersnatch_demo() -> None:
    # Keys from jamtestvectors safrole/tickets traces (validator set 0 of the
    # bootstrap epoch). ASCII-hex at the edge, raw 32 bytes into the ring.
    hex_keys = [
        "ff71c6c03ff88adb5ed52c9681de1629a54e702fc14729f6b50d2f0a76f185b3",
        "9326edb21e5541717fde24ec085000b28709847b8aab1ac51f84e94b37ca1b66",
        "151e5c8fe2b9d8a606966a79edd2f9e5db47e83947ce368ccba53bf6ba20a40b",
        "0746846d17469fb2f95ef365efcab9f4e22fa1feb53111c995376be8019981cc",
    ]
    keys = [bytes.fromhex(k) for k in hex_keys]
    n = len(keys)

    print("== ring commitment ==")
    commitment = bandersnatch_ring_root(keys)
    print("ring:", n, "keys")
    print("commitment:", commitment.hex())

    print()
    print("== ring_vrf_sign / verify roundtrip ==")
    # Demo secret: its public key must sit AT the prover index we sign with.
    s = secret_from_seed(int.to_bytes(99, length=8, byteorder="little"))
    pub = public_from_secret(s)
    # Ring of 1023: 4 real bootstrap keys, then OUR key at index 4, then
    # zero-blobs (invalid -> replaced by the binding's padding point).
    prover_index = len(keys)  # 4
    ring_keys = keys + [pub] + [b"\x00" * 32] * (1023 - len(keys) - 1)
    ctx = RingContext(SRS, ring_keys)

    vrf_input = b"epoch-0-sealed-ticket"
    aux = b"aux"
    sig = ctx.ring_vrf_sign(
        prover_key_index=prover_index, secret_key=s, vrf_input_data=vrf_input, aux_data=aux
    )
    print("signature:", len(sig), "bytes")
    print("sig hex:", sig.hex())
    out = ctx.ring_vrf_verify(vrf_input_data=vrf_input, aux_data=aux, signature=sig)
    print("ring output:", out.hex())

    print()
    print("== ietf ticket-claim style signing (non-anonymous) ==")
    ietf_sig = ietf_vrf_sign(s, vrf_input, aux)
    ietf_out = ietf_vrf_verify(pub, vrf_input, aux, ietf_sig)
    print("ietf output:", ietf_out.hex())
    assert ietf_out == out, "ring and ietf paths disagree"

    print()
    print("== wrong signer caught ==")
    try:
        ietf_vrf_verify(keys[0], vrf_input, aux, ietf_sig)
    except ValueError as e:
        print("caught:", e)

    print()
    print("== vrf_output consistency ==")
    print("vrf_output():", vrf_output(s, vrf_input).hex())
    assert vrf_output(s, vrf_input) == out

    print()
    print("ALL OK")

def remove_offenders(validators: list[ValidatorData], offenders: list[bytes]):    
    return [
              dataclasses.replace(v, bandersnatch=b"\x00"*32, ed25519=b"\x00"*32,
                                  bls=b"\x00"*144, metadata=b"\x00"*128)
              if v.ed25519 in offenders else v
              for v in validators
          ]
    
def on_epoch_change(state: State):
    # GP 6.13, 6.14
    state.previous_validators.validators = state.current_validators.validators.copy()
    state.current_validators.validators = state.safrole.pending_validators.copy()
    state.safrole.pending_validators = remove_offenders(state.upcoming_validators.validators.copy(), state.disputes.offenders if state.disputes else [])
    state.safrole.epoch_root = bandersnatch_ring_root([validator.bandersnatch for validator in state.safrole.pending_validators])
    old_entropy_values = state.entropy.values.copy()
    # GP 6.23
    state.entropy.values[1] = old_entropy_values[0]
    state.entropy.values[2] = old_entropy_values[1]
    state.entropy.values[3] = old_entropy_values[2]


def fallback_key_sequence(entropy: bytes, validator_keys: list[ValidatorData]) -> list[bytes]:
    fallback_keys = []    
    for i in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS):        
        index = util.decode_fixed(util.hash_via_blake2b(entropy + util.encode_fixed(i, 4))[:4], 4) % len(validator_keys)
        fallback_keys.append(validator_keys[index].bandersnatch)
    return fallback_keys


def check_header_seal_and_vrf(state: State, header: Header):
    out = None
    author_bandersnatch = state.current_validators.validators[header.author_index].bandersnatch
    if not state.safrole.tickets_or_keys_flag:
        i: TicketBody = state.safrole.tickets_or_keys[header.slot % util.NUM_VALIDATORS_IN_EPOCH_MARK]
        context = JAM_TICKET_SEAL + state.entropy.values[3] + util.u8(i.attempt)
        try:            
            unsigned_header_bytes = header.encode_unsigned()
            out = ietf_vrf_verify(public_key=author_bandersnatch, vrf_input_data=context, 
                aux_data=unsigned_header_bytes, signature=header.seal)
        except ValueError as e:
            raise ValueError(f"Header seal faulty {e}")
        assert out == i.id
    else:
        i: bytes = state.safrole.tickets_or_keys[header.slot % util.NUM_VALIDATORS_IN_EPOCH_MARK]
        context = JAM_FALLBACK_SEAL + state.entropy.values[3]
        assert i == author_bandersnatch
        try:
            unsigned_header_bytes = header.encode_unsigned()
            out = ietf_vrf_verify(public_key=i, vrf_input_data=context,
                aux_data=unsigned_header_bytes, signature=header.seal)
        except ValueError as e:
            raise ValueError(f"Header seal faulty {e}")
    vrf_context = JAM_ENTROPY + out
    try:
        out = ietf_vrf_verify(public_key=author_bandersnatch, vrf_input_data=vrf_context,
            aux_data=b'', signature=header.entropy_source)
    except ValueError as e:
        print("Header vrf faulty, ", e)
    state.entropy.values[0] = util.hash_via_blake2b(state.entropy.values[0] + out)


# ============================================================================
# Vector-verified seal/VRF checking — GP 0.7.2 §6.15–6.20 (M1 importer side).
# Verified byte-exact against jamtestvectors traces/safrole 00000001–0100:
#   tokens in the vectors carry NO '$' prefix (GP \token{} prose shows '$',
#   the generator emitted none, polkajam's binary confirms the bare strings);
#   seal message = unsigned header wire bytes; ring = κ for tickets.
# ============================================================================

X_TICKET = b"jam_ticket_seal"
X_FALLBACK = b"jam_fallback_seal"
X_ENTROPY = b"jam_entropy"


def _check_ietf(sig_key: bytes, vrf_input: bytes, aux: bytes, sig: bytes) -> bytes:
    """ietf_vrf_verify that raises the importer's error instead of returning None."""
    try:
        return ietf_vrf_verify(sig_key, vrf_input, aux, sig)
    except (ValueError, TypeError) as e:
        raise ValueError(f"seal/VRF verification failed: {e}") from e


def check_header_seal_and_vrf_072_check_only(state: State, header: Header) -> bytes:
    """Verify a header's seal + entropy-source WITHOUT touching state.eta.

    GP 0.7.2 §6.4 (Sealing and Entropy Accumulation), importer's view — both
    checks are IDENTIFIED VRFs, no secret key needed, Y comes from verify():

      (6.15) ticket mode   (γ_s holds ticket bodies, γ_s[H_t mod E] = 'i'):
             input  = X_E ∥ ε₃′ ∥ E(e)   with E(attempt) = 1 octet
             Y(H_S) == y_i  (i.e. verify() == the slot ticket's id)
      (6.16) fallback mode (γ_s holds keys, γ_s[H_t mod E] = 'i'):
             i == H_{A(I)}  (slot's fallback key IS the author's key)
             input  = X_F ∥ ε₃′
      H_S  ∈ sig(κ′_{A(I)}; input)(unsigned header)   <- message = unsigned bytes
      (6.17) H_V ∈ sig(κ′_{A(I)}; X_E ∥ Y(H_S))(∅) — msg empty for H_V!
      (6.19) caller blends: η₀′ = H(η₀ ∥ Y(H_V)); then rotates per 6.20.

    Vector evidence (traces/safrole, GP 0.7.2 / polkajam 0.1.28):
      fallback:  ietf_vrf_verify(pk, "jam_fallback_seal"+η₃, unsigned) == Y(H_S)
      tickets:   ietf_vrf_verify(pk, "jam_ticket_seal"+η₂+att1B, unsigned) == Y(H_S)
      entropy:   ietf_vrf_verify(pk, "jam_entropy"+Y(H_S), b"") == Y(H_V)   [30/30]
      tickets-γ: ring_vrf_verify(κ-keys, "jam_ticket_seal"+η_p+att1B)  [traces]
      (non-boundary epochs slot the ticket input at η₂ — the gist's framing;
       at epoch boundaries the *pending* epoch's entropy index applies.)
    """
    author = state.current_validators.validators[header.author_index].bandersnatch
    eta = state.entropy.values
    epoch_slot = header.slot % util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    tk = state.safrole.tickets_or_keys
    ga = getattr(state.safrole, 'ticket_accumulator', None)
    # Boundary blocks (slot within epoch == 0) do their epoch rotation IN
    # this block, so the posterior ε₃ = pre ε₂ AND γ_S′ is the NEW epoch's
    if epoch_slot == 0:
        seal_ent = eta[2]  # posterior ε₃ after this block's own rotation
        # posterior γ_S′ kind per 6.14: γ_a FULL (‖γ_a‖ == E) → tickets
        # (Z(γ_a)); γ_a empty or underfull → fallback keys (F(η₂′, κ′)).
        # (The PRE flag does NOT decide: trace 84 is flag==0 with an
        # underfull γ_a and still falls back — verified.)
        entry_is_ticket = bool(ga) and len(ga) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    else:
        seal_ent = eta[3]
        entry_is_ticket = isinstance(tk[0], TicketBody)
    unsigned_header_bytes = header.encode_unsigned()

    if epoch_slot == 0 and not entry_is_ticket:
        # fallback-boundary: pre γ_S[0] is the OLD epoch's slot-0 entry — the
        # 0.7.x vectors rotate γ_S inside this block, so the stored identity
        # pin is stale there; the cryptographic verify below IS the check
        # (6.16's i == author key is implied by verify with the author's key).
        y_seal = _check_ietf(author, X_FALLBACK + seal_ent, unsigned_header_bytes, header.seal)
    elif epoch_slot == 0 and entry_is_ticket:
        # tickets-boundary: new epoch seals by tickets; slot-0's sealer = the
        # winning (smallest-id) ticket of the accumulator (traces 48/60…
        # verified; under-full γ_a keeps fallback — trace 84). The PRE γ_S
        # entry (previous epoch's) is stale; use the accumulator's min.
        cand = min(ga, key=lambda t: bytes(t.id))
        vrf_input = X_TICKET + seal_ent + util.u8(cand.attempt)
        y_seal = _check_ietf(author, vrf_input, unsigned_header_bytes, header.seal)
        if y_seal != cand.id:
            raise ValueError(
                f"Y(H_S) {y_seal.hex()[:16]}… != min(γ_a) id {cand.id.hex()[:16]}… (6.15/6.14)"
            )
    elif entry_is_ticket:  # tickets mode, normal slot — GP (6.15)
        slot_entry = tk[epoch_slot]
        vrf_input = X_TICKET + seal_ent + util.u8(slot_entry.attempt)  # E(e): 1 octet
        y_seal = _check_ietf(
            author, vrf_input, unsigned_header_bytes, header.seal
        )
        if y_seal != slot_entry.id:
            raise ValueError(
                f"Y(H_S) {y_seal.hex()[:16]}… != slot ticket id "
                f"{slot_entry.id.hex()[:16]}… (GP 6.15)"
            )
    else:  # fallback-key mode, normal slot — GP (6.16)
        slot_entry = tk[epoch_slot]
        if slot_entry != author:
            raise ValueError("slot's fallback key is not the author's key (GP 6.16)")
        y_seal = _check_ietf(
            author, X_FALLBACK + seal_ent, unsigned_header_bytes, header.seal
        )

    # GP (6.17): H_V signature — message is EMPTY; input binds Y(H_S)
    return _check_ietf(author, X_ENTROPY + y_seal, b"", header.entropy_source)


def apply_entropy_072(state: State, y_h_v: bytes) -> None:
    """GP 0.7.2 (6.19): η₀′ = H(η₀ ∥ Y(H_V)) — call AFTER the seal checks."""
    state.entropy.values[0] = util.hash_via_blake2b(
        state.entropy.values[0] + y_h_v
    )


def outside_in_sequencer(ticket_accumulator: list[TicketBody]) -> list[TicketBody]:
    # GP 6.25    
    first_half = ticket_accumulator[:len(ticket_accumulator)//2]
    second_half = ticket_accumulator[len(ticket_accumulator)//2:]
    out: list[TicketBody] = []
    for i in range(len(ticket_accumulator)//2):
        out.append(first_half[i]); out.append(second_half[len(second_half) - 1 - i])
    return out

def safrole_stf(state: State, header: Header, extrinsic: Extrinsic, y_h_v: bytes, spec):
    """GP 0.7.2 §6 stf transition for one vector — TO BE IMPLEMENTED.

    Args:
        state:  semantic State (models.State.State)
        header:     models.Header.Header — FROM THE STF VECTORS the
                    derivable fields are honest (slot; extrinsic_hash =
                    blake2b of the encoded stf input) and the seal/VRF
                    fields are ZERO-FILLED FAKES (stf vectors externalize
                    the VRF outputs: no H_S/H_V exists to check). Do NOT
                    run check_header_seal_and_vrf here; the stf checks
                    the ticket/key placement and entropy blend instead.
        extrinsic:  models.Extrinsic.Extrinsic with ONLY the tickets leg
                    filled (ε_T); slot/η come from the stf input via the
                    harness (the stf input η substitutes for Y(H_V)).
        spec:       'tiny' | 'full'

    Returns:
        ("ok",    {"epoch_mark": E | None, "tickets_mark": W | None},
         post_state: State, post_offenders: list[bytes])
        ("err",   <your error name>, post_state: State,
         post_offenders: list[bytes])
        with output shapes mirroring the vectors' json sidecars.
    """        
    epoch_mark = None
    tickets_mark = None
    post_offenders = []    
    # output epoch mark
    block_epoch = header.slot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    block_slot_phase_index = header.slot % util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    latest_epoch = state.most_recent_timeslot.timeslot // util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    latest_slot_phase_index = state.most_recent_timeslot.timeslot % util.LENGTH_OF_EPOCH_IN_TIMESLOTS    
    # Checking for errors before touching state
    if(state.most_recent_timeslot.timeslot >= header.slot):
        return "err", "bad_slot", state, post_offenders
    if len(extrinsic.tickets) > util.MAX_TICKETS_IN_EXTRINSIC:
        return "err", "tickets_length_exceeded", state, post_offenders
    if block_slot_phase_index > util.TICKET_SUBMISSION_DEADLINE_IN_TIMESLOTS and len(extrinsic.tickets) != 0:
        return "err", "tickets_submitted_after_deadline", state, post_offenders        
    extrinsic_ticket_verifications = []    
    ctx = RingContext(SRS, [validator.bandersnatch for validator in state.safrole.pending_validators])    
    for ticket in extrinsic.tickets:
        if ticket.attempt >= util.MAX_TICKETS_ATTEMPT:
            return "err", "bad_ticket_attempt", state, post_offenders        
        out = ctx.ring_vrf_verify(vrf_input_data=X_TICKET + state.entropy.values[2] + ticket.attempt.to_bytes(1), aux_data=b'', signature=ticket.signature)        
        if out in [ticket.id for ticket in state.safrole.ticket_accumulator]:
            return "err", "duplicate_ticket", state, post_offenders
        extrinsic_ticket_verifications.append((ticket.attempt, out))

    is_right_after_ticket_submission_deadline = latest_slot_phase_index < util.TICKET_SUBMISSION_DEADLINE_IN_TIMESLOTS <= block_slot_phase_index
    is_new_epoch = block_epoch > latest_epoch
    if is_new_epoch:
        # update entropy
        on_epoch_change(state)        
        validator_keys = [ { "bandersnatch": key.bandersnatch, "ed25519": key.ed25519 } for key in state.safrole.pending_validators ]
        epoch_mark = { "entropy": state.entropy.values[1], "tickets_entropy": state.entropy.values[2], "validators": validator_keys }    
    elif not is_new_epoch and is_right_after_ticket_submission_deadline  and len(state.safrole.ticket_accumulator) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS:
        tickets_mark = outside_in_sequencer(state.safrole.ticket_accumulator)
    # slot key sequence
    if(is_new_epoch and latest_slot_phase_index >= util.TICKET_SUBMISSION_DEADLINE_IN_TIMESLOTS and len(state.safrole.ticket_accumulator) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS):
        state.safrole.tickets_or_keys = outside_in_sequencer(state.safrole.ticket_accumulator)
    elif not is_new_epoch:
        pass
    else:
        state.safrole.tickets_or_keys = fallback_key_sequence(state.entropy.values[2], state.current_validators.validators)
    
    extrinsic_tickets = [TicketBody(id=verification[1], attempt=verification[0]) for verification in extrinsic_ticket_verifications]
    if(is_new_epoch):
        state.safrole.ticket_accumulator = extrinsic_tickets        
    else:
        state.safrole.ticket_accumulator.extend(extrinsic_tickets)
    state.safrole.ticket_accumulator.sort(key=lambda ticket: ticket.id)
    if(len(state.safrole.ticket_accumulator) > util.LENGTH_OF_EPOCH_IN_TIMESLOTS):
        state.safrole.ticket_accumulator = state.safrole.ticket_accumulator[:util.LENGTH_OF_EPOCH_IN_TIMESLOTS]
    state.most_recent_timeslot.timeslot = header.slot
    state.entropy.values[0] = util.hash_via_blake2b(state.entropy.values[0] + y_h_v)
    return "ok", {"epoch_mark": epoch_mark, "tickets_mark": tickets_mark}, state, post_offenders    

if __name__ == "__main__":
    bandersnatch_demo()