"""STF harness: run a safrole stf vector through `safrole_stf` (the stub
you will implement in jam_impl/safrole.py) and compare the encoded
post_state against the vector's post_state bytes, plus the marks.

Layout of every file this touches (all verified byte-exact against the
vendored jamtestvectors, tiny and full):

  stf/safrole/<spec>/<name>.bin = INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input     = τ_input(E4) η_input(32) ↕ tickets[(attempt:1, sig:784)]
    state     = τ(E4) η(4×32) λ κ γₖ ι (V × [b32 e32 bls144 meta128])
                γ_a(↕ n×[id32 att1]) γₛ-flag(1)
                γₛ = flag1: E×32 keys | flag0: E×[id32 att1 tickets]
                γ_z(144) offenders(↕ n×32)
    output    = 00 ok { E-mark ¿(01 η₀ 32 η₁ 32 κ V×[b32 e32])
                        W-mark ¿(01 E×[id32 att1] — FIXED E, no ↕!) }
                | 01 err  ← variants: bad_slot, bad_ticket_attempt,
                    duplicate_ticket, bad_ticket_order, bad_ticket_proof,
                    unexpected_ticket… (payload shapes differ per variant;
                    this harness locates post_state by anchor then, so the
                    payload is passed through opaquely)
    post      = same shape as pre_state

  stf/accumulate/<spec>/<name>.bin = INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input     = slot(E4) ↕ reports
    state     = slot(E4) entropy(32)
                ready_queue [E × (↕ n×[report + ↕ deps])]
                accumulated [E × (↕ n×32B hash)]
                privileges 5×E4 (bless, assign×C, designate, register)
                statistics  ↕ n×[id E4 + record]
                accounts    ↕ n×[id E4 + account…]
    (walked + verified on tiny/queues_are_shifted-2; accounts internals
     not needed pre-implementation — passthrough handles them)

Contract with the stub (in jam_impl/safrole.py):

  NOTE on dump semantics: `safrole_stf` receives `pre` BY REFERENCE and (by
  stf design) mutates it in place — `header`/`inp`/`pre` in the debug json
  are dumps of those same objects taken AFTER the call returned. A
  safrole_stf that runs epoch-change logic therefore leaves `pre` holding
  POST-change content (e.g. pending_validators rotated to [] or ι). The
  honest pre-state is the sidecar's pre_state (and `expected_post` for the
  target); pre-wire offsets live in post_state_span only for err vectors.

    safrole_stf(pre_state: State, header: Header, extrinsic: Extrinsic, spec)
      → ("ok", {"epoch_mark": …, "tickets_mark": …},
              post_state: State, post_offenders: list[bytes])
      → ("err", err_name, post_state: State, post_offenders: list[bytes])

  The stf vectors externalize the VRF outputs: they carry NO seal/H_V, so
  the Header built here has honest derivable fields (slot; H_X = blake2b
  of the encoded stf input) and zero-filled fake seal fields, and the stf
  input's η substitutes for Y(H_V) (verified: post η₀ = blake2b(pre η₀ ‖
  η_input) on every ok vector). Do NOT run check_header_seal_and_vrf
  inside the stf on these headers.

  Ticket ring-verification IS part of the stf: verify each extrinsic
  ticket against the γₖ ring (ctx = b"jam_ticket_seal" + PRE η₂ +
  attempt-octet, aux = b""), giving Y = ticket id. γₖ, not κ: γ_z is
  γₖ's ring root (GP 0.7.2 6.6/6.7).

Usage:
    uv run jam_impl/tests/stf_harness.py jamtestvectors/stf/safrole/tiny/publish-tickets-no-mark-2
    uv run jam_impl/tests/stf_harness.py            # all safrole vectors
    uv run jam_impl/tests/stf_harness.py --accumulate jamtestvectors/stf/accumulate/tiny/queues_are_shifted-2
"""
import dataclasses
import glob
import json
import os
import sys
import copy
from typing import Any

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from jam_impl.util import Decoder, Encoder, hash_via_blake2b
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.state_codec import (
    decode_validator_list, encode_validator_list,
    decode_most_recent_timeslot, encode_most_recent_timeslot,
    decode_entropy_accumulator, encode_entropy_accumulator,
    decode_previous_validators, encode_previous_validators,
    decode_current_validators, encode_current_validators,
    decode_upcoming_validators, encode_upcoming_validators,
)
from jam_impl.codec.extrinsic_codec import decode_tickets, encode_tickets
from jam_impl.models.Header import Header, EpochMarker, ValidatorKeys as HKValidatorKeys
from jam_impl.models.Extrinsic import Disputes as ExtrinsicDisputes, Extrinsic
from jam_impl.models.State import (
    State, SafroleState, TicketBody, MostRecentTimeslot, EntropyAccumulator,
    PreviousValidators, CurrentValidators, UpcomingValidators, Disputes,
)
from jam_impl.safrole import safrole_stf
import jam_impl.util as util


# ---------------------------------------------------------------------------
# Wire walkers (all verified byte-exact against the vendored vectors)
#
# WHY THIS ISN'T just state_codec.decode_safrole_state: that function parses
# the C(4) TRIE VALUE only (γₖ‖γ_z‖flag‖γₛ‖γ_A, keyvals form). The stf .bin
# state is a flat positional concatenation of TEN components (τ η λ κ γₖ
# ι γ_a flag γₛ γ_z offenders) in stf order (γ_a BEFORE the flag, γ_z AFTER
# γₛ) — no keys, different order, more components. decode_state (keyvals)
# and decode_safrole_state (C4-only) can't consume it; this positional walk
# is the stf-native reader. Per-component decode/encode delegates to the
# state_codec functions on exact spans; the output marks' κ = V×(b, e)
# 64-B pairs — NOT decode_validator_list's shape, so those stay inline.
# ---------------------------------------------------------------------------

def _be_pair(d):
    return (d.hash32(), d.hash32())


def decode_safrole_state(d):
    """One safrole stf state (pre or post) → semantic repo models.

    Two passes: (1) mirror-walk to find each component's exact span — the
    state_codec component decoders are span-exact (they finish()), so the
    stf concatenation must be sliced per component; (2) decode each span
    with the matching state_codec function into the State class:
      τ → most_recent_timeslot (MostRecentTimeslot)
      η → entropy (EntropyAccumulator)
      λ → previous_validators  κ → current_validators
      ι → upcoming_validators  γₖ → safrole.pending_validators
      γ_A+flag+γₛ → safrole (C4 SafroleState); γ_z → epoch_root.
    The stf's externalized punish-set (wire ↕ + n×32, GP ψ′_O) lands in
    state.disputes.offenders (good/bad/wonky are not in the safrole stf's
    wire and stay empty — safrole only ever READS ψ_O, per 6.13). Returns
    the State alone.
    """
    state = State()
    safrole = SafroleState(pending_validators=[], epoch_root=b"",
                           tickets_or_keys_flag=0, tickets_or_keys=[],
                           ticket_accumulator=[])

    # ---- pass 1: mirror-walk to find component spans (absolute in d.b)
    o = d.o
    d.u32()                                   # τ
    for _ in range(4):
        d.hash32()                            # η
    V = util.NUM_VALIDATORS_IN_EPOCH_MARK
    spans = []                                # (start, end) of λ κ γₖ ι
    for _ in range(4):
        s0 = d.o
        for _ in range(V):
            d.hash32(); d.hash32(); d.take(144); d.take(128)
        spans.append((s0, d.o))
    ga0 = d.o                                 # γ_a: ↕ + n×(id, attempt)
    n_ga = d.decode_compact()
    for _ in range(n_ga):
        d.hash32(); d.u8()
    ga1 = d.o
    flag = d.u8()                             # γₛ flag + fixed-E contents
    E = util.LENGTH_OF_EPOCH_IN_TIMESLOTS
    gs0 = d.o
    if flag == 0:
        for _ in range(E):
            d.hash32(); d.u8()
    elif flag == 1:
        for _ in range(E):
            d.hash32()
    else:
        raise ValueError(f"gamma_s slot-sealer flag invalid: {flag}")
    gs1 = d.o
    gz0 = d.o
    d.take(144)                               # γ_z
    off0 = d.o                                # offenders: ↕ + n×32
    n_off = d.decode_compact()
    for _ in range(n_off):
        d.hash32()
    end = d.o
    # span offsets are ABSOLUTE in d.b — slice d.b directly (seg-relative
    # slicing was a bug when o != 0, i.e. every pre_state after the input).

    # ---- pass 2: per-component decode via state_codec on exact spans
    state.most_recent_timeslot = decode_most_recent_timeslot(d.b[o:o + 4])
    state.entropy = decode_entropy_accumulator(d.b[o + 4:o + 132])
    ((lam0, lam1), (kap0, kap1), (gk0, gk1), (io0, io1)) = spans
    state.previous_validators = decode_previous_validators(d.b[lam0:lam1])
    state.current_validators = decode_current_validators(d.b[kap0:kap1])
    safrole.pending_validators = decode_validator_list(Decoder(d.b[gk0:gk1]))
    state.upcoming_validators = decode_upcoming_validators(d.b[io0:io1])
    dg = Decoder(d.b[ga0:ga1])
    safrole.ticket_accumulator = [
        TicketBody(id=dg.hash32(), attempt=dg.u8())
        for _ in range(dg.decode_compact())
    ]
    dg.finish()
    dfs = Decoder(d.b[gs0:gs1])
    if flag == 0:
        safrole.tickets_or_keys = [
            TicketBody(id=dfs.hash32(), attempt=dfs.u8()) for _ in range(E)
        ]
    else:
        safrole.tickets_or_keys = [dfs.hash32() for _ in range(E)]
    dfs.finish()
    safrole.tickets_or_keys_flag = flag
    safrole.epoch_root = d.b[gz0:gz0 + 144]
    dof = Decoder(d.b[off0:end])
    punish_set = [dof.hash32() for _ in range(dof.decode_compact())]
    dof.finish()    
    state.disputes = Disputes(good=[], bad=[], wonky=[], offenders=punish_set)
    state.safrole = safrole
    return state


def _encode_stf_state(state, post_offenders):
    """State (+ offenders, outside C1..C16) → the stf's flat state wire.
    Byte-exact (verified by round-trip on all 42 vectors). Delegates to
    the state_codec component encoders."""
    sf = state.safrole
    e = Encoder()
    e.raw(encode_most_recent_timeslot(state.most_recent_timeslot))
    e.raw(encode_entropy_accumulator(state.entropy))
    e.raw(encode_previous_validators(state.previous_validators))
    e.raw(encode_current_validators(state.current_validators))
    encode_validator_list(e, sf.pending_validators)          # γₖ
    e.raw(encode_upcoming_validators(state.upcoming_validators))
    e.compact(len(sf.ticket_accumulator))
    for t in sf.ticket_accumulator:
        e.raw(t.id)
        e.u8(t.attempt)
    e.u8(sf.tickets_or_keys_flag)
    if sf.tickets_or_keys_flag == 0:
        for t in sf.tickets_or_keys:
            e.raw(t.id)
            e.u8(t.attempt)
    else:
        for k in sf.tickets_or_keys:
            e.raw(k)
    e.raw(sf.epoch_root)
    e.compact(len(post_offenders))
    for k in post_offenders:
        e.raw(k)
    return e.finish()


def decode_safrole_input(d):
    """stf input: slot(E4) + η(32) + ↕ tickets → (slot, η, [Ticket models])."""
    slot = d.u32()
    eta = d.hash32()
    tickets = decode_tickets(d)
    return slot, eta, tickets


def encode_safrole_input(slot, eta, tickets):
    """Inverse of decode_safrole_input (round-trip self-checks + H_X)."""
    e = Encoder()
    e.u32(slot)
    e.raw(eta)
    e.compact(len(tickets))
    for t in tickets:
        e.u8(t.attempt)
        e.raw(t.signature)
    return e.finish()


def build_header(slot, eta, tickets):
    """A Header for a safrole stf vector — derivable fields honest, the
    rest cannot exist (see note) and are zero-filled placeholders.

    From a safrole stf vector you get ONLY (slot, η, tickets). A Header's
    H_S/H_V are bandersnatch VRF SIGNATURES the vectors externalize —
    there is nothing to put there, so entropy_source/seal are 96 zero
    octets, parent/state root are zero hashes, author_index 0, marks
    None. This Header is for the stf's OWN logic (ticket seating, entropy
    blend, epoch rotation) — NOT for check_header_seal_and_vrf_072_check_
    only, which would (correctly) reject the fake seal. H_X = blake2b of
    the encoded stf input (honest: that IS this block's extrinsic).
    """
    return Header(
        parent=b"\x00" * 32,
        parent_state_root=b"\x00" * 32,
        extrinsic_hash=hash_via_blake2b(encode_safrole_input(slot, eta, tickets)),
        slot=slot,
        epoch_mark=None,
        tickets_mark=None,
        author_index=0,
        entropy_source=b"\x00" * 96,
        offenders_mark=[],
        seal=b"\x00" * 96,
    )


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _locate_post_state(b, start, tau_j):
    """Anchor-scan: find the offset ≥ start where decode_safrole_state
    consumes to EOF. Returns (offset, (State, post_offenders))."""
    anchor = int(tau_j).to_bytes(4, "little")
    pos = start
    while True:
        i = b.find(anchor, pos)
        if i < 0:
            return None
        try:
            d = Decoder(b[i:])
            st = decode_safrole_state(d)
            if d.o == len(b) - i:
                return i, st
        except AssertionError:
            pass
        pos = i + 1


def _norm_val(x: Any) -> Any:
    """Model → plain comparable: raw bytes stay, TicketBody → (id, attempt),
    ValidatorData → (bs, ed, bls, metadata), lists/tuples recurse."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if hasattr(x, "id") and hasattr(x, "attempt"):
        return (bytes(x.id), x.attempt)
    if hasattr(x, "bandersnatch") and hasattr(x, "ed25519"):
        return tuple(bytes(c) if isinstance(c, (bytes, bytearray)) else c
                     for c in (x.bandersnatch, x.ed25519, x.bls, x.metadata))
    if isinstance(x, list):
        return [_norm_val(i) for i in x]
    if isinstance(x, tuple):
        return tuple(_norm_val(i) for i in x)
    return x


def _h8(b):
    return (b.hex() if isinstance(b, (bytes, bytearray)) else str(b))[:8]


def _canon_mark_entry(v):
    """One validator/ticket mark entry → positional tuple, whatever shape
    the producer used: sidecar dict {'bandersnatch','ed25519'} or
    {'id','attempt'}, a TicketBody record, an (bs,e)/ValidatorKeys object,
    or an already-positional tuple/list."""
    if isinstance(v, dict):
        if "bandersnatch" in v:
            return (bytes(v["bandersnatch"]), bytes(v["ed25519"]))
        return (bytes(v["id"]), v["attempt"])
    if hasattr(v, "bandersnatch") and hasattr(v, "ed25519"):
        return (bytes(v.bandersnatch), bytes(v.ed25519))
    if hasattr(v, "id") and hasattr(v, "attempt"):
        return (bytes(v.id), v.attempt)
    if isinstance(v, (tuple, list)):
        return (bytes(v[0]), v[1])
    return v


def _canon_marks(marks):
    """Marks → ONE canonical shape for comparison. Producers differ: the
    stub may emit sidecar dicts / TicketBody records / positional tuples,
    the harness's expected side is built positional from the sidecar json —
    a dict-vs-tuple compare fails even when every octet agrees (the
    enact-4/padding-1/with-mark-4 failure class: 'state bytes match;
    verdict/marks leg differs'). Canonical: epoch mark → (entropy,
    tickets_entropy, [(bs, e)...]); tickets mark → [(id, attempt)...];
    None stays None (both directions of absent-vs-absent)."""
    if marks is None:
        return None
    if isinstance(marks, dict):
        em, tm = marks.get("epoch_mark"), marks.get("tickets_mark")
    elif hasattr(marks, "epoch_mark"):
        em, tm = marks.epoch_mark, marks.tickets_mark
    else:
        return marks
    if em is not None and isinstance(em, dict):
        em = (bytes(em["entropy"]), bytes(em["tickets_entropy"]),
              [_canon_mark_entry(v) for v in em["validators"]])
    elif em is not None:
        em = (bytes(em.entropy), bytes(em.tickets_entropy),
              [_canon_mark_entry(v) for v in em.validators])
    if tm is not None:
        tm = [_canon_mark_entry(t) for t in tm]
    return {"epoch_mark": em, "tickets_mark": tm}


_GETTERS = (
    ("tau",     lambda s: s.most_recent_timeslot.timeslot if s.most_recent_timeslot else None),
    ("eta",     lambda s: list(s.entropy.values) if s.entropy else None),
    ("lambda",  lambda s: list(s.previous_validators.validators) if s.previous_validators else None),
    ("kappa",   lambda s: list(s.current_validators.validators) if s.current_validators else None),
    ("gamma_k", lambda s: list(s.safrole.pending_validators) if s.safrole else None),
    ("iota",    lambda s: list(s.upcoming_validators.validators) if s.upcoming_validators else None),
    ("gamma_a", lambda s: list(s.safrole.ticket_accumulator) if s.safrole else None),
    ("gamma_s", lambda s: (s.safrole.tickets_or_keys_flag, s.safrole.tickets_or_keys) if s.safrole else None),
    ("gamma_z", lambda s: s.safrole.epoch_root if s.safrole else None),
)


def _state_diff_msgs(expected, stub, inp=None, pre=None, limit=12):
    """Per-component semantic diff: expected post-state (vector decode) vs the
    stub's returned post-state. Names the usual silent failure shapes
    (offender-Φ never fired / over-fired, η₀ blend missing, τ′ != slot,
    ring-root input). Returns up to `limit` human strings for FAIL log + dump."""
    msgs = []
    for name, get in _GETTERS:
        try:
            ev = get(expected)
        except AttributeError:
            ev = None
        try:
            sv = get(stub)
        except AttributeError:
            sv = None
        en, sn = _norm_val(ev), _norm_val(sv)
        if en == sn:
            continue
        if name == "tau":
            slot = inp.get("slot") if isinstance(inp, dict) else None
            msgs.append(f"tau: {sn} != {en} — τ′ must equal the block's header slot"
                        f" (header.slot={slot})")
        elif name == "eta" and isinstance(en, list) and isinstance(sn, list) \
                and len(en) == len(sn) and en[1:] == sn[1:]:
            msgs.append(f"eta[0]: {_h8(en[0])} != got {_h8(sn[0])}"
                        " — η₀′ = H(pre η₀ ‖ η_input)")
            msg2 = None
            if pre is not None and getattr(pre.entropy, "values", None):
                try:
                    import hashlib
                    blend = hashlib.blake2b(bytes(pre.entropy.values[0])
                                            + bytes(inp["eta"]), digest_size=32).digest()
                    if bytes(sn[0]) == bytes(pre.entropy.values[0]):
                        msg2 = "  …yours == PRE η₀: no blend applied"
                    elif bytes(sn[0]) == blend:
                        msg2 = "  …yours == blend(pre η₀‖η_input): pre η₀ or η_input mismatch upstream"
                    else:
                        msg2 = f"  …yours is neither pre η₀ nor H(pre η₀‖η_input)={_h8(blend)}"
                except Exception:
                    pass
            if msg2:
                msgs.append(msg2)
        elif name in ("lambda", "kappa", "gamma_k", "iota") \
                and isinstance(en, list) and isinstance(sn, list):
            if len(sn) != len(en):
                msgs.append(f"{name}: len {len(sn)} != expected {len(en)}")
                continue
            shown = 0
            for i, (a, b) in enumerate(zip(en, sn)):
                if a == b:
                    continue
                shown += 1
                if all(c == b"\x00" * len(c) for c in a):
                    msgs.append(f"{name}[{i}]: expected ALL-ZERO record (offender nulled,"
                                f" Φ fired) — yours keeps ed={_h8(b[1])}"
                                " (Φ didn't fire / empty offenders list)")
                elif all(c == b"\x00" * len(c) for c in b):
                    msgs.append(f"{name}[{i}]: you nulled this record but expected"
                                f" ed={_h8(a[1])} (Φ over-fired / wrong offenders)")
                else:
                    msgs.append(f"{name}[{i}]: differs — expected ed={_h8(a[1])}"
                                f" got ed={_h8(b[1])}")
                if shown >= 3:
                    msgs.append(f"  … (+{len(en) - sum(1 for x, y in zip(en, sn) if _norm_val(x) != _norm_val(y)) - shown} more records differ)")
                    break
        elif name == "gamma_s" and isinstance(en, tuple) and isinstance(sn, tuple):
            if sn[0] != en[0]:
                msgs.append(f"gamma_s: kind flag {sn[0]} != {en[0]} (0=tickets, 1=fallback keys)")
            else:
                ea, sa = _norm_val(en[1]), _norm_val(sn[1])
                ndiff = sum(1 for x, y in zip(ea, sa) if x != y)
                msgs.append(f"gamma_s contents differ ({ndiff} of {len(ea)} entries),"
                            " kind unchanged")
        elif name == "gamma_a" and isinstance(en, list) and isinstance(sn, list):
            msgs.append(f"gamma_a: len {len(sn)} != {len(en)}" if len(sn) != len(en)
                        else "gamma_a entries differ (merge of submitted tickets into best-E)")
        elif name == "gamma_z":
            msgs.append("gamma_z: ring-root bytes differ — the list passed to"
                        " bandersnatch_ring_root is wrong (post-Φ γₖ′, zero records stay in)")
        else:
            msgs.append(f"{name}: differs ({_h8(sn) if sn is not None else '∅'}"
                        f" vs {_h8(en) if en is not None else '∅'})")
        if len(msgs) >= limit:
            return msgs[:limit]
    return msgs


def run_vector(path_no_ext, verbose=True):
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        slot, eta, tickets = decode_safrole_input(d)
        pre = decode_safrole_state(d)

        # byte-exact self-check on the input + pre span we just consumed
        assert d.o <= len(b), "pre_state walk overran the bin"

        tag = d.o
        result = None
        post_at = None
        post_decoded = None
        linear_ok = False
        if tag < len(b):
            out_tag = b[tag]
            if out_tag == 0:
                d.u8()
                try:
                    em = d.u8()
                    ok_out: dict = {"epoch_mark": None, "tickets_mark": None}
                    if em == 1:
                        ok_out["epoch_mark"] = {
                            "entropy": d.hash32(),
                            "tickets_entropy": d.hash32(),
                            "validators": [_be_pair(d) for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)],
                            # NOTE: stf-mark κ carries only (bandersnatch, ed25519)
                        }
                    tm = d.u8()  # W-mark ¿-tag: 0 = absent
                    if tm == 1:
                        # H_W = fixed E×(id, attempt) — NO ↕ count (verified:
                        # tiny mark-4 n=12==E, full mark-4 n=600==E, anchor-located)
                        ok_out["tickets_mark"] = [
                            {"id": d.hash32(), "attempt": d.u8()}
                            for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
                        ]
                    post_start = d.o   # span START: capture BEFORE the consuming decode (d.o after = END = len(b))
                    post_decoded = decode_safrole_state(d)
                    if d.o == len(b):
                        linear_ok = True
                        post_at = post_start   # want = b[post_at:] = the post-state wire the stub must produce
                        result = ("ok", ok_out, post_decoded)
                except AssertionError:
                    pass

        if not linear_ok:
            # err output (or ok-mark framing drift): locate post by anchor
            found = _locate_post_state(b, tag, j["post_state"]["tau"])
            if found is None:
                return {"name": os.path.basename(path_no_ext),
                        "verdict": "HARNESS-FAIL",
                        "why": "post_state not locatable (walkers vs this vector)"}
            post_at, post_decoded = found
            out_j = j["output"]
            if "err" in out_j:
                result = ("err", out_j["err"], post_decoded)
            else:
                result = (None, out_j.get("ok"), post_decoded)

        # ---- the actual test: run the stub, encode its post, byte-compare.
        # The stf input's η substitutes for Y(H_V) (externalized VRFs — the
        # vectors carry no seal), so the Header's seal fields are fakes and
        # check_header_seal_and_vrf must NOT run inside the stf.
        header = build_header(slot, eta, tickets)
        input_data = Extrinsic(
            assurances=[], tickets=tickets, preimages=[],
            guarantees=[], disputes=ExtrinsicDisputes(verdicts=[], culprits=[], faults=[]),
        )
        try:
            stub_out = safrole_stf(copy.deepcopy(pre), header, input_data, eta, spec)
        except NotImplementedError:
            dbg = _dump_debug(vector=path_no_ext, pre=pre,
                              inp={"slot": slot, "eta": eta, "tickets": tickets},
                              header=header, extrinsic=input_data,
                              expected_output=j["output"],
                              expected_post=_jsonify(post_decoded),
                              post_state_span=(post_at, len(b)))
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "pre_state": pre,
                    "input": _jsonify({"slot": slot, "eta": eta, "tickets": tickets}),
                    "expected_output": j["output"],
                    "expected_post_state": _jsonify(post_decoded),
                    "post_state_span": (post_at, len(b)),
                    "debug_json": dbg}

        stub_verdict = stub_out[0]
        if stub_verdict == "ok":
            stub_marks = stub_out[1] or {}
            stub_post = stub_out[2]
            # offenders: ψ_O rides IN the state now (state.disputes.offenders);
            # a stub's 4th element is tolerated but ignored for encoding.
            stub_offenders = getattr(getattr(stub_post, "disputes", None),
                                     "offenders", []) or []
        else:  # err: state may still move (bad_slot = no; others partial)
            stub_marks = None
            stub_post = stub_out[2] if len(stub_out) > 2 else stub_out[1]
            stub_offenders = getattr(getattr(stub_post, "disputes", None),
                                     "offenders", []) or []

        if isinstance(stub_post, State):
            encoded = _encode_stf_state(stub_post, stub_offenders)
        elif isinstance(stub_post, bytes):
            encoded = stub_post  # stub may hand back pre-encoded bytes
        else:
            raise TypeError("safrole_stf must return "
                            "(verdict, marks|err, post_state-State-or-bytes[, offenders])")
        want = b[post_at:]
        match = encoded == want

        # ---- verdict leg must match: an err-vector run through a stub that
        # says "ok" matches all post-state bytes (err leaves state unchanged)
        # and would PASS vacuously without this check.
        report_added = {}
        out_leg = j["output"]
        expected_verdict = "err" if "err" in out_leg else "ok"
        if stub_verdict != expected_verdict:
            match = False
            report_added = {"verdict_mismatch": {
                "stub": stub_verdict,
                "stub_err": stub_out[1] if stub_verdict == "err" else None,
                "expected": out_leg}}
        # ---- marks check: the stub's declared marks must equal the vector's
        # expected output-side marks (both directions: absent-vs-absent too).
        # VALUE equality only — producers use different Python shapes (stub
        # dicts/records, sidecar-derived tuples), so both sides pass through
        # _canon_marks before comparing; shape must never enter the verdict.
        if match and stub_verdict == "ok":
            expected = j["output"].get("ok") or {}
            want_marks = {
                "epoch_mark": (None if expected.get("epoch_mark") is None else {
                    "entropy": bytes.fromhex(expected["epoch_mark"]["entropy"][2:]),
                    "tickets_entropy": bytes.fromhex(expected["epoch_mark"]["tickets_entropy"][2:]),
                    "validators": [
                        (bytes.fromhex(v["bandersnatch"][2:]), bytes.fromhex(v["ed25519"][2:]))
                        for v in expected["epoch_mark"]["validators"]
                    ],
                }),
                "tickets_mark": (None if expected.get("tickets_mark") is None else [
                    (bytes.fromhex(t["id"][2:]), t["attempt"])
                    for t in expected["tickets_mark"]
                ]),
            }
            got_marks = {
                "epoch_mark": (stub_marks or {}).get("epoch_mark"),
                "tickets_mark": (stub_marks or {}).get("tickets_mark"),
            }
            if _canon_marks(got_marks) != _canon_marks(want_marks):
                match = False
                report_added = {"marks_mismatch": {
                    "got": _jsonify(got_marks), "expected": _jsonify(want_marks)}}

        # ---- semantic diff annotation: name WHICH component/record diverged,
        # not just the first octet (the silent-failure shapes are visible here
        # without hand-decoding wire offsets).
        expected_state = post_decoded[0] if isinstance(post_decoded, tuple) else post_decoded
        diff_notes = _state_diff_msgs(expected_state, stub_post, inp={"slot": slot, "eta": eta},
                                      pre=pre) if not match else []

        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "stub_output_verdict": stub_verdict,
            "expected_output": j["output"],
            "diff_notes": diff_notes,
            **report_added,
        }
        out_path = _dump_debug(vector=path_no_ext, pre=pre,
                               inp={"slot": slot, "eta": eta, "tickets": tickets},
                               header=header, extrinsic=input_data,
                               # output legs, sidecar shape: expected vs what the stub declared
                               expected_output=j["output"],
                               output={"ok": _jsonify(stub_marks)} if stub_verdict == "ok"
                                      else {"err": stub_out[1]},
                               expected_post=_jsonify(post_decoded),
                               stub_post=_jsonify(stub_post) if isinstance(stub_post, State) else None,
                               encoded_len=len(encoded), want_len=len(want),
                               match=match, diff_notes=diff_notes,
                               **report_added)
        report["debug_json"] = out_path
        if not match:
            i = next((k for k in range(min(len(encoded), len(want)))
                      if encoded[k] != want[k]), None)
            if i is None:  # bytes equal ⇒ the mismatch is the verdict/marks leg
                report["why"] = "state bytes match; verdict/marks leg differs"
            else:
                report["first_diff_octet"] = i
                report["diff_context"] = {
                    "encoded": encoded[max(0, i - 8):i + 8].hex(),
                    "expected": want[max(0, i - 8):i + 8].hex(),
                }
        return report


def _jsonify(o):
    if isinstance(o, bytes):
        return "0x" + o.hex()
    if isinstance(o, (set, frozenset)):
        # sets have no wire order; sort by serialization for deterministic
        # dumps. If this rides inside tickets_mark, the marks check will
        # (correctly) flag the lost order — the W-mark is a positional SEQUENCE.
        return sorted((_jsonify(i) for i in o),
                      key=lambda v: json.dumps(v, sort_keys=True, default=repr))
    if isinstance(o, dict):
        return {k: _jsonify(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonify(v) for v in o]
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return _jsonify(dataclasses.asdict(o))
    return o


def _dump_debug(**kw):
    name = os.path.basename(kw.get("vector", "debug"))
    path = os.path.join(REPO, "jam_impl", "tests", "stf_debug", name + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(_jsonify(kw), f, indent=1)
    return path


def main(argv):
    if argv and argv[0] == "--accumulate":
        print("accumulate stf not wired yet (walker verified; hook up when"
              " the accumulate module lands)")
        return 2
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO, "jamtestvectors/stf/safrole/*/*.json")))]
    passed = failed = skipped = 0
    for path in paths:
        try:
            rep = run_vector(path)
        except ValueError as ex:
            failed += 1
            print(f"  HARNESS-FAIL {os.path.basename(path)}: {ex!r}")
            continue
        except Exception as ex:  # a crash in the stf is a log row, not a dead suite
            import traceback
            failed += 1
            print(f"  CRASH {os.path.basename(path)}: {ex!r}"
                  " (suite continues; traceback follows)")
            traceback.print_exc()
            continue
        verdict = rep["verdict"]
        if verdict == "PASS":
            passed += 1
            print(f"  PASS {rep['name']}")
        elif verdict == "STUB-UNIMPLEMENTED":
            skipped += 1
            print(f"  STUB {rep['name']} (safrole_stf not implemented yet;"
                  f" pre/input/expected dumped to {rep['debug_json']})")
        elif verdict == "HARNESS-FAIL":
            failed += 1
            print(f"  HARNESS-FAIL {rep['name']}: {rep['why']}")
        else:
            failed += 1
            why = f" why={rep['why']}" if "why" in rep else ""
            notes = "".join("\n      ! " + n for n in (rep.get("diff_notes") or []))
            extra = ""
            if "marks_mismatch" in rep:
                mm = rep["marks_mismatch"]
                extra = (f" marks_mismatch got={json.dumps(mm['got'])[:160]}"
                         f" expected={json.dumps(mm['expected'])[:160]}")
            elif "verdict_mismatch" in rep:
                vm = rep["verdict_mismatch"]
                extra = (f" verdict_mismatch stub={vm['stub']!r}"
                         f" stub_err={vm.get('stub_err')!r}"
                         f" expected={json.dumps(vm.get('expected'))[:120]}")
            print(f"  FAIL {rep['name']}{why} first_diff_octet={rep.get('first_diff_octet')}"
                  f" diff={rep.get('diff_context')}{extra} debug={rep['debug_json']}{notes}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))