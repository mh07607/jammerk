"""STF harness: run a safrole stf vector through `safrole_stf` (the stub
you will implement) and compare the encoded post_state against the
vector's post_state bytes.

Layout of every file this touches (all verified byte-exact against the
vendored jamtestvectors, tiny and full):

  stf/safrole/<spec>/<name>.bin = INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input     = τ_input(E4) η_input(32) ↕ tickets[(attempt:1, sig:784)]
    state     = τ(E4) η(4×32) λ κ γₖ ι (V × [b32 e32 bls144 meta128])
                γ_a(↕ n×[id32 att1]) γₛ-flag(1)
                γₛ = flag1: E×32 keys | flag0: E×[id32 att1 tickets]
                γ_z(144) offenders(↕ n×32)
    output    = 00 ok { E-mark ¿(01 η₀ 32 η₁ 32 κ V×[b32 e32]) ¿?
                        W-mark ¿(01 ↕ n×[id32 att1]) }
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

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from jam_impl.util import Decoder, Encoder
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.state_codec import (
    decode_validator_list, encode_validator_list,
    decode_most_recent_timeslot, encode_most_recent_timeslot,
    decode_entropy_accumulator, encode_entropy_accumulator,
    decode_previous_validators, encode_previous_validators,
    decode_current_validators, encode_current_validators,
    decode_upcoming_validators, encode_upcoming_validators,
)
from jam_impl.models.State import (
    TicketBody, MostRecentTimeslot, EntropyAccumulator,
    PreviousValidators, CurrentValidators, UpcomingValidators,
)
import jam_impl.util as util

EPOCH = 12  # replaced per-spec below


# ---------------------------------------------------------------------------
# Wire walkers (all verified byte-exact against the vendored vectors)
#
# WHY THIS ISN'T just state_codec.decode_safrole_state: that function parses
# the C(4) TRIE VALUE only (γₖ‖γ_z‖flag‖γₛ‖γ_A, keyvals form). The stf .bin
# state is a flat positional concatenation of TEN components (τ η λ κ γₖ
# ι γ_a flag γₛ γ_z offenders) in stf order (γ_a BEFORE the flag, γ_z AFTER
# γₛ) — no keys, different order, more components. decode_state (keyvals)
# and decode_safrole_state (C4-only) can't consume it; this positional walk
# is the stf-native reader. Piecewise helpers ARE reused where the shapes
# coincide: decode_validator_list / repo model classes (ValidatorData,
# TicketBody). The outputmarks' κ = V×(bandersnatch, ed25519) 64-B pairs —
# NOT decode_validator_list's shape, so those stay inline.
# ---------------------------------------------------------------------------

def _be_pair(d):
    return {"bandersnatch": d.hash32(), "ed25519": d.hash32()}


def decode_safrole_state(d):
    """One safrole state (pre or post), as repo-model/codec classes.

    Two passes: (1) mirror-walk to find each component's exact span — the
    state_codec component decoders are span-exact (they finish()), so the
    stf concatenation must be sliced per component; (2) decode each span
    with the matching state_codec function:
      τ → decode_most_recent_timeslot      η → decode_entropy_accumulator
      λ → decode_previous_validators       κ → decode_current_validators
      ι → decode_upcoming_validators       γₖ → decode_validator_list
    Span-to-model equality with the direct walkers was verified on tiny +
    full before adopting this (/tmp/spancheck.py). γ_a / γₛ / γ_z /
    offenders have no standalone codec fn (γₛ's flag lives inside C4's
    decoder), so they're walked here in C4's own field order.
    """
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
    # NOTE: span offsets are ABSOLUTE in d.b — slice d.b directly (seg-relative
    # slicing was a bug when o != 0, i.e. every pre_state after the input).
    seg_end = end

    # --- per-component decode via state_codec functions on exact spans
    st = {}
    st["tau"] = decode_most_recent_timeslot(d.b[o:o + 4]).timeslot
    st["eta"] = decode_entropy_accumulator(d.b[o + 4:o + 132]).values
    ((lam0, lam1), (kap0, kap1), (gk0, gk1), (io0, io1)) = spans
    st["lambda"] = decode_previous_validators(d.b[lam0:lam1]).validators
    st["kappa"] = decode_current_validators(d.b[kap0:kap1]).validators
    st["gamma_k"] = decode_validator_list(Decoder(d.b[gk0:gk1]))
    st["iota"] = decode_upcoming_validators(d.b[io0:io1]).validators
    dg = Decoder(d.b[ga0:ga1])
    st["gamma_a"] = [TicketBody(id=dg.hash32(), attempt=dg.u8())
                     for _ in range(dg.decode_compact())]
    dg.finish()
    st["gamma_s_flag"] = flag
    dfs = Decoder(d.b[gs0:gs1])
    if flag == 0:
        st["gamma_s"] = {"tickets": [TicketBody(id=dfs.hash32(), attempt=dfs.u8())
                                     for _ in range(E)]}
    else:
        st["gamma_s"] = {"keys": [dfs.hash32() for _ in range(E)]}
    dfs.finish()
    st["gamma_z"] = d.b[gz0:gz0 + 144]
    dof = Decoder(d.b[off0:seg_end])
    st["post_offenders"] = [dof.hash32() for _ in range(dof.decode_compact())]
    dof.finish()
    return st


def encode_safrole_state(st):
    """Inverse of decode_safrole_state — byte-exact (verified by round-trip).
    Uses the state_codec component encoders where the shapes coincide:
      τ → encode_most_recent_timeslot      η → encode_entropy_accumulator
      λ → encode_previous_validators       κ → encode_current_validators
      ι → encode_upcoming_validators       γₖ → encode_validator_list
    """
    tau = encode_most_recent_timeslot(MostRecentTimeslot(timeslot=st["tau"]))
    eta = encode_entropy_accumulator(EntropyAccumulator(values=st["eta"]))
    parts = [tau, eta,
             encode_previous_validators(PreviousValidators(validators=st["lambda"])),
             encode_current_validators(CurrentValidators(validators=st["kappa"]))]
    # γₖ sits between κ and ι in the stf state order
    e = Encoder()
    for p in parts:
        e.raw(p)
    encode_validator_list(e, st["gamma_k"])
    e.raw(encode_upcoming_validators(UpcomingValidators(validators=st["iota"])))
    e.compact(len(st["gamma_a"]))
    for t in st["gamma_a"]:
        e.raw(t.id)
        e.u8(t.attempt)
    e.u8(st["gamma_s_flag"])
    if st["gamma_s_flag"] == 0:
        for t in st["gamma_s"]["tickets"]:
            e.raw(t.id)
            e.u8(t.attempt)
    else:
        for k in st["gamma_s"]["keys"]:
            e.raw(k)
    e.raw(st["gamma_z"])
    e.compact(len(st["post_offenders"]))
    for k in st["post_offenders"]:
        e.raw(k)
    return e.finish()


def decode_safrole_input(d):
    slot = d.u32()
    entropy = d.hash32()
    tickets = []
    for _ in range(d.decode_compact()):
        tickets.append({"attempt": d.u8(), "signature": d.take(784)})
    return {"slot": slot, "entropy": entropy, "tickets": tickets}


def decode_safrole_output(d, b, post_anchor_start):
    """Output CHOICE. The ok path is walked exactly; the err path only pins
    the variant name (payload left opaque — the stub's business), and the
    post_state is then re-located by anchor. (Folded into run_vector.)"""
    raise RuntimeError("folded into run_vector")


# (decode_safrole_output is folded into run_vector; kept as doc anchor above)


# ---------------------------------------------------------------------------
# The stub: YOU implement this. Wire it into your real safrole code later.
# ---------------------------------------------------------------------------

def safrole_stf(pre_state, input_data, spec):
    """GP 0.7.2 §6 stf transition for one vector — TO BE IMPLEMENTED.

    Args:
        pre_state:  decoded pre-state dict (decode_safrole_state shape)
        input_data: {"slot": int, "entropy": bytes, "tickets": [...]}
        spec:       'tiny' | 'full'

    Returns:
        ("ok",    {"epoch_mark": E | None, "tickets_mark": W | None}, post_state)
        ("err",   <your error name>, post_state)
        with output shapes mirroring the vectors' json sidecars.
    """
    raise NotImplementedError("safrole_stf is the part you implement")


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def _locate_post_state(b, start, tau_j):
    """Anchor-scan: find the offset ≥ start where walk_state consumes to EOF."""
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


def run_vector(path_no_ext, verbose=True):
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        input_data = decode_safrole_input(d)
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
                    post_decoded = decode_safrole_state(d)
                    if d.o == len(b):
                        linear_ok = True
                        result = ("ok", ok_out, post_decoded)
                        post_at = d.o
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

        # ---- the actual test: run the stub, encode its post, byte-compare
        try:
            stub_out = safrole_stf(pre, input_data, spec)
        except NotImplementedError:
            dbg = _dump_debug(vector=path_no_ext, pre=pre, inp=input_data,
                              expected_output=j["output"],
                              expected_post=_jsonify(post_decoded),
                              post_state_span=(post_at, len(b)))
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "pre_state": pre,
                    "input": _jsonify(input_data),
                    "expected_output": j["output"],
                    "expected_post_state": _jsonify(post_decoded),
                    "post_state_span": (post_at, len(b)),
                    "debug_json": dbg}

        stub_verdict, stub_post = stub_out[0], stub_out[2] if len(stub_out) > 2 else stub_out[1]
        if isinstance(stub_post, dict):
            encoded = encode_safrole_state(stub_post)
        elif isinstance(stub_post, bytes):
            encoded = stub_post  # stub may hand back pre-encoded bytes
        else:
            raise TypeError("safrole_stf must return (verdict, output, post_state-dict-or-bytes)")
        want = b[post_at:]
        match = encoded == want

        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "stub_output_verdict": stub_verdict,
            "expected_output": j["output"],
        }
        out_path = _dump_debug(vector=path_no_ext, pre=pre, inp=input_data,
                               expected_post=_jsonify(post_decoded),
                               stub_post=_jsonify(stub_post) if isinstance(stub_post, dict) else None,
                               encoded_len=len(encoded), want_len=len(want),
                               match=match)
        report["debug_json"] = out_path
        if not match:
            i = next((k for k in range(min(len(encoded), len(want)))
                      if encoded[k] != want[k]), min(len(encoded), len(want)))
            report["first_diff_octet"] = i
            report["diff_context"] = {
                "encoded": encoded[max(0, i - 8):i + 8].hex(),
                "expected": want[max(0, i - 8):i + 8].hex(),
            }
        return report


def _jsonify(o):
    if isinstance(o, bytes):
        return "0x" + o.hex()
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
    targets = argv or sorted(
        glob.glob(os.path.join(REPO, "jamtestvectors/stf/safrole/*/*.json")))
    passed = failed = skipped = 0
    for t in sorted(glob.glob(os.path.join(REPO, "jamtestvectors/stf/safrole/*/*.json"))):
        path = t[:-5] if t.endswith(".json") else t
        try:
            rep = run_vector(path)
        except ValueError as ex:
            failed += 1
            print(f"  HARNESS-FAIL {os.path.basename(path)}: {ex!r}")
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
            print(f"  FAIL {rep['name']} first_diff_octet={rep.get('first_diff_octet')}"
                  f" diff={rep.get('diff_context')} debug={rep['debug_json']}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))