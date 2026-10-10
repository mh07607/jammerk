import copy
import glob
import json
import os
import sys
import dataclasses
from typing import Any

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from jam_impl.util import Decoder, Encoder, encode_compact
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import (
    decode_disputes as decode_ed_wire,
    encode_disputes as encode_ed_wire,
    decode_report, encode_report,
)
from jam_impl.codec.state_codec import (
    decode_disputes as decode_psi_wire,
    encode_disputes_state as encode_psi_wire,
    decode_availability_assignments,
    encode_availability_assignments,
    decode_current_validators, encode_current_validators,
    decode_previous_validators,  encode_previous_validators,
    decode_most_recent_timeslot, encode_most_recent_timeslot,
)
from jam_impl.models.State import (
    Disputes as PsiState, AvailabilityAssignments,
    AvailabilityAssignment, MostRecentTimeslot,
    CurrentValidators, PreviousValidators,
)
from jam_impl.models.Extrinsic import Disputes as EdModel

ERRS = [  # disputes.asn order; json uses snake_case of the same names
    "already_judged", "bad_vote_split", "verdicts_not_sorted_unique",
    "judgements_not_sorted_unique", "culprits_not_sorted_unique",
    "faults_not_sorted_unique", "not_enough_culprits", "not_enough_faults",
    "culprits_verdict_not_bad", "fault_verdict_wrong",
    "offender_already_reported", "bad_judgement_age", "bad_validator_index",
    "bad_signature", "bad_guarantor_key", "bad_auditor_key",
]

# ---------------------------------------------------------------------------
# Wire walkers (thin: delegate every field to the repo codecs)
# ---------------------------------------------------------------------------


def decode_disputes_state(d: Decoder, core_count: int, j_side_kappa0: bytes | None = None):
    global _last_walker_end
    """One disputes stf state (pre or post) → (psi, rho, tau, kappa, lam).

    stf component ORDER: ψ (↕-list ×4) ρ (¿×C) τ (E4) κ (V×336) λ (V×336).
    ψ decodes via state_codec over its exact span. ρ is decoded over its
    exact [ψ-end, τ) slice with decode_availability_assignments — whose
    finish() validates the boundary (the wire's work-report core_index is a
    COMPACT N per extrinsic_codec, since his cross-suite fix). The τ offset
    is LOCATED by searching for the first validator record's bandersnatch
    key (j_side_kappa0, from the json sidecar) — the mirror-walk fallback
    (no anchor) also uses the fixed codec."""
    o0 = d.o
    dp = Decoder(d.b); dp.o = o0                       # ψ: 4×(↕ + hashes)
    for _ in range(4):
        n = dp.decode_compact()
        dp.take(32 * n)
    psi_end = dp.o
    psi = decode_psi_wire(d.b[o0:psi_end])
    if j_side_kappa0 is not None:
        tau_at = d.b.find(j_side_kappa0, psi_end) - 4
        if tau_at < psi_end:
            raise ValueError("disputes stf: κ[0] anchor not found after ψ")
    else:
        drho = Decoder(d.b); drho.o = psi_end
        for _ in range(core_count):
            if drho.u8() == 1:
                decode_report(drho)
                drho.u32()
        tau_at = drho.o
    rho = decode_availability_assignments(d.b[psi_end:tau_at])
    d.o = tau_at
    tau = decode_most_recent_timeslot(d.take(4))
    kap0 = d.o
    kappa = decode_current_validators(d.b[kap0:kap0 + _v_len()])
    d.o = kap0 + _v_len()
    lam0 = d.o
    lam = decode_previous_validators(d.b[lam0:lam0 + _v_len()])
    d.o = lam0 + _v_len()
    _last_walker_end = d.o
    return psi, rho, tau, kappa, lam


def _v_len() -> int:
    import jam_impl.util as util
    return util.NUM_VALIDATORS_IN_EPOCH_MARK * (32 + 32 + 144 + 128)


_last_walker_end = None


def _decoder_at(b: bytes, o: int) -> Decoder:
    d = Decoder(b)
    d.o = o
    return d


def encode_disputes_state(psi, rho, tau, kappa, lam) -> bytes:
    """Inverse of decode_disputes_state (delegates to repo encoders,
    incl. encode_availability_assignments — core-compact since his
    extrinsic_codec fix)."""
    e = Encoder()
    e.raw(encode_psi_wire(psi))
    e.raw(encode_availability_assignments(rho))
    e.raw(encode_most_recent_timeslot(tau))
    e.raw(encode_current_validators(kappa))
    e.raw(encode_previous_validators(lam))
    return e.finish()


def decode_output(b: bytes, o: int):
    """Output wire → ("ok", offenders_mark list) | ("err", name). Returns
    (verdict, mark_or_err, next_offset).

    Wire: 00 ok → offenders-mark = ↕(V×32): COMPACT count (00 = empty, no
    separate presence tag — verdicts-4/culprits-4/faults-2 byte-proved);
    01 err → E1 code, ERRS[code]."""
    d = Decoder(b); d.o = o
    tag = d.u8()
    if tag == 0:                                       # ok
        n = d.decode_compact()
        mark = [d.hash32() for _ in range(n)]
        return "ok", mark, d.o
    code = d.u8()
    return "err", ERRS[code] if code < len(ERRS) else code, d.o


def encode_output(verdict: str, mark_or_err) -> bytes:
    e = Encoder()
    if verdict == "ok":
        e.u8(0).compact(len(mark_or_err))
        for k in mark_or_err:
            e.hash32(k)
    else:
        e.u8(1).u8(ERRS.index(mark_or_err))
    return e.finish()


def _jsonify(o):
    if isinstance(o, bytes):
        return "0x" + o.hex()
    if isinstance(o, set):
        return sorted((_jsonify(i) for i in o),
                      key=lambda v: json.dumps(v, sort_keys=True, default=repr))
    if isinstance(o, dict):
        return {k: _jsonify(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonify(v) for v in o]
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        # recurse FIELD BY FIELD: asdict() recurses via copy.deepcopy which
        # chokes on nested models with non-dataclass members (WorkResult…)
        return {f: _jsonify(getattr(o, f)) for f in o.__dataclass_fields__}
    from enum import Enum
    if isinstance(o, Enum):          # WorkResult tags etc.
        return o.name
    if isinstance(o, (int, str, bool, float)) or o is None:
        return o
    return repr(o)


def _dump_debug(**kw):
    name = os.path.basename(kw.get("vector", "debug"))
    path = os.path.join(REPO, "jam_impl", "tests", "stf_debug", name + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(_jsonify(kw), f, indent=1)
    return path


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def run_vector(path_no_ext, verbose=True):
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    from jam_impl.codec.state_codec import core_count
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        ed: EdModel = decode_ed_wire(d)
        kappa0_anchor = bytes.fromhex(j["pre_state"]["kappa"][0]["bandersnatch"][2:])
        pre_psi, pre_rho, pre_tau, pre_kappa, pre_lam = \
            decode_disputes_state(d, core_count(), kappa0_anchor)
        assert d.o <= len(b), "pre-state walk overran"

        # locate OUTPUT / POST. OUTPUT follows the pre-state directly; the
        # POST state ends at EOF. Anchor the POST state's ψ end the same way
        # (its κ[0] equals pre κ[0] — disputes never mutates the key sets).
        out_off = d.o
        verdict, mark_or_err, post_off = decode_output(b, out_off)
        post0 = out_off + 2 if verdict == "err" else post_off
        post_anchor = bytes.fromhex(j["post_state"]["kappa"][0]["bandersnatch"][2:])
        post_psi, post_rho, post_tau, post_kappa, post_lam = \
            decode_disputes_state(
                _decoder_at(b, post0), core_count(), post_anchor)
        if _last_walker_end is None or _last_walker_end != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {_last_walker_end} != {len(b)}"}

        # ---- the test: run the stub on the PRE components + E_D
        import jam_impl.disputes as disputes_mod
        try:
            disputes_stf = disputes_mod.disputes_stf
        except AttributeError:
            dbg = _dump_debug(vector=path_no_ext, input=ed,
                              expected_output=j["output"],
                              expected_post=_jsonify(
                                  (post_psi, post_rho, post_tau)))
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify((post_psi, post_rho, post_tau)),
                    "debug_json": dbg}
        stub_out = None
        try:
            stub_out = disputes_stf(
                copy.deepcopy(pre_psi), copy.deepcopy(pre_rho),
                copy.deepcopy(pre_tau), copy.deepcopy(pre_kappa),
                copy.deepcopy(pre_lam), copy.deepcopy(ed), spec)
        except NotImplementedError:
            dbg = _dump_debug(vector=path_no_ext, input=ed,
                              expected_output=j["output"],
                              expected_post=_jsonify(
                                  (post_psi, post_rho, post_tau)),
                              contract=disputes_stf.__doc__ if disputes_stf.__doc__ else None)
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify((post_psi, post_rho, post_tau)),
                    "debug_json": dbg}
        except BaseException as ex:
            import traceback
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": traceback.format_exc(),
                    "expected_output": j["output"],
                    "debug_json": _dump_debug(
                        vector=path_no_ext, input=ed,
                        expected_output=j["output"],
                        failure={"kind": "stub-exception",
                                 "exception": f"{type(ex).__name__}: {ex}",
                                 "traceback": traceback.format_exc()})}

        expected_verdict = "err" if "err" in j["output"] else "ok"
        report_added = {}
        match = True
        if stub_out[0] != expected_verdict:
            match = False
            report_added = {"verdict_mismatch": {
                "stub": stub_out[0],
                "stub_err": stub_out[1] if stub_out[0] == "err" else None,
                "expected": j["output"]}}
        else:
            if stub_out[0] == "ok":
                # offenders mark must equal the vector output-side mark
                want_mark = [bytes.fromhex(k[2:])
                             for k in j["output"]["ok"]["offenders_mark"]]
                got_mark = stub_out[1]
                if _norm(got_mark) != _norm(want_mark):
                    match = False
                    report_added = {"mark_mismatch": {
                        "got": _jsonify(got_mark),
                        "expected": _jsonify(want_mark)}}
            else:
                if stub_out[1] != j["output"]["err"]:
                    match = False
                    report_added = {"err_name_mismatch": {
                        "stub": stub_out[1], "expected": j["output"]["err"]}}
        # ---- post components byte-equal via the wire (value compare only)
        if match:
            stub_psi, stub_rho, stub_tau = stub_out[2]
            want = b[post0:]
            encoded = encode_disputes_state(
                stub_psi, stub_rho, stub_tau, pre_kappa, pre_lam)
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want)))
                          if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                report_added = {"post_state_mismatch": {
                    "stub": _jsonify((stub_psi, stub_rho, stub_tau)),
                    "expected_post": _jsonify((post_psi, post_rho, post_tau)),
                    "first_diff_octet": i,
                    "encoded_hex_head": encoded[:16].hex(),
                    "want_hex_head": want[:16].hex()}}
            elif stub_out[0] == "ok" and stub_out[1] is not None \
                    and not report_added:
                pass
            # marks vs mark leg double-check happens above only

        diff_notes = []
        if not match and "verdict_mismatch" not in report_added \
                and "mark_mismatch" not in report_added \
                and "err_name_mismatch" not in report_added \
                and "post_state_mismatch" not in report_added:
            pass

        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "stub_verdict": stub_out[0],
            "expected_output": j["output"],
            "diff_notes": diff_notes,
            **report_added,
        }
        report["debug_json"] = _dump_debug(
            vector=path_no_ext, input=ed,
            expected_output=j["output"],
            output={"ok": _jsonify(stub_out[1]) if stub_out[0] == "ok"
                    else {"err": stub_out[1]}} if stub_out[0] != "exception"
            else None,
            expected_post=_jsonify((post_psi, post_rho, post_tau)),
            stub_post=_jsonify(tuple(stub_out[2]) if len(stub_out) > 2 else None),
            match=match, diff_notes=diff_notes, **report_added)
        return report


def _norm(x):
    """bytes→bytes, int→int, dataclass→dict, recurse."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, (list, tuple)):
        return [_norm(i) for i in x]
    if dataclasses.is_dataclass(x) and not isinstance(x, type):
        return _norm(dataclasses.asdict(x))
    return x


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO,
                        "jamtestvectors/stf/disputes/*/*.json")))]
    passed = failed = skipped = 0
    for path in paths:
        try:
            rep = run_vector(path)
        except Exception as ex:
            import traceback
            failed += 1
            print(f"  HARNESS-FAIL {os.path.basename(path)}: {ex!r}")
            traceback.print_exc()
            continue
        verdict = rep["verdict"]
        if verdict == "PASS":
            passed += 1
            print(f"  PASS {rep['name']}")
        elif verdict == "STUB-UNIMPLEMENTED":
            skipped += 1
            print(f"  STUB {rep['name']} (disputes_stf not implemented yet;"
                  f" expected dumped to {rep['debug_json']})")
        elif verdict == "CRASH":
            failed += 1
            print(f"  CRASH {rep['name']}: {rep['why']} (stub raised;"
                  f" debug={rep['debug_json']})")
        elif verdict == "HARNESS-FAIL":
            failed += 1
            print(f"  HARNESS-FAIL {rep['name']}: {rep['why']}")
        else:
            failed += 1
            extra = ""
            for key in ("verdict_mismatch", "mark_mismatch",
                        "err_name_mismatch", "post_state_mismatch"):
                if key in rep:
                    extra += (f" {key}: "
                              f"{json.dumps({k: rep[key][k] for k in rep[key]} , default=str)[:220]}")
            print(f"  FAIL {rep['name']}{extra} debug={rep['debug_json']}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))