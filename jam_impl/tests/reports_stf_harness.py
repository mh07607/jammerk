"""STF harness: run a reports (work-report guaranteeing) stf vector through
`reports_stf` (the stub you implement in jam_impl/reports.py) and compare the
encoded post_state against the vector's post-state bytes, plus the reported /
reporters output leg.

Layout of every file this touches (verified: all 42 tiny + 42 full vectors
walk byte-exact to EOF; ok-leg outputs, err codes and rotation sets verified
against the JSON sidecars + GP shuffle vectors):

  stf/reports/<spec>/<name>.bin = INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input   = ↕guarantees (repo extrinsic codec: report C.29 + slot E4 ↕creds)
              ‖ slot(E4) ‖ ↕known_packages (n × 32)
    state   = ρ (¿×C: 00 | 01 report timeout-E4)
              ‖ κ (V×336) ‖ λ (V×336) ‖ η (4×32)
              ‖ offenders (↕ + n×32)
              ‖ β (↕history + ↕mmr-peaks, repo decode_recent_history shape)
              ‖ α (C × (↕ + n×32))
              ‖ accounts (n × (E4 id + 89-octet service record))
              ‖ π_C (C × 8 compacts)
              ‖ π_S (↕ + n × (E4 id + 10 compacts))
    output  = 00 ok → n↕ (×n: 32+32 work-package-hash ‖ segment-tree-root)
                       ‖ m↕ (×m: 32 reporter ed25519 keys)
              | 01 err → E1 code (ERRS below; reports.asn enum order)
    post    = same shape as pre

Contract with the stub (jam_impl/reports.py) — FLAT SEMANTIC ARGUMENTS, no
state bag: every GP component is a named parameter, mutating the repo's state
models in place, exactly like assurances_stf / disputes_stf:

    reports_stf(
        availability_assignments,     # ρ: seat / replace / timeout (mutated)
        core_statistics_post,         # π_C refinement components (mutated)
        service_statistics_post,      # π_S refinement components (mutated)
        recent_history,               # β: read-only on this leg,
        current_validators,           # κ
        previous_validators,          # λ (prev-rotation basis)
        entropy,                      # η (shuffle basis)
        disputes,                     # ψ (offenders filter for credentials)
        accounts,                     # δ: read-only (code hash, min_item_gas)
        guarantees,                   # X_G, decoded input leg
        current_slot,                 # τ' (input leg)
        known_packages,               # input leg (see notes; hand through)
        spec,
    )
      → ("ok", reported: list[(work_package_hash, exports_root)],   # 32‖32
               reporters: list[bytes])                              # ed25519 keys
      → ("err", err_name: str)

  The stub receives the PRE components and mutates them in place: ρ seating /
  replacement (timeout = present slot t'), statistics accumulation
  (π_C: imports i, extrinsic_count x, extrinsic_size z, exports e,
  bundle_size b, gas_used u; π_S: refinement_count r.0, refinement_gas_used
  r.1, imports i, extrinsics x, extrinsic_size z, exports e).
  Err vectors leave the state untouched (verified: pre bytes == post bytes on
  all 56 err vectors).

  β (recent history) is READ-ONLY on the reports leg: verified against the
  JSON sidecars, recent_blocks is pre==post identical on every ok vector; the
  (reported, reporters) output leg is what the outer block layer folds back
  into β's next entry. known_packages equals sorted(K(β_H[*].reported)) +
  the package hashes of any reports seated in ρ (the two pre-seated vectors
  carry those extras) — pass it through as decoded rather than re-deriving.
  The ancestor-record check (GP 0.7.2 eq 11.35) needs the ancestor header
  series A, which is not on this wire; it is checked upstream of this STF.

Verification performed by this harness per vector:
  1. run the stub on the decoded pre-components,
  2. byte-compare the harness-encoded post-state against the wire,
  3. value-compare (reported, reporters) against the vector's ok-output.

Usage:
    uv run jam_impl/tests/reports_stf_harness.py jamtestvectors/stf/reports/tiny/multiple_reports-1
    uv run jam_impl/tests/reports_stf_harness.py            # all reports vectors
"""
import copy
import glob
import json
import os
import sys
import dataclasses
from typing import Any

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import decode_guarantees, encode_guarantees, encode_report
from jam_impl.codec.state_codec import (
    decode_availability_assignments, encode_availability_assignments,
    decode_current_validators, encode_current_validators,
    decode_previous_validators, encode_previous_validators,
    decode_entropy_accumulator, encode_entropy_accumulator,
    decode_recent_history, encode_recent_history,
    decode_authorization_pool, encode_authorization_pool,
    decode_service_definition, encode_service_definition,
    decode_reports_statistics, encode_reports_statistics,
)
from jam_impl.util import Decoder, Encoder

ERRS = [  # reports.asn ErrorCode order; json sidecars use the snake_case names
    "bad_core_index",                  # 0
    "future_report_slot",              # 1
    "report_epoch_before_last",        # 2
    "insufficient_guarantees",         # 3
    "out_of_order_guarantee",          # 4
    "not_sorted_or_unique_guarantors", # 5
    "wrong_assignment",                # 6
    "core_engaged",                    # 7
    "anchor_not_recent",               # 8
    "bad_service_id",                  # 9
    "bad_code_hash",                   # 10
    "dependency_missing",              # 11
    "duplicate_package",               # 12
    "bad_state_root",                  # 13
    "bad_beefy_mmr_root",              # 14
    "core_unauthorized",               # 15
    "bad_validator_index",             # 16
    "work_report_gas_too_high",        # 17
    "service_item_gas_too_low",        # 18
    "too_many_dependencies",           # 19
    "segment_root_lookup_invalid",     # 20
    "bad_signature",                   # 21
    "work_report_too_big",             # 22
    "banned_validator",                # 23
    "lookup_anchor_not_recent",        # 24
    "missing_work_results",            # 25
]


# ---------------------------------------------------------------------------
# Account record wrapper (ServiceRecord is kept for the accounts-span walkers:
# the reports-stf positional wire carries C(255,s) bodies (89 octets each),
# not the whole-C(13) registrar layout). NO state-bag class otherwise — the
# components are handed to the stub as flat semantic arguments.
# ---------------------------------------------------------------------------

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


# π_C/π_S are decoded/encoded by decode_reports_statistics/encode_reports_statistics
# in jam_impl/codec/state_codec.py, using the repo's CoreStatistics /
# ServiceStatistics classes; services are keyed by service id in a dict,
# mirroring RegistrarState.services_stats in jam_impl/models/State.py.


# ---------------------------------------------------------------------------
# Wire walkers (delegating every component to the repo codecs)
# ---------------------------------------------------------------------------

def _v_len() -> int:
    import jam_impl.util as util
    return util.NUM_VALIDATORS_IN_EPOCH_MARK * (32 + 32 + 144 + 128)


def decode_reports_input(d: Decoder):
    """stf input: ↕guarantees ‖ slot(E4) ‖ ↕known_packages →
    (guarantees, slot, known_packages)."""
    guarantees = decode_guarantees(d)
    slot = d.u32()
    known = [d.hash32() for _ in range(d.decode_compact())]
    return guarantees, slot, known


def encode_reports_input(guarantees, slot, known) -> bytes:
    e = Encoder()
    e.raw(encode_guarantees(guarantees))
    e.u32(slot)
    e.compact(len(known))
    for k in known:
        e.hash32(k)
    return e.finish()


def decode_reports_state(d: Decoder):
    """One reports stf state (pre or post) → the flat components (classes).

    Component order: ρ (¿×C) κ λ η offenders β α accounts π_C π_S.
    ρ/κ/λ/η/β/α decode via the repo codecs over their exact spans; accounts/
    π_C/π_S walk inline (their whole-C(13)-layout shapes differ on this wire).
    Returns a components dict keyed by the reports_stf argument names.
    """
    import jam_impl.util as util
    C = util.NUM_VALIDATORS_IN_EPOCH_MARK // util.CORE_SIZE
    V = util.NUM_VALIDATORS_IN_EPOCH_MARK

    rho0 = d.o
    for _ in range(C):
        if d.u8() == 1:
            from jam_impl.codec.extrinsic_codec import decode_report
            decode_report(d)
            d.u32()
    rho1 = d.o
    kap0 = kap1 = d.o
    d.o = kap1 = kap0 + V * 336
    lam0 = lam1 = d.o
    d.o = lam1 = lam0 + V * 336
    eta0 = eta1 = d.o
    d.o = eta1 = eta0 + 128

    n_off = d.decode_compact()
    offenders = [d.hash32() for _ in range(n_off)]

    rb0 = d.o
    for _ in range(d.decode_compact()):
        d.hash32(); d.hash32(); d.hash32()
        for _ in range(d.decode_compact()):
            d.hash32(); d.hash32()
    for _ in range(d.decode_compact()):
        if d.u8() == 1:
            d.hash32()
    rb1 = d.o

    ap0 = d.o
    for _ in range(C):
        for _ in range(d.decode_compact()):
            d.hash32()
    ap1 = d.o

    accounts = []
    n_acc = d.decode_compact()
    for _ in range(n_acc):
        service_id = d.u32()
        accounts.append(ServiceRecord(
            service_id, decode_service_definition(d.b[d.o:d.o + ServiceRecord.SIZE], service_id)))
        d.o += ServiceRecord.SIZE

    cores, services = decode_reports_statistics(d)

    b = d.b
    return {
        "availability_assignments": decode_availability_assignments(b[rho0:rho1]),
        "current_validators":       decode_current_validators(b[kap0:kap1]),
        "previous_validators":      decode_previous_validators(b[lam0:lam1]),
        "entropy":                  decode_entropy_accumulator(b[eta0:eta1]),
        "disputes":                 offenders,
        "recent_history":           decode_recent_history(b[rb0:rb1]),
        "authorization_pools":      decode_authorization_pool(b[ap0:ap1]),
        "accounts":                 accounts,
        "core_statistics_post":     cores,
        "service_statistics_post":  services,
    }, d.o


def encode_reports_state(components: dict) -> bytes:
    """Flat components → the stf's flat state wire (inverse of decode)."""
    e = Encoder()
    e.raw(encode_availability_assignments(components["availability_assignments"]))
    e.raw(encode_current_validators(components["current_validators"]))
    e.raw(encode_previous_validators(components["previous_validators"]))
    e.raw(encode_entropy_accumulator(components["entropy"]))
    e.compact(len(components["disputes"]))
    for k in components["disputes"]:
        e.hash32(k)
    e.raw(encode_recent_history(components["recent_history"]))
    e.raw(encode_authorization_pool(components["authorization_pools"]))
    e.compact(len(components["accounts"]))
    for account in components["accounts"]:
        e.u32(account.service_id)
        e.raw(_encode_service_record(account))
    encode_reports_statistics(e, components["core_statistics_post"],
                              components["service_statistics_post"])
    return e.finish()


def _encode_service_record(account: ServiceRecord) -> bytes:
    from jam_impl.codec.state_codec import encode_service_definition
    if account.definition is None:
        raise ValueError(f"account {account.service_id} has no decoded record")
    return encode_service_definition(account.definition)


def decode_reports_output(b: bytes, o: int):
    """Output wire → ("ok", reported, reporters, next_offset) | ("err", name, next_offset).
    Wire: 00 → n↕(hash64 ×n) m↕(32 ×m) | 01 → E1 code."""
    import jam_impl.util as util
    d = Decoder(b); d.o = o
    if d.u8() == 0:                                       # ok
        reported = [(d.hash32(), d.hash32()) for _ in range(d.decode_compact())]
        reporters = [d.hash32() for _ in range(d.decode_compact())]
        return "ok", reported, reporters, d.o
    code = d.u8()
    return "err", (ERRS[code] if code < len(ERRS) else code), None, d.o


def encode_reports_output(verdict: str, payload) -> bytes:
    e = Encoder()
    if verdict == "ok":
        reported, reporters = payload
        e.u8(0).compact(len(reported))
        for wp, st in reported:
            e.hash32(wp).hash32(st)
        e.compact(len(reporters))
        for k in reporters:
            e.hash32(k)
    else:
        e.u8(1).u8(ERRS.index(payload))
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
        return {f: _jsonify(getattr(o, f)) for f in o.__dataclass_fields__}
    from enum import Enum
    if isinstance(o, Enum):
        return o.name
    if isinstance(o, (int, str, bool, float)) or o is None:
        return o
    return repr(o)


def _dump_debug(**kw):
    name = os.path.basename(str(kw.get("vector", "debug")))
    if name in ("devnull", "null") or not name:
        return None
    path = os.path.join(REPO, "jam_impl", "tests", "stf_debug", name + ".json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(_jsonify(kw), f, indent=1)
    return path


def _norm(x):
    """bytes→bytes, int→int, dataclass→dict, recurse; ServiceRecord etc get
    normalized by their public attrs so stub shapes compare uniformly."""
    if isinstance(x, (bytes, bytearray)):
        return bytes(x)
    if isinstance(x, (list, tuple)):
        return [_norm(i) for i in x]
    if isinstance(x, ServiceRecord):
        return _norm([x.service_id, x.balance(), x.code_hash()])
    if dataclasses.is_dataclass(x) and not isinstance(x, type):
        return _norm(dataclasses.asdict(x))
    return x


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

# The components handed to reports_stf (the wire-decoded pre-state, minus the
# state models this stf does not consume: α auth pools ride the wire for
# layout-symmetry only) — mirrors the stub signature in jam_impl/reports.py.
STUB_COMPONENTS = (
    "availability_assignments", "core_statistics_post", "service_statistics_post",
    "recent_history", "current_validators", "previous_validators",
    "entropy", "disputes", "accounts",
)


def run_vector(path_no_ext, verbose=True):
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        guarantees, slot, known_packages = decode_reports_input(d)
        input_end = d.o
        pre, pre_off = decode_reports_state(d)
        assert d.o <= len(b), "pre-state walk overran"

        verdict_want, reported_want, reporters_want, out_off = \
            decode_reports_output(b, d.o)
        post, post_off = decode_reports_state(_decoder_at(b, out_off))
        if post_off != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {post_off} != {len(b)}"}

        # ---- the test: run the stub on PRE + input (flat components)
        import importlib.util
        if importlib.util.find_spec("jam_impl.reports") is not None:
            import jam_impl.reports as reports_mod
            stub = getattr(reports_mod, "reports_stf", None)
        else:
            stub = None
        if stub is None:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(pre)}
        stub_out = None
        try:
            stub_args = {name: copy.deepcopy(pre[name]) for name in STUB_COMPONENTS}
            stub_out = stub(
                **stub_args,
                guarantees=copy.deepcopy(guarantees),
                current_slot=slot,
                known_packages=copy.deepcopy(known_packages),
                spec=spec)
        except NotImplementedError:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(pre)}
        except BaseException as ex:
            import traceback
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": traceback.format_exc(),
                    "expected_output": j["output"],
                    "debug_json": _dump_debug(
                        vector=path_no_ext,
                        input={"guarantees": guarantees, "slot": slot,
                               "known_packages": known_packages},
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
                want_mark = _mark_from_json(j)
                got = (stub_out[1], stub_out[2])
                if _norm(got) != _norm(want_mark):
                    match = False
                    report_added = {"reported_mismatch": {
                        "got": _jsonify(got),
                        "expected": _jsonify(want_mark)}}
            else:
                if stub_out[1] != j["output"]["err"]:
                    match = False
                    report_added = {"err_name_mismatch": {
                        "stub": stub_out[1], "expected": j["output"]["err"]}}
        # ---- post state byte-equal: the stub mutates the pre-state components.
        # Tuple shapes: ok → (verdict, reported, reporters); err → (verdict, name).
        if match:
            encoded = encode_reports_state({**pre, **stub_args})
            want = b[out_off:]
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want)))
                          if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                report_added = {"post_state_mismatch": {
                    "stub": _jsonify({name: pre[name] for name in STUB_COMPONENTS}),
                    "expected_post": _jsonify(post),
                    "first_diff_octet": i,
                    "encoded_hex_head": encoded[:16].hex(),
                    "want_hex_head": want[:16].hex()}}

        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "stub_verdict": stub_out[0],
            "expected_output": j["output"],
            "diff_notes": [],
            **report_added,
        }
        report["debug_json"] = _dump_debug(
            vector=path_no_ext,
            input={"guarantees": guarantees, "slot": slot,
                   "known_packages": known_packages},
            expected_output=j["output"],
            output={"ok": {"reported": _jsonify(stub_out[1]),
                           "reporters": _jsonify(stub_out[2])}
                    if stub_out[0] == "ok" else {"err": stub_out[1]}
                    if isinstance(stub_out, tuple) and len(stub_out) > 2 else None},
            expected_post=_jsonify(post),
            stub_post=_jsonify({name: pre[name] for name in STUB_COMPONENTS})
                      if isinstance(stub_out, tuple) else None,
            match=match, **report_added)
        return report


def _decoder_at(b: bytes, o: int) -> Decoder:
    d = Decoder(b)
    d.o = o
    return d


def _mark_from_json(j):
    ok = j["output"].get("ok") or {}
    reported = [(bytes.fromhex(x["work_package_hash"][2:]),
                 bytes.fromhex(x["segment_tree_root"][2:]))
                for x in (ok.get("reported") or [])]
    reporters = [bytes.fromhex(k[2:]) for k in (ok.get("reporters") or [])]
    return (reported, reporters)


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO,
                        "jamtestvectors/stf/reports/*/*.json")))]
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
            print(f"  STUB {rep['name']} (reports_stf not implemented yet;"
                  f" expected available in rep['expected_post'])")
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
            for key in ("verdict_mismatch", "reported_mismatch",
                        "err_name_mismatch", "post_state_mismatch"):
                if key in rep:
                    extra += (f" {key}: "
                              f"{json.dumps(rep[key], default=str)[:200]}")
            print(f"  FAIL {rep['name']}{extra} debug={rep['debug_json']}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))