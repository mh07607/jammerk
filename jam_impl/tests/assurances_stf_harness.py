"""STF harness: run an assurances stf vector through `assurances_stf` (the stub
you implement in jam_impl/assurances.py) and compare the encoded post_state
against the vector's post-state bytes, plus the reported-reports output leg.

Layout of every file this touches (verified byte-exact against the vendored
jamtestvectors, tiny and full — frame walked on 10/10 tiny vectors):

  stf/assurances/<spec>/<name>.bin =
      INPUT(E_A ‖ slot ‖ parent) ‖ PRE(ρ† ‖ κ) ‖ OUTPUT ‖ POST(ρ‡ ‖ κ)
    input   = ↕assurances ‖ slot(E4) ‖ parent(32)
              assurance = anchor(32) bitfield(bits(C)) assurer(E2) sig(64)
    state   = ρ† (¿×C: 00 | 01 report τ_E4) ‖ κ (V×336)   [NO other components]
    output  = 00 ok → ↕(reported WorkReports — the entries REMOVED from ρ†
                          because they became available; 00 when empty)
              | 01 err → E1 code (ERRS: disputes-style snake_case)
    post    = same shape as pre

Contract with the stub (jam_impl/assurances.py):

    assurances_stf(rho: AvailabilityAssignments,
                   kappa: CurrentValidators,
                   assurances: list[Assurance],
                   slot: int, parent: bytes, spec)
      → ("ok",   reported: list[Report],        # newly available reports
                 post_rho: AvailabilityAssignments)
      → ("err",  err_name: str,
                 post_rho: AvailabilityAssignments)

  Only ρ†/ρ‡ is mutated by this stf (κ/λ untouched — κ is threaded by the
  harness into the post-state encoder; the vector's output reports are the
  reports REMOVED from ρ† which BECAME available — stale removals (timeout
  exceeded) are removed from the state but NOT returned in the output, as
  the README's no_assurances_with_stale_report-1 documents).

Usage:
    uv run jam_impl/tests/assurances_stf_harness.py jamtestvectors/stf/assurances/tiny/some_assurances-1
    uv run jam_impl/tests/assurances_stf_harness.py            # all assurances vectors
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

from jam_impl.util import Decoder, Encoder
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import (
    decode_assurances, encode_assurances, decode_report, encode_report,
)
from jam_impl.codec.state_codec import (
    decode_availability_assignments, encode_availability_assignments,
    decode_current_validators, encode_current_validators,
)
from jam_impl.models.State import (
    AvailabilityAssignments, AvailabilityAssignment,
    CurrentValidators,
)

ERRS = [  # assurances.asn order; json uses snake_case of the same names
    "bad_attestation_parent", "bad_validator_index", "core_not_engaged",
    "bad_signature", "not_sorted_or_unique_assurers",
]

# ---------------------------------------------------------------------------
# Wire walkers (thin: delegate every field to the repo codecs)
# ---------------------------------------------------------------------------


def _v_len() -> int:
    import jam_impl.util as util
    return util.NUM_VALIDATORS_IN_EPOCH_MARK * (32 + 32 + 144 + 128)


_last_walker_end = None


def _decoder_at(b: bytes, o: int) -> Decoder:
    d = Decoder(b)
    d.o = o
    return d


def decode_assurances_input(d: Decoder):
    """stf input: ↕E_A + slot(E4) + parent(32) → (assurances, slot, parent)."""
    assurances = decode_assurances(d)
    slot = d.u32()
    parent = d.hash32()
    return assurances, slot, parent


def _decode_rho_state(d: Decoder, anchor: bytes):
    """One assurances stf state (pre or post) → (rho, kappa).

    stf component ORDER: ρ (¿×C) κ (V×336). ρ is decoded over its exact
    [start, κ) slice — its finish() validates the boundary; the κ offset
    is LOCATED by anchoring on κ[0].bandersnatch (kappa never mutates)."""
    global _last_walker_end
    o0 = d.o
    kap_at = d.b.find(anchor, o0)
    if kap_at < 0:
        raise ValueError("assurances stf: κ[0] anchor not found after start")
    rho = decode_availability_assignments(d.b[o0:kap_at])
    from jam_impl.codec.state_codec import decode_current_validators as _dcv
    kap_at_check = kap_at
    kappa = decode_current_validators(d.b[kap_at:kap_at + _v_len()])
    d.o = kap_at + _v_len()
    _last_walker_end = d.o
    return rho, kappa


def decode_assurances_output(b: bytes, o: int):
    """Output wire → ("ok", reported reports | None) | ("err", name).

    Wire: 00 ok → ↕(WorkReports) — plain COMPACT count (00 = empty, no
    separate presence tag; byte-proved on no_assurances-1/faults-analogues);
    01 err → E1 code, ERRS[code]."""
    d = Decoder(b); d.o = o
    tag = d.u8()
    if tag == 0:
        n = d.decode_compact()
        reports = []
        for _ in range(n):
            reports.append(decode_report(d))
        return "ok", reports, d.o
    code = d.u8()
    return "err", ERRS[code] if code < len(ERRS) else code, d.o


def encode_assurances_output(verdict: str, mark_or_err) -> bytes:
    e = Encoder()
    if verdict == "ok":
        e.u8(0).compact(len(mark_or_err))
        for rep in mark_or_err:
            encode_report(e, rep)
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
        return {f: _jsonify(getattr(o, f)) for f in o.__dataclass_fields__}
    from enum import Enum
    if isinstance(o, Enum):
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
    global _last_walker_end
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    from jam_impl.codec.state_codec import core_count
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        assurances, slot, parent = decode_assurances_input(d)
        kappa0 = bytes.fromhex(j["pre_state"]["curr_validators"][0]["bandersnatch"][2:])
        pre_rho, pre_kappa = _decode_rho_state(d, kappa0)
        assert d.o <= len(b), "pre-state walk overran"

        out_off = _last_walker_end
        verdict, out_payload, post_off = decode_assurances_output(b, out_off)
        post0 = out_off + 2 if verdict == "err" else post_off
        post_kappa0 = bytes.fromhex(j["post_state"]["curr_validators"][0]["bandersnatch"][2:])
        post_rho, post_kappa = _decode_rho_state(_decoder_at(b, post0), post_kappa0)
        if _last_walker_end != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {_last_walker_end} != {len(b)}"}

        # ---- the test: run the stub.
        import jam_impl.assurances as assurances_mod
        try:
            assurances_stf = assurances_mod.assurances_stf
        except AttributeError:
            dbg = _dump_debug(vector=path_no_ext, input={"assurances": assurances,
                                                          "slot": slot, "parent": parent},
                              expected_output=j["output"],
                              expected_post=_jsonify((post_rho, post_kappa)))
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify((post_rho, post_kappa)),
                    "debug_json": dbg}
        stub_out = None
        try:
            stub_out = assurances_stf(
                copy.deepcopy(pre_rho), copy.deepcopy(pre_kappa),
                copy.deepcopy(assurances), slot, parent, spec)
        except NotImplementedError:
            dbg = _dump_debug(vector=path_no_ext,
                              input={"assurances": assurances, "slot": slot, "parent": parent},
                              expected_output=j["output"],
                              expected_post=_jsonify((post_rho, post_kappa)))
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify((post_rho, post_kappa)),
                    "debug_json": dbg}
        except BaseException as ex:
            import traceback
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": traceback.format_exc(),
                    "expected_output": j["output"],
                    "debug_json": _dump_debug(
                        vector=path_no_ext,
                        input={"assurances": assurances, "slot": slot, "parent": parent},
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
                want_reports = [rep for rep in _jsonify_decode(j, "ok")]
                got = stub_out[1]
                if _norm(got) != _norm(want_reports):
                    match = False
                    report_added = {"reported_mismatch": {
                        "got": _jsonify(got),
                        "expected": _jsonify(want_reports)}}
            else:
                if stub_out[1] != j["output"]["err"]:
                    match = False
                    report_added = {"err_name_mismatch": {
                        "stub": stub_out[1], "expected": j["output"]["err"]}}
        # ---- post state byte-equal: κ threaded from the pre-state
        if match:
            stub_rho_post = stub_out[2]
            want = b[post0:]
            encoded = _encode_assurances_state(stub_rho_post, pre_kappa)
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want)))
                          if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                report_added = {"post_state_mismatch": {
                    "stub": _jsonify(stub_rho_post),
                    "expected_post": _jsonify(post_rho),
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
            input={"assurances": assurances, "slot": slot, "parent": parent},
            expected_output=j["output"],
            output={"ok": _jsonify(stub_out[1]) if stub_out[0] == "ok"
                    else {"err": stub_out[1]}} if isinstance(stub_out, tuple)
            else None,
            expected_post=_jsonify(post_rho),
            stub_post=_jsonify(stub_out[2]) if isinstance(stub_out, tuple) and len(stub_out) > 2 else None,
            match=match, **report_added)
        return report


def _jsonify_decode(j, key):
    """vector output.ok.reported (json) → [Report models] for value compare."""
    from jam_impl.models.Extrinsic import (PackageSpec, Context, ResultItem,
                                           WorkResult, ResultOk, RefineLoad,
                                           Report, SegmentRootLookupEntry)

    def refine_from_json(rj):
        return RefineLoad(gas_used=rj["gas_used"], imports=rj["imports"],
                          extrinsic_count=rj["extrinsic_count"],
                          extrinsic_size=rj["extrinsic_size"],
                          exports=rj["exports"])

    def report_from_json(rj):
        results = []
        for x in rj["results"]:
            tag = x["result"]
            tag_name = next(iter(tag))
            wattr = {"out_of_gas": "OUT_OF_GAS", "panic": "PANIC",
                     "ok": "OK", "invalid_exports_count": "INVALID_EXPORTS_COUNT",
                     "digest_size_limit_exceeded": "DIGEST_SIZE_LIMIT_EXCEEDED",
                     "bad_code": "BAD_CODE", "big": "BIG"}.get(tag_name, tag_name)
            result = getattr(WorkResult, wattr)
            payload = ResultOk(ok=hxj(tag[tag_name])) if tag_name == "ok" else None
            results.append(ResultItem(
                service_id=x["service_id"],
                code_hash=hxj(x["code_hash"]),
                payload_hash=hxj(x["payload_hash"]),
                accumulate_gas=x["accumulate_gas"],
                result=result,
                result_payload=payload,
                refine_load=refine_from_json(x["refine_load"])))
        return Report(
            package_spec=PackageSpec(hash=hxj(rj["package_spec"]["hash"]),
                                     length=rj["package_spec"]["length"],
                                     erasure_root=hxj(rj["package_spec"]["erasure_root"]),
                                     exports_root=hxj(rj["package_spec"]["exports_root"]),
                                     exports_count=rj["package_spec"]["exports_count"]),
            context=Context(anchor=hxj(rj["context"]["anchor"]),
                            state_root=hxj(rj["context"]["state_root"]),
                            beefy_root=hxj(rj["context"]["beefy_root"]),
                            lookup_anchor=hxj(rj["context"]["lookup_anchor"]),
                            lookup_anchor_slot=rj["context"]["lookup_anchor_slot"],
                            prerequisites=[hxj(x) for x in rj["context"]["prerequisites"]]),
            core_index=rj["core_index"],
            authorizer_hash=hxj(rj["authorizer_hash"]),
            auth_gas_used=rj["auth_gas_used"],
            auth_output=hxj(rj["auth_output"]),
            segment_root_lookup=[SegmentRootLookupEntry(hxj(e["work_package_hash"]),
                                                         hxj(e["segment_tree_root"]))
                                  for e in rj["segment_root_lookup"]],
            results=results,
        )

    def hxj(x):
        return bytes.fromhex(x[2:]) if isinstance(x, str) else x

    ok = j["output"].get("ok") or {}
    return [report_from_json(r) for r in (ok.get("reported") or [])]


def _encode_assurances_state(rho, kappa) -> bytes:
    e = Encoder()
    e.raw(encode_availability_assignments(rho))
    e.raw(encode_current_validators(kappa))
    return e.finish()


def _norm(x):
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
                        "jamtestvectors/stf/assurances/*/*.json")))]
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
            print(f"  STUB {rep['name']} (assurances_stf not implemented yet;"
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