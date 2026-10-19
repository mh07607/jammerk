"""Preimages STF (E_P) harness — jamtestvectors/stf/preimages/{tiny,full} (16 vectors).

Wire (SCALE, verified byte-exact on all 16, order per jamtestvectors/lib/bin_to_json.py
and preimages/preimages.asn):
    input leg:  n↕{ (E4 requester) (↕) blob }  E4(slot)
    pre-state:  accounts n{ E4(id) blobs n{32B hash ↕blob} requests n{32B hash E4(len)
                n×E4(timeslots)} }  statistics: n{ E4(id) ×10 compacts }   (no ↕ wrapper)
    output leg: ok → 00;  err → 01 (E1 code)   codes: 0=preimage-unneeded,
                1=preimages-not-sorted-unique  (values not GP-specified)
    post-state: same as pre-state

Contract: preimages_stf(accounts, service_statistics_post, preimages,
current_slot) mutates accounts (a_p, a_l buckets) and service_statistics_post
(provided_count/provided_size) in place — mirroring the flat-args house style
of reports_stf/assurances_stf. service_statistics_post is the SAME shape
reports_stf takes: dict[int, ServiceStatistics] keyed by service id, with
records from the repo's models/State.py ServiceStatistics class (all 10
compact columns; decode via decode_service_statistics_record below — the
preimages wire carries bare compacts, no ↕ wrapper). Ids absent from the
pre-state statistics are seeded with a fresh zero record on provide
(verified against the ok vectors: pre π_S is always empty, post π_S gains
exactly the requester ids). The stub raises NotImplementedError until
implemented.
"""
### GP map (0.7.2):
#   §12.x accum.tex eq:preimagesareordered  — E_P is ordered+unique by (id, blob) pair,
#                                             ordering check → preimages_not_sorted_unique
#   eq:fnprovidable (accum.tex)             — d[s].requests[(H(blob), len(blob))] == ∅
#                                             and s ∈ keys(d) → solicited & unprovided
#                                             (else preimage_unneeded)
#   eq:fnprovide (accum.tex)                — on provide: requests[key].append(slot)
#                                             (h=⟨t⟩ 1-element = available-since-t,
#                                             accounts.tex semantics), preimages[h]=blob
#   §13.2 eq servicestats'                  — provision = Σ over E_P of (1, |blob|)
#                                             per service; π_S' is REBUILT per block
#                                             (overwrite, not +=); ids absent from the
#                                             pre-state get fresh zero records

import copy
import glob
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

from jam_impl.util import Decoder
from jam_impl.preimages import PreimagesAccount
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import decode_preimages
from jam_impl.models.Extrinsic import Preimage
from jam_impl.models.State import ServiceStatistics

ERRS = {  # preimages.asn order; sidecars use snake_case names
    0: "preimage_unneeded",
    1: "preimages_not_sorted_unique",
}

STUB_COMPONENTS = [
    "accounts",                 # δ (preimage-relevant buckets only, per-STF wire)
    "service_statistics_post",  # π_S (ServiceStatistics; provided_count/size)
]


def decode_preimages_input(d: Decoder) -> tuple[list[Preimage], int]:
    """Input leg ↦ (preimages, slot); wire walkers verbatim, zero reinterpretation."""
    preimages = decode_preimages(d)
    slot = int.from_bytes(d.take(4), "little")
    return preimages, slot


def decode_service_statistics_record(d: Decoder) -> ServiceStatistics:
    """One π_S record (10 bare compacts, no ↕ wrapper on the preimages wire) →
    models.State.ServiceStatistics. Same record layout as
    decode_reports_statistics / decode_registrar_state in
    jam_impl/codec/state_codec.py (GP 0.7.2 §13.2, jam-types.asn
    ServiceActivityRecord)."""
    return ServiceStatistics(
        provided_count=d.decode_compact(),
        provided_size=d.decode_compact(),
        refinement_count=d.decode_compact(),
        refinement_gas_used=d.decode_compact(),
        imports=d.decode_compact(),
        extrinsic_count=d.decode_compact(),
        extrinsic_size=d.decode_compact(),
        exports=d.decode_compact(),
        accumulate_count=d.decode_compact(),
        accumulate_gas_used=d.decode_compact(),
    )


def decode_preimages_state(d: Decoder) -> tuple[list[PreimagesAccount],
                                                dict[int, ServiceStatistics]]:
    """State legs (pre & post) ↦ (accounts, statistics): π_S records keyed by
    service id, as models.State.ServiceStatistics — the same flat shape
    reports_stf takes."""
    accounts = []
    for _ in range(d.decode_compact()):
        accounts.append(PreimagesAccount(
            service_id=d.u32(),
        ))
        for _ in range(d.decode_compact()):
            h = d.take(32)
            accounts[-1].blobs[h] = d.blob()
        for _ in range(d.decode_compact()):
            h = d.take(32)
            length = int.from_bytes(d.take(4), "little")
            accounts[-1].requests[(h, length)] = [
                int.from_bytes(d.take(4), "little") for _ in range(d.decode_compact())
            ]
    stats: dict[int, ServiceStatistics] = {}
    for _ in range(d.decode_compact()):
        service_id = d.u32()
        stats[service_id] = decode_service_statistics_record(d)
    return accounts, stats


def encode_preimages_state(accounts, stats) -> bytes:
    """Inverse of decode_preimages_state — used to compare the stub's mutated
    components against the vector's post-state bytes."""
    from jam_impl.util import Encoder
    e = Encoder()
    e.compact(len(accounts))
    for acc in accounts:
        e.u32(acc.service_id)
        items = sorted(acc.blobs.items())
        e.compact(len(items))
        for h, blob in items:
            e.raw(h)
            e.blob(blob)
        reqs = sorted(acc.requests.items())
        e.compact(len(reqs))
        for (h, length), ts in reqs:
            e.raw(h)
            e.raw(int(length).to_bytes(4, "little"))
            e.compact(len(ts))
            for t in ts:
                e.raw(int(t).to_bytes(4, "little"))
    e.compact(len(stats))
    for service_id in sorted(stats):
        rec = stats[service_id]
        e.u32(service_id)
        e.compact(rec.provided_count)
        e.compact(rec.provided_size)
        e.compact(rec.refinement_count)
        e.compact(rec.refinement_gas_used)
        e.compact(rec.imports)
        e.compact(rec.extrinsic_count)
        e.compact(rec.extrinsic_size)
        e.compact(rec.exports)
        e.compact(rec.accumulate_count)
        e.compact(rec.accumulate_gas_used)
    return e.finish()


def decode_preimages_output(b: bytes, o: int):
    """Output leg ↦ ('ok', next_off) | ('err', code_name, next_off)."""
    d = Decoder(b)
    d.o = o
    tag = d.u8()
    if tag == 0:
        return "ok", None, d.o
    if tag == 1:
        return "err", ERRS[d.u8()], d.o
    raise ValueError(f"preimages output leg: unknown tag {tag}")


def _stub_module():
    import importlib.util
    if importlib.util.find_spec("jam_impl.preimages") is not None:
        import jam_impl.preimages as m
        stub = getattr(m, "preimages_stf", None)
        return m, stub
    return None, None


def run_vector(path: str) -> dict:
    b = open(path + ".bin", "rb").read()
    j = json.load(open(path + ".json"))
    spec = "tiny" if "/tiny/" in path.replace("\\", "/") else "full"
    with spec_globals(spec):
        d = Decoder(b)
        preimages, slot = decode_preimages_input(d)
        assert d.o <= len(b), "input walk overran"
        pre_accounts, pre_stats = decode_preimages_state(d)
        pre_off = d.o

        verdict, err_name, out_off = decode_preimages_output(b, pre_off)
        post_accounts, post_stats = decode_preimages_state(Decoder(b) if False else _decoder_at(b, out_off))

        stub = _stub_module()[1]
        if stub is None:
            return {"name": os.path.basename(path), "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"]}

        stub_args = {
            "accounts": copy.deepcopy(pre_accounts),
            "service_statistics_post": copy.deepcopy(pre_stats),
        }
        try:
            stub_out = stub(
                stub_args["accounts"],
                stub_args["service_statistics_post"],
                copy.deepcopy(preimages),
                current_slot=slot,
                spec=spec)
        except NotImplementedError:
            return {"name": os.path.basename(path), "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"]}
        except BaseException as ex:
            import traceback
            tb = traceback.format_exc()
            dj = os.path.join(REPO, "jam_impl", "tests", "stf_debug",
                              os.path.basename(path) + ".debug.json")
            with open(dj, "w") as f:
                json.dump({"input": {"preimages": [(q.requester, q.blob.hex()) for q in preimages],
                                     "slot": slot},
                           "expected_output": j["output"],
                           "failure": {"exception": f"{type(ex).__name__}: {ex}",
                                       "traceback": tb}}, f, indent=2)
            return {"name": os.path.basename(path), "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": tb,
                    "debug_json": dj}

        expected_verdict = "err" if "err" in j["output"] else "ok"
        match = True
        notes = {}
        if stub_out[0] != expected_verdict:
            match = False
            notes = {"verdict_mismatch": {"stub": stub_out[0],
                                          "stub_err": stub_out[1] if stub_out[0] == "err" else None,
                                          "expected": j["output"]}}
        elif stub_out[0] == "err" and stub_out[1] != j["output"]["err"]:
            match = False
            notes = {"err_name_mismatch": {"stub": stub_out[1], "expected": j["output"]["err"]}}

        if match:
            encoded = encode_preimages_state(stub_args["accounts"], stub_args["service_statistics_post"])
            want = b[out_off:]
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want))) if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                notes = {"post_state_mismatch": {"first_diff_octet": i,
                                                 "encoded_len": len(encoded), "want_len": len(want)}}

        return {"name": os.path.basename(path), "verdict": "PASS" if match else "FAIL",
                "expected_output": j["output"],
                "debug_json": _dump_debug(path, preimages, slot, j, match, notes, stub_out),
                **notes}


def _dump_debug(path, preimages, slot, j, match, notes, stub_out):
    dump = {"input": {"preimages": [(p.requester, p.blob.hex()) for p in preimages], "slot": slot},
            "expected_output": j["output"],
            "match": match, **notes}
    if isinstance(stub_out, tuple):
        dump["stub_return"] = [str(x) if not isinstance(x, (int, str, type(None))) else x
                               for x in stub_out]
    dj = os.path.join(REPO, "jam_impl", "tests", "stf_debug", os.path.basename(path) + ".debug.json")
    with open(dj, "w") as f:
        json.dump(dump, f, indent=2)
    return dj


def _decoder_at(b: bytes, o: int) -> Decoder:
    d = Decoder(b)
    d.o = o
    return d


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = sorted(glob.glob(os.path.join(REPO, "jamtestvectors/stf/preimages/*/*.json")))
        paths = [p[:-5] for p in paths]
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
        v = rep["verdict"]
        if v == "PASS":
            passed += 1
            print(f"  PASS {rep['name']}")
        elif v == "STUB-UNIMPLEMENTED":
            skipped += 1
            print(f"  STUB {rep['name']} (preimages_stf not implemented yet)")
        elif v == "CRASH":
            failed += 1
            print(f"  CRASH {rep['name']}: {rep['why']} (stub raised; debug={rep['debug_json']})")
        else:
            failed += 1
            reason = next((k for k in ("verdict_mismatch", "err_name_mismatch",
                                       "post_state_mismatch") if k in rep), "")
            print(f"  FAIL {rep['name']} {reason}: {json.dumps({k: rep[k] for k in rep if k not in ('name', 'verdict', 'debug_json')})[:180]} debug={rep['debug_json']}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))