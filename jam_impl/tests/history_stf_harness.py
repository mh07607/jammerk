"""History STF (D.1/§11 recent-history block advancement) harness —
jamtestvectors/stf/history/{tiny,full} (8 vectors: 4 tiny + 4 full, mirrored
copies).

Wire (SCALE, verified byte-exact on all 8; schema jamtestvectors/stf/history/
history.asn, JSON per lib/bin_to_json.py). The state legs ARE the C(3) β
component verbatim — same layout decode_recent_history in
jam_impl/codec/state_codec.py parses (unlike the reports harness, whose
positional per-STF state needed span-walking):

  stf/history/<spec>/<name>.bin = INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input   = H(32, new head's header hash) ‖ H_r(32, parent state root)
              ‖ r(32, accumulation-output Merkle root)
              ‖ ↕wp (n × (32 work-package hash ‖ 32 exports root))
    state   = β only: ↕β_H (n × (hh32 ‖ beefy32 ‖ sroot32 ‖ ↕rep (n × 64)))
              ‖ β_B (n × ¿-tagged peaks: 01 → 32-octet peak, 00 → None)
    output  = NULL — nothing at all (no tag, no bytes): this leg never errs
    post    = same shape as pre

GP equation map (0.8.0 graypaper/text/recent_history.tex; every equation
verified against the vectors — note 0.7.2 DIFFERS: old entry order was
⟨hash, sroot, beefy, t⟩ newest-first):

  eq:correctlaststateroot — PRE-APPEND correction: the OLDEST entry's
      state-root is replaced by H_r ("the state root of the parent block as
      found in the current header" — the parent's posterior root, newly
      known here), then the corrected history is carried below.
      Vector-verified on -2/-3/-4 (the corrected tail keeps its own
      hh/beefy/reported).
  eq:recenthistorydef — the new head is appended at the END (history[] is
      OLDEST-FIRST on this wire):
        BlockInfo(header_hash = H,           # taken as given from the input
                  beefy_root   = <head beefy>,   # see GATED FIELD below
                  state_root   = zero-hash,      # vector-verified literal
                  reported     = work_packages)  # dict semantics; wire = input
      v1–v3 verified: head beefy_root == the POST belt's top peak, i.e. with
      ≤1 live belt peak the GP mmsuperpeak base cases return that peak raw
      (a fresh belt's single leaf = acc_root itself: -1's 8720… = acc root ✓).
  cap  — 2^Cmaxhistorylen = 8 entries (jamtestvectors max-blocks-history=8);
      the cap applies to the CORRECTED sequence: -4 drops the oldest block
      which is exactly the tail that just received its correction.
  belt — β_B' = mmb_append(β_B, r), one leaf r per block (eq:accoutbeltdef;
      leaf values are the accumulation roots; H = keccak256; no $leaf wrap —
      leaves append as the raw root, eq:mmrappend P() cases vector-verified):
        n ≥ len(r)          → r.append(leaf)
        n < len(r), r[n]=∅  → r[n] = leaf        # -4: slot 0 ∅ takes the leaf
                                                 # DIRECTLY — no H(), and the
                                                 # ∅-slot placement TERMINATES
                                                 # the merge (no cascade)
        otherwise           → r[n]=∅; recurse P(r, H(r[n]‖leaf), n+1)
      The merge at step n+1 (0-based leaves) fires iff n+1 == 2^j: the two
      same-height live peaks (slots ≤ j) fold pairwise 'old ‖ new' —
      K(r[n]‖leaf) chains upward (old slot left of the new leaf) — and the
      folded root takes slot j; all lower slots (incl. ∅ ones) reset to ∅.
      Verified: -2 fold K(8720‖7507) = 7076… ; -3 triple-chain into a single
      height-3 top peak; belt needs NO extra state (live leaf count =
      Σ 2^i over live slots — self-describing; -3 pre: 7 = 1+2+4 ✓, -4
      post: 9 = 1+8 ✓).

GATED FIELD (documented divergence — the ONLY thing not reproduced):
  progress_blocks_history-4's new-head beefy_root (ebdb6db060af…). The post
  belt there = [a983, ∅, ∅, 658b] whose GP super-peak folds
  K($peak ‖ K($peak‖a983) ‖ 658b); the vector's value did not match that nor
  30+ other swept constructions (operand orders, $leaf/$node/0x18 prefixes,
  ∅-as-zero-slot chains, left/right-deep folds, count-prefixed roots,
  $jam_beefy contexts, blake2b). The harness byte-compares the belt leg and
  all other history fields STRICTLY, and the new head's beefy_root through a
  gate: when the ONLY divergence is that one field, the row reports
  `beefy_root_gate` with the stub's value instead of a bare
  post_state_mismatch (still a FAIL — the gate only sharpens the diagnosis;
  flip STRICT_HEAD_BEEFY = False to treat that single field as
  pass-through while the host recipe is unconfirmed).

Discrepancy note (wire vs GP 0.8.0): the vector history entries carry NO
⟨t⟩ timeslot field (hh ‖ beefy ‖ sroot ‖ rep) although eq:recentspec's
entry includes it — jamtestvectors 0.7.1 serialization. The repo's
BlockInfo model has no timeslot field either, so nothing to fill.

Verification performed by this harness per vector:
  1. decode the input + pre β and round-trip-encode both (byte-exact
     self-checks against the wire before anything is trusted),
  2. decode the expected post β (same round-trip self-check),
  3. run the stub on a deep-copied PRE β + the input leg (flat args),
  4. re-encode the stub's mutated β and byte-compare against the post wire,
  5. value-check the update semantics (corrected tail / new head / cap).

Contract with the stub (jam_impl/history.py) — FLAT SEMANTIC ARGUMENTS, no
state bag, mutating the repo's RecentHistory model in place (house style of
reports_stf / preimages_stf):

    history_stf(
        recent_history,      # RecentHistory β (mutated: .history + .mmr_peaks)
        header_hash,         # bytes32 — H, blake2b of the head's header encoding
        parent_state_root,   # bytes32 — H_r (the appended tail's corrected root)
        accumulate_root,     # bytes32 — r (belt leaf for this block)
        work_packages,       # list[ReportedWorkPackage] — this block's reports
        spec,
    ) → None                 # ("ok" is implicit; the output leg is NULL)

Missing infrastructure (YOURS to implement — NOT done here, per instruction):
  1. util.hash_via_keccak256 is an explicit TO-DO stub → the belt fold
     needs keccak-256 (NOT hashlib.sha3_256 — different permutation
     padding; verified K(8720‖7507) via pycryptodome). One-liner:
       def hash_via_keccak256(data: bytes) -> bytes:
           from Crypto.Hash import keccak
           h = keccak.new(digest_bits=256); h.update(data); return h.digest()
     (needs `uv add pycryptodome`; no other dep change).
  2. jam_impl/history.py — the stub module (draft staged beside this
     harness; create-permission on jam_impl/ was still ACL-blocked when
     this harness was staged).
  3. mmb_append bookkeeping is derivable from mmr_peaks alone (leaf count
     = Σ 2^i over live slots) — no model change needed; implement the
     append as a helper in history.py (or util.py) once keccak lands.

Usage:
    uv run jam_impl/tests/history_stf_harness.py jamtestvectors/stf/history/tiny/progress_blocks_history-1
    uv run jam_impl/tests/history_stf_harness.py            # all history vectors
"""
import copy
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
    decode_recent_history, encode_recent_history, RECENT_HISTORY_LENGTH,
)
from jam_impl.models.State import RecentHistory, BlockInfo, ReportedWorkPackage

STRICT_HEAD_BEEFY = True   # False → v4-style head beefy_root field pass-through

ZERO_HASH = b"\x00" * 32   # eq:recenthistorydef: new head's state root


# ---------------------------------------------------------------------------
# Wire walkers
# ---------------------------------------------------------------------------

def decode_history_input(d: Decoder):
    """Input leg → (header_hash, parent_state_root, accumulate_root,
    work_packages [(32B hash, 32B exports_root)])."""
    header_hash = d.hash32()
    parent_state_root = d.hash32()
    accumulate_root = d.hash32()
    work_packages = [(d.hash32(), d.hash32())
                     for _ in range(d.decode_compact())]
    return header_hash, parent_state_root, accumulate_root, work_packages


def encode_history_input(header_hash, parent_state_root, accumulate_root,
                         work_packages) -> bytes:
    """Round-trip of decode_history_input (self-check + byte framing)."""
    e = Encoder()
    e.hash32(header_hash).hash32(parent_state_root).hash32(accumulate_root)
    e.compact(len(work_packages))
    for h, s in work_packages:
        e.hash32(h).hash32(s)
    return e.finish()


def _walk_recent_history(d: Decoder):
    """Span-walk one state leg (pre or post) without invoking the component
    codecs' finish() asserts. History: n × (hh, beefy, sroot, ↕rep n × 64);
    belt: n × ¿(01 → 32B)."""
    for _ in range(d.decode_compact()):
        d.hash32(); d.hash32(); d.hash32()
        for _ in range(d.decode_compact()):
            d.hash32(); d.hash32()
    for _ in range(d.decode_compact()):
        if d.u8() == 1:
            d.hash32()


def decode_state_at(b: bytes, start: int):
    """Decode the β state leg beginning at byte offset `start` →
    (RecentHistory, end_offset). Delegates to the repo codec."""
    d = Decoder(b)
    d.o = start
    _walk_recent_history(d)          # span only
    end = d.o
    return decode_recent_history(b[start:end]), end


def encode_state(beta: RecentHistory) -> bytes:
    """Flat wire (inverse of decode_state_at) — the repo codec verbatim."""
    return encode_recent_history(beta)


# ---------------------------------------------------------------------------
# Expected-update semantics (value-level only, no hashing — feeds annotations)
# ---------------------------------------------------------------------------

def _expected_semantics(pre: RecentHistory, post: RecentHistory,
                        header_hash, parent_state_root, accumulate_root,
                        work_packages) -> dict:
    sem = {}
    if pre.history:
        tail = pre.history[0]
        sem["tail_corrected_prepend"] = bool(
            post.history
            and post.history[0].header_hash == tail.header_hash
            and post.history[0].beefy_root == tail.beefy_root
            and post.history[0].reported == tail.reported
            and post.history[0].state_root == parent_state_root)
    got = [p for p in post.mmr_peaks if p is not None]
    sem["belt_top_raw_passthrough"] = len(got) == 1 and got[0] == accumulate_root
    head = post.history[-1] if post.history else None
    sem["head_appended"] = bool(head and head.header_hash == header_hash)
    sem["head_state_root_zeros"] = bool(head and head.state_root == ZERO_HASH)
    sem["head_reported_matches"] = bool(
        head and [(p.hash, p.exports_root) for p in head.reported]
        == list(work_packages))
    return sem


def _jsonify(o):
    if isinstance(o, (bytes, bytearray)):
        return "0x" + bytes(o).hex()
    if isinstance(o, (list, tuple)):
        return [_jsonify(v) for v in o]
    if isinstance(o, dict):
        return {k: _jsonify(v) for k, v in o.items()}
    if dataclasses.is_dataclass(o) and not isinstance(o, type):
        return {f.name: _jsonify(getattr(o, f.name))
                for f in dataclasses.fields(o)}
    return o


def _dump_debug(**kw):
    name = os.path.basename(str(kw.get("vector", "debug")))
    if name in ("devnull", "null") or not name:
        return None
    path = os.path.join(REPO, "jam_impl", "tests", "stf_debug", name + ".json")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(_jsonify(kw), f, indent=1)
    except OSError:
        return None     # debug dumps must never kill a run
    return path


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def run_vector(path_no_ext, verbose=True):
    spec = "tiny" if "/tiny/" in path_no_ext else "full"
    with spec_globals(spec):
        b = open(path_no_ext + ".bin", "rb").read()
        j = json.load(open(path_no_ext + ".json"))

        d = Decoder(b)
        header_hash, parent_state_root, accumulate_root, work_packages = \
            decode_history_input(d)
        input_end = d.o
        assert encode_history_input(header_hash, parent_state_root,
                                    accumulate_root, work_packages) \
            == b[:input_end], "input round-trip diverged"

        pre, pre_end = decode_state_at(b, input_end)
        assert encode_state(pre) == b[input_end:pre_end], \
            "pre-state round-trip diverged"
        # output leg: NULL — the post state begins immediately at pre_end
        post, post_end = decode_state_at(b, pre_end)
        assert encode_state(post) == b[pre_end:], \
            "post-state round-trip diverged"
        if post_end != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {post_end} != {len(b)}"}
        want = b[pre_end:]

        # ---- the test: run the stub on PRE + input (flat components)
        import importlib.util
        if importlib.util.find_spec("jam_impl.history") is not None:
            import jam_impl.history as history_mod
            stub = getattr(history_mod, "history_stf", None)
        else:
            stub = None
        if stub is None:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(post)}
        stub_beta = copy.deepcopy(pre)
        try:
            stub_out = stub(
                stub_beta,
                header_hash,
                parent_state_root,
                accumulate_root,
                [ReportedWorkPackage(hash=h, exports_root=s)
                 for h, s in work_packages],
                spec=spec)
        except NotImplementedError:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(post)}
        except BaseException as ex:
            import traceback
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": traceback.format_exc(),
                    "expected_output": j["output"],
                    "debug_json": _dump_debug(
                        vector=path_no_ext,
                        input={"header_hash": header_hash,
                               "parent_state_root": parent_state_root,
                               "accumulate_root": accumulate_root,
                               "work_packages": work_packages},
                        expected_output=j["output"],
                        expected_post=_jsonify(post),
                        failure={"kind": "stub-exception",
                                 "exception": f"{type(ex).__name__}: {ex}",
                                 "traceback": traceback.format_exc()})}

        # ---- verdict: Output is NULL — this leg never errs
        report_added = {}
        match = stub_out in (None, (), ("ok",), ("ok", None))
        if not match:
            report_added = {"verdict_mismatch": {
                "stub": _jsonify(stub_out),
                "expected": None}}

        # ---- post-state byte-equal: the stub mutates β in place
        if match:
            encoded = encode_state(stub_beta)
            if encoded != want:
                exp_head = post.history[-1] if post.history else None
                stub_hist = stub_beta.history
                # surgical gate: is the ONLY divergence the new head's
                # beefy_root (the one open construction field)?
                head_beefy_only = bool(
                    exp_head and stub_hist and len(stub_hist) == len(post.history)
                    and stub_beta.mmr_peaks == post.mmr_peaks
                    and all(
                        s.header_hash == p.header_hash
                        and s.state_root == p.state_root
                        and [(q.hash, q.exports_root) for q in s.reported]
                            == [(q.hash, q.exports_root) for q in p.reported]
                        for s, p in zip(stub_hist, post.history))
                    and all(s.beefy_root == p.beefy_root
                            for s, p in zip(stub_hist[:-1], post.history[:-1]))
                    and stub_hist[-1].beefy_root != exp_head.beefy_root)
                if head_beefy_only and not STRICT_HEAD_BEEFY:
                    report_added["beefy_root_gate"] = {
                        "stub": _jsonify(stub_hist[-1].beefy_root),
                        "expected": _jsonify(exp_head.beefy_root),
                        "note": "v4 construction open; gate pass-through"}
                else:
                    match = False
                    i = next((k for k in range(min(len(encoded), len(want)))
                              if encoded[k] != want[k]), None)
                    i = len(want) if i is None and len(encoded) != len(want) else i
                    if head_beefy_only:
                        report_added["beefy_root_gate"] = {
                            "stub": _jsonify(stub_hist[-1].beefy_root),
                            "expected": _jsonify(exp_head.beefy_root),
                            "first_diff_octet": i,
                            "note": "only the head beefy_root diverges "
                                    "(construction open — see docstring)"}
                    else:
                        report_added["post_state_mismatch"] = {
                            "stub": _jsonify(stub_beta),
                            "expected_post": _jsonify(post),
                            "first_diff_octet": i,
                            "encoded_hex_head": encoded[:16].hex(),
                            "want_hex_head": want[:16].hex()}

        sem = _expected_semantics(pre, post, header_hash, parent_state_root,
                                  accumulate_root, work_packages)
        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "semantics_in_vector": sem,
            "expected_output": j["output"],
            "diff_notes": [],
            **report_added,
        }
        report["debug_json"] = _dump_debug(
            vector=path_no_ext,
            input={"header_hash": header_hash,
                   "parent_state_root": parent_state_root,
                   "accumulate_root": accumulate_root,
                   "work_packages": work_packages},
            expected_output=j["output"],
            expected_post=_jsonify(post),
            stub_post=_jsonify(stub_beta),
            match=match, **report_added)
        return report


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO,
                        "jamtestvectors/stf/history/*/*.json")))]
    passed = failed = skipped = gated = 0
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
            extra = " [beefy-gated]" if "beefy_root_gate" in rep else ""
            if extra:
                gated += 1
            print(f"  PASS {rep['name']}{extra}")
        elif verdict == "STUB-UNIMPLEMENTED":
            skipped += 1
            print(f"  STUB {rep['name']} (history_stf not implemented yet;"
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
            for key in ("verdict_mismatch", "post_state_mismatch",
                        "beefy_root_gate"):
                if key in rep:
                    extra += (f" {key}: "
                              f"{json.dumps(rep[key], default=str)[:200]}")
            print(f"  FAIL {rep['name']}{extra} debug={rep['debug_json']}")
    gate = f" (gated {gated})" if gated else ""
    print(f"\ntotal={passed + failed + skipped} pass={passed}{gate}"
          f" fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))