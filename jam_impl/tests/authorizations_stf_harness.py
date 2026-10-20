"""Authorizations STF (authorization.tex, eq:authstate pool/queue advancement)
harness — jamtestvectors/stf/authorizations/{tiny,full} (12 vectors: 3 tiny +
3 full, mirrored copies).

Wire (SCALE, verified byte-exact on all 12; schema stf/authorizations/
authorizations.asn):

  stf/authorizations/<spec>/<name>.bin =
      INPUT ‖ PRE_STATE(pools‖queues) ‖ OUTPUT ‖ POST_STATE(pools‖queues)
    input   = slot(E4 LE) ‖ ↕auths (compact n; n × (u16-LE core index
              + 32-octet authorizer hash))    — CoreAuthorizer, ONE PER
              GUARANTEE E_G[i] (the vectors ship only w.core + w.auth-hash,
              deliberately not the whole extrinsic)
    state   = α (auth pools: core_count × (compact len + len×32), counted per
              core, NO outer prefix — AuthPools is a FixedLengthArray)
              ‖ ϕ (auth queues: FIXED core_count × 80 × 32, no counts at all)
              — the two repo codecs decode_authorization_pool /
              decode_authorization_queue consume exactly these layouts
    output  = NULL — nothing (no tag, no bytes): this leg never errs
    post    = pools ‖ queues again (same encodings)

GP equation map (0.8.0 text/authorization.tex; every rule verified against
all 12 vectors — value-level agree check runs on every harness invocation):

  eq:authstate — pool'_c ≡ ←[ F(c) ++ cyclic(queue'_c)[τ'] ]^8
  F(c)         — pool_c minus the authorizer hash behind every guarantee
                 authored on core c this block (eq:guaranteesextrinsic link:
                 γ_w = E_G[i].w). Wire-verified reading: remove ALL
                 occurrences of the used hash, order preserved (no vector
                 has a duplicated used hash, so occurrence-count is
                 unverifiable; set-minus reading is the GP-conformant one).
  empirical wire rules pinned by the vectors (the equation's abstract
  ⟨…⟩/←^N notation underdetermines two things the vectors settle):
    1. DRAW INDEX: cyclic(queue'_c)[τ'] = queue'_c[τ' mod Cauthqueuesize(80)]
       — cyclic over the queue's OWN length, NOT the epoch length
       (v3-full: slot 645 draws queue[5], not queue[645 mod 600 = 45]).
    2. TRUNCATION: ←A^8 keeps the LAST 8 (drop from the FRONT): every vector's
       post == (F(c) ++ [draw])[-8:]. The wire pool is OLDEST-FIRST and the
       freshly drawn authorizer lands at the TAIL; when |F(c)| == 8 the
       oldest authorizer slides off (v1: 3eec… leaves, f9e9… enters).
    3. QUEUE READ-ONLY: queue' == queue on every vector — ϕ is mutated only
       through privileged-services Accumulate calls (assign), never here.
  NOTE: the GP says α'_c depends on ϕ'_c, pushing this step after
  accumulation; the vectors serialize the pre-accumulation ϕ (unchanged) and
  the harness feeds it through verbatim — the stub consumes the queue as
  given and mutates nothing in it.

Verification performed by this harness per vector:
  1. decode input + both state legs (span-exact via the repo codecs),
  2. round-trip EVERY leg byte-exactly against the wire before trusting it,
  3. value-check the vector's own post against the documented update rule
     (`vector_rule_agrees` in the report — informational, harness
     self-consistency, not a stub gate),
  4. run the stub on a deep-copied PRE state + the input leg (flat args,
     mutate in place),
  5. re-encode the stub's mutated components and byte-compare against the
     post wire.

Contract with the stub (jam_impl/authorizations.py) — FLAT SEMANTIC
ARGUMENTS, no state bag, mutating the repo's state models in place (house
style of reports_stf / preimages_stf / history_stf):

    authorizations_stf(
        authorization_pools,       # AuthorizationPool α (mutated)
        authorization_queues,      # AuthorizationQueue ϕ (READ-ONLY here)
        guarantees_core_authors,   # list[CoreAuthorizer] — (core, auth_hash)
                                   #   per guarantee in E_G order
        current_slot,              # τ' — draw index basis for the refill
        spec,
    ) → None                       # ("ok" is implicit; the output leg is NULL)

  CoreAuthorizer is defined in the stub module (wire item model, mirrors
  PreimagesAccount living in preimages.py).

Missing infrastructure — nothing: the pool/queue codecs and state models all
exist; the stub is the only unimplemented piece.

Usage:
    uv run jam_impl/tests/authorizations_stf_harness.py jamtestvectors/stf/authorizations/tiny/progress_authorizations-1
    uv run jam_impl/tests/authorizations_stf_harness.py         # all 12 vectors
"""
import copy
import glob
import json
import os
import sys
from dataclasses import fields, is_dataclass

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

import jam_impl.util as util
from jam_impl.util import Decoder, Encoder
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.state_codec import (
    decode_authorization_pool, encode_authorization_pool,
    decode_authorization_queue, encode_authorization_queue,    
)
from jam_impl.models.State import AuthorizationPool, AuthorizationQueue

POOL_CAP = 8                      # Cauthpoolsize — wire-verified on both specs
QUEUE_LEN = util.AUTHORIZATION_QUEUE_LENGTH   # Cauthqueuesize (80)


# ---------------------------------------------------------------------------
# Wire walkers
# ---------------------------------------------------------------------------

def decode_input(d: Decoder):
    """Input leg → (slot, [(core, auth_hash)]). Core is u16-LE on this wire
    (verified: count byte compact; items start 2 little-endian core bytes
    followed by the 32-octet authorizer hash)."""
    slot = d.u32()
    auths = []
    for _ in range(d.decode_compact()):
        core = int.from_bytes(d.take(2), "little")
        auths.append((core, d.hash32()))
    return slot, auths


def encode_input(slot, auths) -> bytes:
    """Round-trip of decode_input (self-check + byte framing)."""
    e = Encoder()
    e.u32(slot)
    e.compact(len(auths))
    for core, h in auths:
        e.raw(int(core).to_bytes(2, "little"))
        e.hash32(h)
    return e.finish()


def _walk_pools(d: Decoder, core_count: int):
    """Span-walk the pools leg: per-core compact count + count hashes.
    No outer prefix (AuthPools is a FixedLengthArray).
    NOTE: the count is read into a local BEFORE `d.o += …`: a same-expression
    `d.o += d.decode_compact() * 32` reads the STALE d.o (attribute-target
    augmented assignment loads the target before the RHS call mutates it)."""
    start = d.o
    for _ in range(core_count):
        k = d.decode_compact()
        d.o += k * 32
    return start, d.o


def _walk_queues(d: Decoder, core_count: int):
    """Span-walk the queues leg: strictly core_count × 80 × 32, no counts."""
    start = d.o
    d.o += core_count * QUEUE_LEN * 32
    return start, d.o


def decode_state_at(b: bytes, start: int, core_count: int):
    """Decode one state leg (pools ‖ queues) at byte offset `start` →
    ((AuthorizationPool, AuthorizationQueue), end_offset). Spans are sliced
    first so the repo codecs' finish() asserts land exactly."""
    d = Decoder(b)
    d.o = start
    p0, p1 = _walk_pools(d, core_count)
    q0, q1 = _walk_queues(d, core_count)
    pools = decode_authorization_pool(b[p0:p1])
    queues = decode_authorization_queue(b[q0:q1])
    return (pools, queues), d.o


def encode_state(pools: AuthorizationPool, queues: AuthorizationQueue) -> bytes:
    """Flat wire (inverse of decode_state_at) — repo codecs verbatim."""
    return (encode_authorization_pool(pools)
            + encode_authorization_queue(queues))


# ---------------------------------------------------------------------------
# Documented update rule (informational self-check against each vector)
# ---------------------------------------------------------------------------

def _rule_expected(pools_pre: list[list], queues_post: list[list],
                   auths: list[tuple], slot: int, core_count: int) -> list[list]:
    """pool'_c = (F(c) ++ [queue'_c[τ' mod 80]])[-8:] — exactly the rule the
    harness docstring documents; used only to confirm the vectors agree
    (vector_rule_agrees), never to judge the stub."""
    used = {}
    for core, h in auths:
        used.setdefault(core, set()).add(h)
    out = []
    for c in range(core_count):
        base = [h for h in pools_pre[c] if h not in used.get(c, set())]
        draw = queues_post[c][slot % QUEUE_LEN]
        out.append((base + [draw])[-POOL_CAP:])
    return out


def _jsonify(o):
    if isinstance(o, (bytes, bytearray)):
        return "0x" + bytes(o).hex()
    if isinstance(o, (list, tuple)):
        return [_jsonify(v) for v in o]
    if isinstance(o, dict):
        return {k: _jsonify(v) for k, v in o.items()}
    if is_dataclass(o) and not isinstance(o, type):
        return {f.name: _jsonify(getattr(o, f.name)) for f in fields(o)}
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
        n_cores = util.core_count()

        d = Decoder(b)
        slot, auths = decode_input(d)
        input_end = d.o
        assert encode_input(slot, auths) == b[:input_end], \
            "input round-trip diverged"
        # json cross-check on the input leg
        assert slot == j["input"]["slot"]
        assert [(c, h.hex()) for c, h in auths] == [
            (a["core"], bytes.fromhex(a["auth_hash"][2:]).hex())
            for a in j["input"]["auths"]]

        pre, pre_end = decode_state_at(b, input_end, n_cores)
        assert encode_state(*pre) == b[input_end:pre_end], \
            "pre-state round-trip diverged"
        # output leg: NULL — the post state begins immediately at pre_end
        post, post_end = decode_state_at(b, pre_end, n_cores)
        assert encode_state(*post) == b[pre_end:post_end], \
            "post-state round-trip diverged"
        if post_end != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {post_end} != {len(b)}"}
        want = b[pre_end:]

        # informational: the vectors must agree with the documented rule
        rule_pools = _rule_expected([list(x) for x in pre[0].pools],
                                    [list(x) for x in post[1].queues],
                                    auths, slot, n_cores)
        vector_rule_agrees = rule_pools == post[0].pools
        rule_note = None if vector_rule_agrees else next(
            (f"core {c}" for c in range(n_cores)
             if rule_pools[c] != post[0].pools[c]), "?")

        # sanity: this leg never changes the queue (documented + verified)
        assert pre[1].queues == post[1].queues, "vector changed the queue?!"

        # ---- the test: run the stub on PRE + input (flat components)
        import importlib.util
        if importlib.util.find_spec("jam_impl.authorizations") is not None:
            import jam_impl.authorizations as authz_mod
            stub = getattr(authz_mod, "authorizations_stf", None)
        else:
            stub = None
        if stub is None:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(post),
                    "vector_rule_agrees": vector_rule_agrees}
        stub_pools = copy.deepcopy(pre[0])
        try:
            from jam_impl.authorizations import CoreAuthorizer
            stub_out = stub(
                stub_pools,
                copy.deepcopy(pre[1]),
                [CoreAuthorizer(core=c, auth_hash=h) for c, h in auths],
                slot,
                spec=spec)
        except NotImplementedError:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(post),
                    "vector_rule_agrees": vector_rule_agrees}
        except BaseException as ex:
            import traceback
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "CRASH",
                    "why": f"{type(ex).__name__}: {ex}",
                    "traceback": traceback.format_exc(),
                    "expected_output": j["output"],
                    "vector_rule_agrees": vector_rule_agrees,
                    "debug_json": _dump_debug(
                        vector=path_no_ext,
                        input={"slot": slot, "auths": auths},
                        expected_output=j["output"],
                        expected_post=_jsonify(post),
                        vector_rule_agrees=vector_rule_agrees,
                        failure={"kind": "stub-exception",
                                 "exception": f"{type(ex).__name__}: {ex}",
                                 "traceback": traceback.format_exc()})}

        # ---- verdict: Output is NULL — this leg never errs
        report_added = {}
        match = stub_out in (None, (), ("ok",), ("ok", None))
        if not match:
            report_added = {"verdict_mismatch": {
                "stub": _jsonify(stub_out), "expected": None}}

        # ---- post-state byte-equal: the stub mutates the pre components
        if match:
            encoded = encode_state(stub_pools, stub_args_queues
                                   if False else _queues_of(stub_pools, pre))
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want)))
                          if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                report_added["post_state_mismatch"] = {
                    "stub": _jsonify(stub_pools),
                    "expected_post": _jsonify(post),
                    "first_diff_octet": i,
                    "rule_disagreement": (f"vector itself disagrees with the "
                                          f"documented rule at {rule_note}"
                                          if not vector_rule_agrees else None)}

        report = {
            "name": os.path.basename(path_no_ext),
            "verdict": "PASS" if match else "FAIL",
            "vector_rule_agrees": vector_rule_agrees,
            "expected_output": j["output"],
            "diff_notes": [],
            **report_added,
        }
        report["debug_json"] = _dump_debug(
            vector=path_no_ext,
            input={"slot": slot, "auths": auths},
            expected_output=j["output"],
            expected_post=_jsonify(post),
            stub_post=_jsonify(stub_pools),
            vector_rule_agrees=vector_rule_agrees,
            match=match, **report_added)
        return report


# the stub contract mutates ONLY the pools model; the queues model handed in
# is passed straight back to the encoder (queue read-only on this leg).
def _queues_of(_pools, pre):
    return pre[1]


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO,
                        "jamtestvectors/stf/authorizations/*/*.json")))]
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
            print(f"  STUB {rep['name']} (authorizations_stf not implemented"
                  f" yet; expected available in rep['expected_post'])")
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
            for key in ("verdict_mismatch", "post_state_mismatch"):
                if key in rep:
                    extra += (f" {key}: "
                              f"{json.dumps(rep[key], default=str)[:200]}")
            rule = "" if rep.get("vector_rule_agrees", True) else \
                " (vector disagrees with the documented rule — see debug)"
            print(f"  FAIL {rep['name']}{extra}{rule} debug={rep['debug_json']}")
    print(f"\ntotal={passed + failed + skipped} pass={passed} "
          f"fail={failed} stub={skipped}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))