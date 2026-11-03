"""Statistics STF (statistics.tex, §"Validator Activity") harness —
jamtestvectors/stf/statistics/{tiny,full} (6 vectors: 3 tiny + 3 full).

This group is the VALIDATOR statistics leg only: the π_V accumulator and the
π_L previous-epoch table.  π_C (core) and π_S (service) statistics are
maintained by the preimages / reports / accumulate vectors, NOT here
(stf/statistics/README.md).

Wire (SCALE, verified byte-exact on all 6 vectors; schema
stf/statistics/statistics.asn):

  stf/statistics/<spec>/<name>.bin =
      INPUT ‖ PRE_STATE ‖ OUTPUT ‖ POST_STATE
    input   = slot(E4 LE) ‖ author-index(E2 LE) ‖ extrinsic
              (E = tickets ‖ preimages ‖ guarantees ‖ assurances ‖ disputes,
               wire order C.16; the repo's extrinsic_codec decodes exactly
               these)
    state   = π_V (validators-count × 6×u32)   — accumulator, this epoch
              ‖ π_L (validators-count × 6×u32) — previous epoch
              ‖ τ (prior timeslot, E4 LE)
              ‖ κ' (validators-count × ValidatorData: 32+32+144+128 octets)
    output  = NULL — nothing (no tag, no bytes): this leg never errs
    post    = the same four components again

GP equation map (0.7.2 text/statistics.tex — the version the 0.7.1-format
vectors were generated from; every rule verified byte-exact against all 6
vectors, and the value-level agreement check runs on every harness
invocation):

  epoch switch (0.7.2 "using e = time/Cepochlen, e' = time'/Cepochlen"):
      (a, previous') ≡ (accumulator, previous)          if e' = e
                       (zeros, accumulator)             otherwise
  per validator v:
      accumulator'[v].blocks        = a[v].blocks + (v = author-index)
      accumulator'[v].tickets       = a[v].tickets + |E_T|        (if author)
      accumulator'[v].preimagecount = a[v].preimagecount + |E_P| (if author)
      accumulator'[v].preimagesize  = a[v].preimagesize + Σ len(blob) (if author)
      accumulator'[v].guarantees    = a[v].guarantees + (κ'[v] ∈ reporters)
      accumulator'[v].assurances    = a[v].assurances
                                     + (∃ a ∈ E_A : a.assurer = v)
  reporters = the set of Ed25519 keys of the guarantee credential signers
              (eq:guarantorsig, reporting_assurance.tex line 299:
              k = (κ'[v]).ed25519).

  ⚠ WHERE THE REPORTERS SET COMES FROM — the reason this step needs an
  input it cannot compute itself:

      In the TOTAL state transition the reporters set is the REPORTS step's
      OUTPUT (the reports wire output leg carries the sorted reporter keys),
      and the total STF threads it into this step.  The reports step owns the
      rotation-aware key resolution (eq:guarantorsig): a guarantee whose
      timeslot is in THIS block's rotation is signed with a κ' key, one from
      the previous rotation with a λ' key — so the key cannot be derived
      from the guarantee's signer INDEX alone, and the statistics step does
      not have λ' (nor the entropy) to redo it.

      The standalone stf/statistics vectors are a special case: their state
      leg ships κ' and NO rotation context, and their guarantee credentials
      are all-zero placeholders with timeslot 0.  The harness therefore
      resolves the reporters set the VECTOR-STANDALONE way (every signer's
      key read from the single shipped validator set) — the harness's job,
      not the stub's.  That resolution is exactly what the vectors expect:
      it credits the signer indices 0..3, whereas resolving the same indices
      through the previous-rotation set (λ') would credit 0,2,4,5 / 1,45,842,997
      — which contradicts the vectors' post-state on both specs.

      So the stub receives the reporters set as a plain argument (a collection
      of Ed25519 keys) and only does the membership test against κ'.

  Wire-pinned details the GP text leaves implicit:
    1. PREIMAGE SIZE counts the BLOB octets only (the ↕ length prefix is not
       counted): tiny vector — 3 blobs of 16/17/18 octets ⇒ +51.
    2. GUARANTEES is counted per VALIDATOR, not per guarantee: a validator
       that signed two guarantees in one block is credited once (the vectors'
       reporters set is a SET of keys, and the increment is a membership
       indicator (κ'[v] ∈ reporters), not a count).
    3. The STATISTICS leg does NOT verify signatures: the vectors ship
       all-zero placeholder signatures, so any verification here would fail
       every vector.  Assurance/guarantee VALIDITY is the assurances/reports
       leg's job; this leg only counts what is in the extrinsic.
    4. τ (the state's prior timeslot) and κ' are READ-ONLY here: the
       statistics leg does not advance the timeslot nor change the
       validator set (both are unchanged on every vector).
    5. ALIASING PITFALL: on an epoch switch the OLD accumulator becomes the
       previous table, so the stub must SNAPSHOT it (prev = list(curr)) — if
       it merely aliases (prev = curr) and later writes `curr[:] = acc`, the
       write lands on the very list `prev` names and the previous table is
       destroyed.  The harness catches this (the epoch-change vectors fail).

  ⚠ GP VERSION DISCREPANCY (read before implementing against the local
  0.8.0 checkout): 0.8.0 text/statistics.tex splits the update into
  accumulator^dagger (the ASSURANCE bump) → the epoch switch →
  accumulator^ddagger (the remaining bumps).  0.8.0 therefore applies the
  assurance increment to the OLD accumulator, so on an epoch-switch block
  the assurance count lands in previous' and the fresh accumulator does NOT
  receive it.  The 0.7.2 text (and these vectors) do the epoch switch FIRST
  and then apply every increment to the fresh accumulator, so on an epoch
  switch previous' == the untouched old accumulator and the assurance
  increment lands in the NEW accumulator.
  The vectors settle it: in stats_with_epoch_change-1 the previous-epoch
  table is bit-identical to the old accumulator (assurances NOT bumped) and
  the fresh accumulator carries the +1 assurance.  Implement the 0.7.2
  ordering (epoch switch first) to pass these vectors.

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

Contract with the stub (jam_impl/statistics.py) — FLAT SEMANTIC ARGUMENTS,
no state bag, mutating the repo's state models in place (house style of
reports_stf / preimages_stf / history_stf / authorizations_stf):

    statistics_stf(
        validators_curr_stats,   # list[ValidatorStatistics] — π_V (mutated)
        validators_last_stats,   # list[ValidatorStatistics] — π_L (mutated)
        current_validators,      # list[ValidatorData]       — κ' (read-only)
        reporters,               # collection[bytes]        — the reporters KEY
                                   #   SET (eq:guarantorsig) — the REPORTS
                                   #   step's output in the total STF; the
                                   #   harness supplies it here
        tickets,                 # list[Ticket]              — E_T (read-only)
        preimages,               # list[Preimage]            — E_P (read-only)
        assurances,              # list[Assurance]           — E_A (read-only)
        block_slot,              # H_t — this block's timeslot
        author_index,            # H_i — the block author
        prior_slot,              # τ  — the state's prior timeslot
        spec,
    ) → None                    # ("ok" is implicit; the output leg is NULL)

  The state models are reused from jam_impl/models/State.py
  (ValidatorStatistics, ValidatorData) and jam_impl/models/Extrinsic.py
  (Ticket, Preimage, Guarantee, Assurance) — no local copies.

Missing infrastructure — nothing: the validator-statistics and validator-set
codecs exist (decode_validators_statistics / decode_validator_list); the
stub is the only unimplemented piece.

Usage:
    uv run jam_impl/tests/statistics_stf_harness.py jamtestvectors/stf/statistics/tiny/stats_with_epoch_change-1
    uv run jam_impl/tests/statistics_stf_harness.py         # all 6 vectors
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
    decode_validators_statistics, encode_validators_statistics,
    decode_validator_list, encode_validator_list,
)
from jam_impl.codec import extrinsic_codec as xc
from jam_impl.guarantors import reporters_from_validator_indices
from jam_impl.models.State import ValidatorStatistics, ValidatorData


# ---------------------------------------------------------------------------
# Wire walkers
# ---------------------------------------------------------------------------

def decode_input(d: Decoder):
    """Input leg → (block_slot, author_index, extrinsic parts).

    slot(E4) ‖ author-index(E2) ‖ E, where E is the extrinsic tuple in the
    C.16 wire order (tickets, preimages, guarantees, assurances, disputes) —
    decoded component-wise with the repo's extrinsic_codec so the state legs
    that follow in the same buffer stay untouched."""
    block_slot = d.u32()
    author_index = d.u16()
    tickets = xc.decode_tickets(d)
    preimages = xc.decode_preimages(d)
    guarantees = xc.decode_guarantees(d)
    assurances = xc.decode_assurances(d)
    disputes = xc.decode_disputes(d)
    return block_slot, author_index, tickets, preimages, guarantees, assurances, disputes


def encode_input(block_slot, author_index, tickets, preimages, guarantees,
                 assurances, disputes) -> bytes:
    """Round-trip of decode_input (self-check + byte framing)."""
    e = Encoder()
    e.u32(block_slot)
    e.u16(author_index)
    e.raw(xc.encode_tickets(tickets))
    e.raw(xc.encode_preimages(preimages))
    e.raw(xc.encode_guarantees(guarantees))
    e.raw(xc.encode_assurances(assurances))
    e.raw(xc.encode_disputes(disputes))
    return e.finish()


def decode_state_at(b: bytes, start: int):
    """Decode one state leg (π_V ‖ π_L ‖ τ ‖ κ') at byte offset `start` →
    ((curr_stats, last_stats, prior_slot, validators), end_offset)."""
    d = Decoder(b)
    d.o = start
    curr_stats = decode_validators_statistics(d)
    last_stats = decode_validators_statistics(d)
    prior_slot = d.u32()
    validators = decode_validator_list(d)
    return (curr_stats, last_stats, prior_slot, validators), d.o


def encode_state(curr_stats, last_stats, prior_slot, validators) -> bytes:
    """Flat wire (inverse of decode_state_at) — repo codecs verbatim."""
    e1 = Encoder()
    encode_validators_statistics(e1, curr_stats)
    e2 = Encoder()
    encode_validators_statistics(e2, last_stats)
    e3 = Encoder()
    e3.u32(prior_slot)
    encode_validator_list(e3, validators)
    return e1.finish() + e2.finish() + e3.finish()


# ---------------------------------------------------------------------------
# Documented update rule (informational self-check against each vector)
# ---------------------------------------------------------------------------

def _rule_expected(curr_stats, last_stats, prior_slot, validators,
                   block_slot, author_index, tickets, preimages, guarantees,
                   assurances, reporters, spec):
    """The rule documented in this module's docstring, applied to a vector's
    own pre-state.  Used only to confirm the vectors agree
    (`vector_rule_agrees`), never to judge the stub."""
    with spec_globals(spec):
        epoch_len = util.LENGTH_OF_EPOCH_IN_TIMESLOTS
        if prior_slot // epoch_len == block_slot // epoch_len:
            acc = [ValidatorStatistics(**s.__dict__) for s in curr_stats]
            prev = list(last_stats)
        else:
            acc = [ValidatorStatistics(0, 0, 0, 0, 0, 0) for _ in curr_stats]
            prev = list(curr_stats)
        # assurance bump (∃ a ∈ E_A : a.assurer = v)
        for assurance in assurances:
            if 0 <= assurance.validator_index < len(acc):
                acc[assurance.validator_index].assurances += 1
        # author bumps
        if 0 <= author_index < len(acc):
            acc[author_index].blocks += 1
            acc[author_index].tickets += len(tickets)
            acc[author_index].pre_images += len(preimages)
            acc[author_index].pre_images_size += sum(len(p.blob) for p in preimages)
        # guarantee bump: (κ'[v] ∈ reporters) — a membership test on the
        # REPORTERS KEY SET (the reports step's output), not on the signer
        # indices: a validator who signed two guarantees is credited ONCE.
        for index, validator in enumerate(validators):
            if index < len(acc) and validator.ed25519 in reporters:
                acc[index].guarantees += 1
        return acc, prev


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

        d = Decoder(b)
        (block_slot, author_index, tickets, preimages, guarantees,
         assurances, disputes) = decode_input(d)
        input_end = d.o
        assert encode_input(block_slot, author_index, tickets, preimages,
                            guarantees, assurances, disputes) == b[:input_end], \
            "input round-trip diverged"
        # json cross-check on the input leg
        assert block_slot == j["input"]["slot"], "input slot mismatch"
        assert author_index == j["input"]["author_index"], "author mismatch"

        pre, pre_end = decode_state_at(b, input_end)
        assert encode_state(*pre) == b[input_end:pre_end], \
            "pre-state round-trip diverged"
        # output leg: NULL — the post state begins immediately at pre_end
        post, post_end = decode_state_at(b, pre_end)
        assert encode_state(*post) == b[pre_end:post_end], \
            "post-state round-trip diverged"
        if post_end != len(b):
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "HARNESS-FAIL",
                    "why": f"post walk ended at {post_end} != {len(b)}"}
        want = b[pre_end:]

        # json cross-check on the state legs
        js_pre = j["pre_state"]
        assert pre[2] == js_pre["slot"], "pre-state slot mismatch"
        assert len(pre[3]) == len(js_pre["curr_validators"]), \
            "validator count mismatch"

        # The REPORTERS set (eq:guarantorsig): in the total STF this is the
        # REPORTS step's output, threaded in by the transition.  These
        # standalone vectors ship one validator set and no rotation context,
        # so the harness resolves the signers' keys against it (see the
        # docstring note on the reporters set's provenance).
        reporters = reporters_from_validator_indices(guarantees, pre[3])

        # informational: the vectors must agree with the documented rule
        rule_curr, rule_last = _rule_expected(
            pre[0], pre[1], pre[2], pre[3], block_slot, author_index,
            tickets, preimages, guarantees, assurances, reporters, spec)
        vector_rule_agrees = (rule_curr == post[0] and rule_last == post[1])
        rule_note = None
        if not vector_rule_agrees:
            rule_note = next(
                (f"accumulator[{i}]" for i in range(len(rule_curr))
                 if rule_curr[i] != post[0][i]),
                next((f"previous[{i}]" for i in range(len(rule_last))
                      if rule_last[i] != post[1][i]), "?"))

        # sanity: this leg does not advance the timeslot nor the validator set
        assert pre[2] == post[2], "vector changed the prior timeslot?!"
        assert pre[3] == post[3], "vector changed the validator set?!"

        # ---- the test: run the stub on PRE + input (flat components)
        import importlib.util
        if importlib.util.find_spec("jam_impl.statistics") is not None:
            import jam_impl.statistics as stats_mod
            stub = getattr(stats_mod, "statistics_stf", None)
        else:
            stub = None
        if stub is None:
            return {"name": os.path.basename(path_no_ext),
                    "verdict": "STUB-UNIMPLEMENTED",
                    "expected_output": j["output"],
                    "expected_post": _jsonify(post),
                    "vector_rule_agrees": vector_rule_agrees}
        stub_curr = copy.deepcopy(pre[0])
        stub_last = copy.deepcopy(pre[1])
        try:
            stub_out = stub(
                stub_curr,
                stub_last,
                copy.deepcopy(pre[3]),
                list(reporters),
                copy.deepcopy(tickets),
                copy.deepcopy(preimages),
                copy.deepcopy(assurances),
                block_slot,
                author_index,
                pre[2],
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
                        spec=spec,
                        input={"block_slot": block_slot,
                               "author_index": author_index},
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

        # ---- post-state byte-equal: the stub mutates the two statistics tables
        if match:
            encoded = encode_state(stub_curr, stub_last, pre[2], pre[3])
            if encoded != want:
                match = False
                i = next((k for k in range(min(len(encoded), len(want)))
                          if encoded[k] != want[k]), None)
                i = len(want) if i is None and len(encoded) != len(want) else i
                report_added["post_state_mismatch"] = {
                    "stub_curr": _jsonify(stub_curr),
                    "stub_last": _jsonify(stub_last),
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
            spec=spec,
            input={"block_slot": block_slot, "author_index": author_index,
                   "reporters": [r.hex() for r in reporters]},
            expected_output=j["output"],
            expected_post=_jsonify(post),
            stub_post={"vals_curr_stats": _jsonify(stub_curr),
                       "vals_last_stats": _jsonify(stub_last)},
            vector_rule_agrees=vector_rule_agrees,
            match=match, **report_added)
        return report


def main(argv):
    if argv:
        paths = [a[:-5] if a.endswith(".json") else a for a in argv]
    else:
        paths = [t[:-5] for t in
                 sorted(glob.glob(os.path.join(REPO,
                        "jamtestvectors/stf/statistics/*/*.json")))]
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
            print(f"  STUB {rep['name']} (statistics_stf not implemented"
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
