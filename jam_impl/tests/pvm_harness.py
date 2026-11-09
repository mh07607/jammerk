"""PVM harness: pull the PVM components out of accumulate STF vectors and run
ONLY the PVM invocation against them — no accumulate STF plumbing (queues,
entropy, statistics mutation) and no codec decode of the vector state.

Source of truth chain (all byte-verified on tiny/enqueue_and_unlock_chain-1):

  stf/accumulate/<spec>/<name>.json
    pre_state.accounts[].data.preimage_blobs[X].blob  = code blob (hex)
      = j .jam container: compact(meta_len) ‖ metadata ‖ u24LE(ro_len)
        ‖ u24LE(rw_len) ‖ u16LE(rw_pad) ‖ u24LE(stack) ‖ ro ‖ rw
        ‖ u32LE(code_len) ‖ code_blob
      metadata for these vectors = 0x00 (Info tag) ‖ GP-compact-prefixed
      strings name/version/license ‖ GP-compact(author_count) ‖ author…
      (GP-compact = 7-bit single octet, NOT parity-scale)
    a_c code_hash = blake2b-256 of the WHOLE blob (whisked by blake2b only,
      no keccak — verified against service.code_hash for every tiny vector)
    strip the metadata prefix and the remainder is EXACTLY GP 0.7.2's standard
    program blob p for Y(p, a) (pvm.tex:749):  E3(|o|) ‖ E3(|w|) ‖ E2(z)
      ‖ E3(s) ‖ o ‖ w ‖ E4(|inner|) ‖ inner
    inner = GP E.1 program blob: compact(|j|) ‖ E1(z raw) ‖ compact(|c|)
      ‖ j (z-octet LE entries) ‖ c ‖ k (1 bit per code octet, packed LSB-first
      within each octet; ceil(|c|/8) octets — 0.7.2's k IS packed, len(k) in
      octets is ceil(|c|/8), the tex's "length equal to len(c)" counts BITS)
  accumulate invocation init (pvm_invocations.tex:126 "Accumulate Invocation"):
    Ψ_A runs Ψ_M(c, gas=g, args=E(t, s, len(i)), mutator F, context I(...)):
    args a = GP-compact(t) ‖ GP-compact(s) ‖ GP-compact(len(i))
      (t = header timeslot of the vector's input slot, s = service id,
      len(i) = number of accumulating items for that service)
    Standard-init applies with that a: registers r0 = 2^32-2^16,
    r1 = 2^32-2*2^16-2^24 (stack base), r7 = 2^32-2^16-2^24 (args base),
    r8 = len(a), others 0. Memory zones (page P=4096, zone Z=2^16):
      ro  = o   at [2^16,        2^16+|o|)           access R
      rw  = w   at [2*2^16 + rnp(|o|), +|w|)          access W  (rnp = P-page
                  aligned up; .jam u16 field 'rw_pad' = GP z = jump entry
                  octets, NOT pages: chain-1 z=2 matches the observed u16 j)
      stack     at [2^32-2Z-I-rnp(s), 2^32-2Z-I)      access W
      args= a   at [2^32-Z-I,      +|a|)              access R
      zone-gap  between each section is R if within ro/rw/args rnp padding
      inside the declared regions, otherwise inaccessible
  host calls (ecalli = opcode 10, imm = host id, fee 10 — JIP-1; transfer 20
    costs 10 + r9, log is NOT in GP 0.7.2's accumulate dispatch):
    GP 0.7.2 ids: gas 0, fetch 1, lookup 2, read 3, write 4, info 5, bless 14,
    assign 15, designate 16, checkpoint 17, new 18, upgrade 19, transfer 20,
    eject 21, query 22 (+23..: solicit/forget/yield/provide — not read)

Contract with the stub:

  run_accumulate_case(case: AccumCase) -> PvmRun
    Runs Ψ_A's inner machine: execute the program from PC = 0 with the initial
    state from accumulate_initial_state(case) and gas = case.expected_gas
    budget (do NOT trust it as a limit — it is the vector's own expectation;
    the budget passed here is only a sanity guard).
    Return PvmRun(exit, gas_used, host_calls, r7_final) where:
      exit       ∈ {"halt", "panic", "oog"}  (host calls are internal)
      gas_used   = instructions*1 + host fees (10 per call, transfer 10+r9)
      host_calls = list[[id, name]] in call order
    The stub raises NotImplementedError until your core lands; point it at
    your Ψ loop (jam_impl/pvm.py) and this harness gates it against the
    vector statistics.

  Gate this harness applies once the core returns (compare_case):
    1. gas_used    == case.expected_gas   (from statistics a.1 diff)
    2. exit        == "halt" (unless the vector is a no-work case)
    3. host calls  == a name census sanity (same multiset as static decode)

Usage:
    uv run jam_impl/tests/pvm_harness.py jamtestvectors/stf/accumulate/tiny/process_one_immediate_report-1
    uv run jam_impl/tests/pvm_harness.py            # default small set
    uv run python -m unittest jam_impl.tests.pvm_harness -v   # extraction legs
"""
import dataclasses
import glob
import json
import os
import sys
import unittest
import hashlib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, REPO)

import jam_impl.util as util

# NOTE: importing jam_impl.pvm currently triggers an import cycle
# (pvm -> pvm_instruction_mapping -> pvm_instruction_definitions -> pvm).
# Until that is fixed, fall back to duck-typed local shapes with the same
# fields so the extraction legs run; when the import works, this harness
# hands HIS types to HIS core.
try:
    from jam_impl.pvm import Program  # pyright: ignore[reportAssignmentType]
    from jam_impl.pvm import Memory  # pyright: ignore[reportAssignmentType]
    _PVM_IMPORTS = "jam_impl.pvm"
except ImportError:
    from dataclasses import dataclass as _dc

    @_dc
    class Program:  # pyright: ignore[reportAssignmentType]
        instruction_data: bytes
        jump_table: list
        opcode_bitmask: list

    @_dc
    class Memory:  # pyright: ignore[reportAssignmentType]
        values: dict
        access: dict

        def read(self, address: int, length: int) -> list:
            base = address % 2 ** 32
            return [self.values.get((base + i) % 2 ** 32, 0) for i in range(length)]

        def readable(self, start: int, length: int) -> bool:
            return all((start + i) >> 12 in self.access
                       and self.access[(start + i) >> 12] is not None
                       for i in range(length))

        def writable(self, start: int, length: int) -> bool:
            return all(self.access.get((start + i) >> 12) == "W"
                       for i in range(length))

    _PVM_IMPORTS = "local stand-ins (jam_impl.pvm import cycle)"

VECTOR_ROOT = os.path.join(REPO, "jamtestvectors", "stf", "accumulate", "tiny")
DEFAULT_CASES = [
    "process_one_immediate_report-1",   # (4364 gas, 1 accumulation) cleanest case
    "queues_are_shifted-1",             # (4364, 1)
    "same_code_different_services-1",   # (4298, 1)
    "enqueue_and_unlock_chain_wraps-2", # (4333, 1) enqueue flavor
]
P = 4096          # page size            (GP Cpvmpagesize)
Z = 2 ** 16       # zone size            (GP Cpvminitzonesize)
I = 2 ** 24       # init input size      (GP Cpvminitinputsize)
ECALLI_OPCODE = 10
# GP 0.7.2 host-call ids (pvm_invocations.tex General Functions):
HOST_NAMES = {
    0: "gas", 1: "fetch", 2: "lookup", 3: "read", 4: "write", 5: "info",
    6: "unknown-6",  # not defined in GP 0.7.2's accumulate dispatch
    14: "bless", 15: "assign", 16: "designate", 17: "checkpoint", 18: "new",
    19: "upgrade", 20: "transfer", 21: "eject", 22: "query",
    100: "log",  # JIP-1: index 100 (level=r7, target=mu[r8..r8+r9], msg=mu[r10..r11])
}
TRANSFER_ID = 20
LOG_ID = 100
NO_FEE_IDS = {LOG_ID}  # this 0.7.1 bundle's README: log fee = 0 (JIP-1 >=0.7.2
                       # charges 10 — if the gas gate is off by exactly +50 per
                       # 5 log calls, flip this set)


# ---------------------------------------------------------------------------
# GP compact helpers (util.decode_compact is authoritative; local mirror for
# the value bands is NOT needed — reuse util's, it handles the 7-bit band)
# ---------------------------------------------------------------------------

def enc_compact(x: int) -> bytes:
    """GP C.5 compact encode, mirroring util.decode_compact's bands."""
    if x < 128:
        return bytes([x])
    if x < (63 << 8) + 0xFF + 1:  # band (128,192): (b&0x3F)<<8 | b1
        return bytes([0x80 | (x >> 8), x & 0xFF])
    # band (192,224): (b&0x1F)<<16 | LE16 payload  (verified 0xc0 0xd8 0x60)
    return bytes([0xC0 | ((x >> 16) & 0x1F), x & 0xFF, (x >> 8) & 0xFF])


# ---------------------------------------------------------------------------
# Container: raw LE fixed-width readers (NOT compact — GP standard init uses
# E3/E2/E4 fixed widths)
# ---------------------------------------------------------------------------

def uN_at(b: bytes, off: int, n: int) -> int:
    return util.decode_fixed(b[off:off + n], n)


def strip_metadata(blob: bytes):
    """compact(meta_len) ‖ metadata … → (dict-ish meta, p_without_meta).
    Returns (meta_bytes, rest) where rest starts at E3(|o|)."""
    mlen, off = util.decode_compact(blob, 0)
    meta = blob[off:off + mlen]
    return meta, blob[off + mlen:]


def parse_standard_p(p: bytes):
    """GP Y's p layout → (o, w, z, s, inner)."""
    lo, lw, lz, ls = uN_at(p, 0, 3), uN_at(p, 3, 3), uN_at(p, 6, 2), uN_at(p, 8, 3)
    o = p[11:11 + lo]
    w = p[11 + lo:11 + lo + lw]
    off = 11 + lo + lw
    lic = uN_at(p, off, 4)
    inner = p[off + 4:off + 4 + lic]
    assert len(inner) == lic, "standard-p inner size overflow"
    assert off + 4 + lic == len(p), "standard-p trailing bytes"
    return o, w, lz, ls, inner


def parse_gp_blob(inner: bytes):
    """GP E.1 program blob → (j, c, k_packed) with z-entry jump table and the
    packed 1-bit-per-octet k; expanded mask returned alongside."""
    lj, off = util.decode_compact(inner, 0)
    z = inner[off]
    off += 1
    lc, off = util.decode_compact(inner, off)
    j = [util.decode_fixed(inner[off + i * z: off + (i + 1) * z], z)
         for i in range(lj)]
    off += lj * z
    c = inner[off:off + lc]
    off += lc
    lm = (lc + 7) // 8
    k = inner[off:off + lm]
    assert len(k) == lm, f"k expected {lm} octets, got {len(k)}"
    assert off + lm == len(inner), "gp-blob trailing bytes"
    mask = []
    for kb in k:
        mask.extend(bool((kb >> bit) & 1) for bit in range(8))
    mask = mask[:lc]
    return j, c, k, mask


# ---------------------------------------------------------------------------
# Accumulate invocation init (pvm_invocations.tex eq:accinvocation + eq:memlayout)
# ---------------------------------------------------------------------------

def ceil_page(x: int) -> int:
    return P * ((x + P - 1) // P)


def ceil_zone(x: int) -> int:
    return Z * ((x + Z - 1) // Z)


def standard_registers(a: bytes) -> list:
    r = [0] * 13
    r[0] = 2 ** 32 - 2 ** 16
    r[1] = 2 ** 32 - 2 * Z - I
    r[7] = 2 ** 32 - Z - I
    r[8] = len(a)
    return r


def standard_memory(o: bytes, w: bytes, z: int, s: int, a: bytes) -> Memory:
    """GP eq:memlayout for Y(p,a). Returns his Memory (values = written octets
    only; access = page → 'R' | 'W'). o's zone uses rnq (zone-aligned |o|) as
    the rw base offset; rw's W access covers rnp(|w|) + z·P pages (GP's
    'z Cpvmpagesize' extra writable scratch follows the rw data)."""
    mem = Memory(values={}, access={})
    ro_base, rw_base = Z, 2 * Z + ceil_zone(len(o))
    st_base = 2 ** 32 - 2 * Z - I - ceil_page(s)
    ar_base = 2 ** 32 - Z - I

    def put(base: int, blob: bytes, access: str, pages: int):
        for i, octet in enumerate(blob):
            mem.values[(base + i) % 2 ** 32] = octet
        for pg in range(pages):
            mem.access[(base // P) + pg] = access

    put(ro_base, o, "R", ceil_page(len(o)) // P)
    put(rw_base, w, "W", (ceil_page(len(w)) // P) + (z * P) // P)
    put(st_base, b"", "W", ceil_page(s) // P)
    put(ar_base, a, "R", max(1, ceil_page(len(a)) // P))
    return mem


def make_args(t: int, s: int, n_items: int) -> bytes:
    """E(t, s, len(i)) — GP-compact chain (GP E = compact for naturals).
    NOTE: fixed-width u32LE is the alternative reading; the census/execution
    legs will disambiguate once the core runs (see harness docstring)."""
    return enc_compact(t) + enc_compact(s) + enc_compact(n_items)


# ---------------------------------------------------------------------------
# Case extraction
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AccumCase:
    name: str
    json: dict
    service_id: int
    code_blob: bytes
    code_hash: str
    t: int
    n_items: int
    n_reports: int
    program: Program
    ro: bytes
    rw: bytes
    stack_pages: int
    args: bytes
    registers: list
    memory: Memory
    expected_gas: int | None
    expected_writes: list


def _stats_gas(d: dict, sid: int) -> int | None:
    """Statistics record for sid: record.accumulate_gas_used (nested), or
    None when the vector carries no record for that service."""
    for rec in d.get("statistics", []):
        if rec.get("id") == sid:
            rd = rec.get("record") or {}
            v = rd.get("accumulate_gas_used")
            return None if v is None else v
    return None


def load_case(name: str) -> AccumCase:
    path = os.path.join(VECTOR_ROOT, name + ".json")
    d = json.load(open(path))
    accounts = d["pre_state"]["accounts"]
    acc = accounts[0]
    svc = acc["data"]["service"]
    sid = acc["id"]
    big = max(acc["data"]["preimage_blobs"], key=lambda e: len(e["blob"]))
    blob = bytes.fromhex(big["blob"][2:])
    ch = svc["code_hash"][2:]
    digest = hashlib.blake2b(blob, digest_size=32).hexdigest()
    assert digest == ch, f"code_hash mismatch: {digest} != code_hash"
    meta, p = strip_metadata(blob)
    o, w, z, s, inner = parse_standard_p(p)
    j, c, k, mask = parse_gp_blob(inner)
    program = Program(instruction_data=c, jump_table=j, opcode_bitmask=mask)
    n_reports = len(d["input"]["reports"])
    t = d["input"]["slot"]
    # accumulate inputs i = this service's work results across the reports
    results = [r for rep in d["input"]["reports"] for r in rep.get("results", [])]
    n_items = len([r for r in results if r.get("service_id") == acc["id"]])
    a = make_args(t, acc["id"], n_items)
    registers = standard_registers(a)
    memory = standard_memory(o, w, z, s, a)
    eg = None
    g_post = _stats_gas(d["post_state"], acc["id"])
    g_pre = _stats_gas(d["pre_state"], acc["id"])
    if g_post is not None:
        eg = g_post - (g_pre or 0)
    pw = _diff_writes(d, acc["id"])
    return AccumCase(
        name=name, json=d, service_id=acc["id"], code_blob=blob, code_hash=ch,
        t=t, n_items=n_items, n_reports=n_reports, program=program, ro=o, rw=w,
        stack_pages=s,
        args=a, registers=registers, memory=memory, expected_gas=eg,
        expected_writes=pw,
    )


def _diff_writes(d: dict, sid: int) -> list:
    pre = {e["key"]: e["value"] for a in d["pre_state"]["accounts"]
           if a["id"] == sid for e in a["data"]["storage"]}
    post = {e["key"]: e["value"] for a in d["post_state"]["accounts"]
            if a["id"] == sid for e in a["data"]["storage"]}
    out = []
    for k in post:
        if post[k] != pre.get(k):
            out.append((k, len(post[k]) // 2, post[k][:40]))
    return out


# ---------------------------------------------------------------------------
# Static census: instruction count + ecalli host-call histogram
# ---------------------------------------------------------------------------

def census(program: Program):
    """Walk instruction starts via the expanded mask; return (n_instr,
    n_host_calls, host_histogram, first_opcodes)."""
    mask, c = program.opcode_bitmask, program.instruction_data
    n = len(c)
    i = 0
    n_instr = 0
    hosts = {}
    start_bytes = []
    while i < n:
        if not mask[i]:
            i += 1
            continue
        n_instr += 1
        if n_instr <= 8:
            start_bytes.append((i, c[i]))
        if c[i] == ECALLI_OPCODE:
            # ONE_IMM width l_X = min(4, skip(i)) — skip = next-start - i - 1
            nxt = i + 1
            while nxt < n and not mask[nxt]:
                nxt += 1
            l = min(4, nxt - i - 1)
            # static raw LE read (ids 0..22 are small positive; elided-octet
            # sext semantics live in the core)
            imm = int.from_bytes(bytes(c[i + 1:i + 1 + l]) or b"\x00", "little")
            hosts[imm] = hosts.get(imm, 0) + 1
            i = nxt
            continue
        i += 1
    return n_instr, hosts, start_bytes


# ---------------------------------------------------------------------------
# The stub you replace with your Ψ loop
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class PvmRun:
    exit: str
    gas_used: int
    host_calls: list
    r7_final: int


def run_accumulate_case(case: AccumCase) -> PvmRun:
    """← THE STUB. Implement your Ψ_A machine loop here (or re-point this at
    your jam_impl/pvm.py entry). Inputs are ready on `case`: program (expanded
    mask + jump table), registers (standard init), memory (zones + args at
    r7), expected_gas budget, and the host-call fee rules in the docstring.

    Required semantics for the gate to be exact:
      - 1 gas per instruction, fee 10 per host call (+r9 for transfer id 20)
      - ecalli = host call; the harness's HostDispatch (below) names them
      - oog/panic end the run exceptionally; halt returns r7 (accumulate yield)
    """
    raise NotImplementedError("PVM core stub — point run_accumulate_case at your Ψ loop")


class HostDispatch:
    """Fee table + name layer; per-call semantics are TODO by design (the
    accumulate service-op layer is STF work, not PVM work)."""

    def __init__(self):
        self.calls = []

    def fee(self, host_id: int, registers: list) -> int:
        if host_id in NO_FEE_IDS:
            return 0
        if host_id == TRANSFER_ID:
            return 10 + registers[9]
        return 10

    def name(self, host_id: int) -> str:
        return HOST_NAMES.get(host_id, f"unknown-{host_id}")


# ---------------------------------------------------------------------------
# Driver — house style: PASS/FAIL/PENDING/CRASH rows, never one-kills-all
# ---------------------------------------------------------------------------

def _fmt_writes(ws):
    return "; ".join(f"{k[:14]}…({n}B)" for k, n, _ in ws) or "∅"


def run_vector(case: AccumCase) -> None:
    print(f"\n=== {case.name}")
    rows = []
    n_instr, hosts, starts = census(case.program)
    j_ok = all(0 <= e < len(case.program.instruction_data) for e in case.program.jump_table)
    rows.append(("PASS" if len(case.code_blob) > 0 and case.program.jump_table else "FAIL",
                 f"blob extracted: {len(case.code_blob)}B, j={len(case.program.jump_table)}"
                 f" (z-entries ok={j_ok}), c={len(case.program.instruction_data)}B,"
                 f" mask bits set={sum(case.program.opcode_bitmask)}"))
    rows.append(("INFO", f"hash blake2b-256 == code_hash ✓, service {case.service_id},"
                 f" slot t={case.t}, items={case.n_items}"))
    rows.append(("INFO", f"instructions={n_instr}, ecalli census={hosts or '∅'},"
                 f" first starts={starts[:3]}"))
    rows.append(("INFO", f"args a={case.args.hex()} ({len(case.args)}B, at r7),"
                 f" gas budget (stats a.1 diff)={case.expected_gas}"))
    rows.append(("INFO", f"expected storage writes: {_fmt_writes(case.expected_writes)}"))
    try:
        run = run_accumulate_case(case)
        if case.expected_gas is not None:
            gate_gas = "PASS" if run.gas_used == case.expected_gas else "FAIL"
            rows.append((gate_gas, f"gas_used={run.gas_used} vs expected={case.expected_gas}"))
        else:
            rows.append(("INFO", "gas gate n/a (vector carries no statistics for the service)"))
        rows.append(("INFO", f"exit={run.exit}, r7={run.r7_final},"
                     f" hosts={[(h[1]) for h in run.host_calls][:10]}"))
    except NotImplementedError:
        rows.append(("PENDING", "run_accumulate_case is the stub — core not landed"))
    except Exception as e:  # noqa: BLE001 — one bad vector never kills the set
        rows.append(("CRASH", f"{type(e).__name__}: {e}"))
    for kind, msg in rows:
        print(f"  {kind:8} | {msg}")


def main(argv):
    names = argv[1:]
    if names and (names[0].endswith(".json") or os.sep in names[0] or "/" in names[0]):
        # accept a path or a bare name
        names = [os.path.splitext(os.path.basename(p))[0] for p in names]
    if not names:
        names = DEFAULT_CASES
    for nm in names:
        case = load_case(nm)
        run_vector(case)


if __name__ == "__main__":
    main(sys.argv)


# ---------------------------------------------------------------------------
# Extraction legs as unittest — these run TODAY, before the core lands
# ---------------------------------------------------------------------------

class PvmHarnessExtraction(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chain = load_case("enqueue_and_unlock_chain-1")
        cls.primary = load_case(DEFAULT_CASES[0])

    def test_code_hash_whisk_is_blake2b(self):
        self.assertEqual(hashlib.blake2b(self.chain.code_blob,
                                        digest_size=32).hexdigest(), self.chain.code_hash)

    def test_mask_anchor_first_octet(self):
        c, m = self.chain.program.instruction_data, self.chain.program.opcode_bitmask
        self.assertTrue(m[0], "c[0] must be an instruction start")
        self.assertEqual(c[0], 0x28, "entry stub opcode 40 = jump")
        self.assertFalse(m[1], "arg octet must not be a start")

    def test_mask_density_sane(self):
        for case in (self.chain, self.primary):
            starts = sum(case.program.opcode_bitmask)
            n = len(case.program.instruction_data)
            self.assertTrue(0.05 < starts / n < 0.5, f"mask density {starts}/{n}")

    def test_jump_table_in_range(self):
        n = len(self.chain.program.instruction_data)
        self.assertTrue(all(0 <= e < n for e in self.chain.program.jump_table))

    def test_standard_register_setup(self):
        r = self.chain.registers
        self.assertEqual(r[0], 2 ** 32 - 2 ** 16)
        self.assertEqual(r[7], 2 ** 32 - 2 ** 16 - 2 ** 24)
        self.assertEqual(r[8], len(self.chain.args))

    def test_args_region_readable(self):
        ar_base = 2 ** 32 - 2 ** 16 - 2 ** 24
        self.assertTrue(self.chain.memory.readable(ar_base, len(self.chain.args)))
        got = bytes(self.chain.memory.read(ar_base, len(self.chain.args)))
        self.assertEqual(got, self.chain.args)

    def test_rw_region_writable(self):
        rw_base = 2 * 2 ** 16 + (2 ** 16) * ((len(self.chain.ro) + 2 ** 16 - 1) // 2 ** 16)
        self.assertTrue(self.chain.memory.writable(rw_base, 2))
        w_span = ((len(self.chain.rw) // 4096 + 1) * 4096) + 2 * 4096  # rnp(|w|) + z·P
        self.assertTrue(self.chain.memory.writable(rw_base, w_span))
        self.assertFalse(self.chain.memory.writable(rw_base + w_span, 1),
                         "zone gap beyond rnp(|w|)+z·P is inaccessible")

    def test_expected_gas_positive_for_primary_case(self):
        self.assertEqual(self.primary.expected_gas, 4364,
                         "process_one_immediate_report-1 statistics a.1")

    def test_host_fee_table(self):
        hd = HostDispatch()
        zero_regs = [0] * 13
        self.assertEqual(hd.fee(0, zero_regs), 10)
        self.assertEqual(hd.fee(LOG_ID, zero_regs), 0)  # log, this bundle
        self.assertEqual(hd.fee(20, [0] * 9 + [500] + [0, 0, 0]), 510)  # 10 + r9
