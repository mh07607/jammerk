"""History STF — GP 0.8.0 §D.1/§11.3 recent-history block advancement
(accumulation stage).

    history_stf(recent_history, header_hash, parent_state_root,
                accumulate_root, work_packages, spec) -> None

Flat semantic args, mutating in place (house style of reports_stf /
preimages_stf); the output leg of this stf is NULL — no verdict tuple:
    recent_history:      RecentHistory  — β (mutated: .history, .mmr_peaks)
    header_hash:         bytes32        — H, the new head's header hash
    parent_state_root:   bytes32        — H_r, the parent's posterior state root
    work_packages:       list[ReportedWorkPackage] — this block's reports

GP equation map (leave this in the docstring):
  eq:correctlaststateroot — the OLDEST β_H entry's state root is replaced by
      H_r THEN the new head is appended (history[] is oldest-first on this
      wire; wire entries carry no ⟨t⟩ timeslot in jamtestvectors 0.7.1).
  eq:recenthistorydef — new head = ⟨H, <head beefy>, zero-hash, wp⟩ appended
      at the END; cap 2^Cmaxhistorylen = 8 on the corrected sequence (-4
      drops the oldest — which is the just-corrected tail).
  β_B' = mmb_append(β_B, r) — the belt leaf for this block is r; the MMB
      needs no extra state (live leaf count = Σ 2^i over live slots):
        n ≥ len(r)          → r.append(leaf)
        n < len(r), r[n]=∅  → r[n] = leaf      # ∅-slot placement TERMINATES
        otherwise           → r[n]=∅; recurse P(r, H(r[n]‖leaf), n+1)
      with H = keccak256 (NOT sha3_256 — different padding) — see
      util.hash_via_keccak256 (currently a TO-DO stub).
      A merge at step n+1 fires iff n+1 == 2^j: fold slots ≤ j pairwise
      'old ‖ new' — K(r[n]‖leaf) chains upward — into slot j, reset slots
      < j to ∅.

  GATED: the new head's beefy_root for the 2-live-peak belt (-4's ebdb6db0…)
  did not match the GP mmsuperpeak fold nor 30+ swept variants — the recipe
  behind progress_blocks_history-4 is open. v1–v3 are the mmsuperpeak base
  cases (≤1 live belt peak → that peak raw). Belt/byte compare is STRICT
  everywhere else; the harness annotates this field via beefy_root_gate.

NotImplementedError until the keccak helper + mmb append land.
"""
from jam_impl.models.State import RecentHistory, ReportedWorkPackage, BlockInfo
from jam_impl.general_merkle import append_to_mmr, mmr_superpeak
import jam_impl.util as util

type HistoryVerdict = None


def history_stf(recent_history: RecentHistory,               # β (mutated)
                header_hash: bytes,                          # H (bytes32)
                parent_state_root: bytes,                    # H_r (bytes32)
                accumulate_root: bytes,                      # r (bytes32)
                work_packages: list[ReportedWorkPackage],    # this block's
                spec: str = "tiny") -> HistoryVerdict:
    # raise NotImplementedError    
    if len(recent_history.history) > 0:
        recent_history.history[-1].state_root = parent_state_root
    if len(recent_history.history) == util.MAX_BLOCKS_IN_RECENT_HISTORY:
        recent_history.history.pop(0)
    append_to_mmr(recent_history.mmr_peaks, accumulate_root, util.hash_via_keccak256)
    recent_history.history.append(BlockInfo(
        header_hash=header_hash,
        beefy_root=mmr_superpeak(recent_history.mmr_peaks),
        state_root=b'\0' * util.HASH_LEN_IN_BYTES,
        reported=work_packages
    ))
    # print(recent_history.mmr_peaks, accumulate_root)    
    # print(recent_history.mmr_peaks)
    return None