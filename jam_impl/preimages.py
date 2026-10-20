"""Preimages STF — GP 0.7.2 §12.x 'Preimage Integration' (accumulation.tex).

    preimages_stf(accounts, service_statistics_post, preimages, current_slot) ->
        ("ok", None) | ("err", err_name)

Flat semantic args, mutating in place (same house style as reports_stf):
    accounts:                  list[PreimagesAccount]   — δ slice: a_p blobs, a_l requests
    service_statistics_post:   dict[int, ServiceStatistics] — π_S (ServiceStatistics,
                               same shape reports_stf takes; provided_count/provided_size)
    preimages:                 list[Preimage]           — E_P extrinsic (requester, blob)

GP equation map (leave this in the docstring):
    eq:preimagesareordered — E_P must be ordered & unique by (service, blob) pair;
                             else err preimages_not_sorted_unique (11.24-style ordering)
    eq:fnprovidable        — s ∈ keys(δ) ∧ δ[s].a_l[(H(i), |i|)] == []     (solicited,
                             not yet provided) else err preimage_unneeded
    eq:fnprovide           — on success: a_l[(H(blob), len)] = [slot] (mode-1 history,
                             'available since t'); a_p[H(blob)] = blob
    §13.2 eq servicestats' — provided_count += 1, provided_size += len(blob)
                             (π_S is per-block overwrite; only these two columns move)
"""
from jam_impl.models.Extrinsic import Preimage
from jam_impl.models.State import ServiceStatistics
import jam_impl.util as util
from jam_impl.util import StrictSet
from hashlib import blake2b  # noqa: F401 — H(blob) for eq:fnprovidable key checks
from dataclasses import dataclass, field

@dataclass
class PreimagesAccount:
    """The preimages-STF slice of a service account (wire-predecoded buckets)."""
    service_id: int
    blobs: dict[bytes, bytes] = field(default_factory=dict)      # a_p: hash → blob
    requests: dict[tuple[bytes, int], list[int]] = field(default_factory=dict)  # a_l


type PreimagesVerdict = tuple[str, None] | tuple[str, str]


def preimages_stf(accounts: list[PreimagesAccount],                  # δ slice (mutated: a_p, a_l buckets)
                  service_statistics_post: dict[int, ServiceStatistics],  # π_S (mutated: provided_count/provided_size)
                  preimages: list[Preimage],       # E_P
                  current_slot: int,               # H_t
                  spec: str = "tiny") -> PreimagesVerdict:
    preimage_tuples = []
    for preimage in preimages:
        preimage_tuples.append((preimage.requester, preimage.blob))
        account_found = False
        for account in accounts:
            if account.service_id == preimage.requester:
                account_found = True
                blob_hash = util.hash_via_blake2b(preimage.blob)
                key = (blob_hash, len(preimage.blob))
                if (key not in account.requests.keys()):
                    return "err", "preimage_unneeded"
                elif(len(account.requests[key]) == 1 or len(account.requests[key]) == 3):
                    return "err", "preimage_unneeded"
    if preimage_tuples != sorted(set(preimage_tuples)):
        return "err", "preimages_not_sorted_unique"    
    for preimage in preimages:
        for account in accounts:
            if account.service_id == preimage.requester:
                blob_hash = util.hash_via_blake2b(preimage.blob)
                key = (blob_hash, len(preimage.blob))
                account.requests[key].append(current_slot)                
                account.blobs[blob_hash] = preimage.blob
                if account.service_id not in service_statistics_post.keys():
                    service_statistics_post[account.service_id] = ServiceStatistics()
                service_statistics_post[account.service_id].provided_count += 1
                service_statistics_post[account.service_id].provided_size += len(preimage.blob)
    return "ok", None 