"""Authorizations STF — GP 0.8.0 authorization.tex, pool/queue advancement
(the eq:authstate step, ordered after accumulation because α'_c reads ϕ'_c).

    authorizations_stf(authorization_pools, authorization_queues,
                       guarantees_core_authors, current_slot, spec) -> None

Flat semantic args, mutating in place (house style of reports_stf /
preimages_stf / history_stf); the output leg of this stf is NULL — no verdict
tuple:
    authorization_pools:    AuthorizationPool    — α (mutated)
    authorization_queues:   AuthorizationQueue   — ϕ (read-only on this leg:
                            mutated only via privileged accumulate assign)
    guarantees_core_authors: list[CoreAuthorizer] — (core, authorizer-hash)
                            per guarantee, in E_G order (the vectors ship
                            exactly this projection of each guarantee's
                            work-report)
    current_slot:           int                  — τ' (draw-index basis)

GP equation map (leave this in the docstring):
  eq:authstate  — pool'_c ≡ ←[ F(c) ++ cyclic(queue'_c)[τ'] ]^8
  F(c)          — pool_c minus the authorizer hash of every guarantee on
                  core c this block (set-minus; order preserved otherwise)
  wire rules pinned by jamtestvectors/stf/authorizations (all 12 verified):
    draw index  cyclic(queue')[τ'] == queue'[τ' mod 80] — cyclic over the
                queue's own length (Cauthqueuesize), NOT τ' mod epoch
                (full v3: slot 645 draws queue[5])
    truncation  ←A^8 keeps the LAST 8 — pools are oldest-first on the wire,
                the drawn authorizer appends at the TAIL, and the oldest
                slides off when |F(c)| == 8
    queue       ϕ' == ϕ here — this step never edits the queue
  No err paths: the output leg of this stf is NULL.
"""
import jam_impl.util as util
from jam_impl.models.State import AuthorizationQueue
from jam_impl.models.State import AuthorizationPool
from dataclasses import dataclass

type AuthorizationsVerdict = None


@dataclass
class CoreAuthorizer:
    """The per-guarantee projection the vectors carry input-side
    (CoreAuthorizer in stf/authorizations/authorizations.asn): the work
    report's core index and authorizer hash — E_G[i].w.core / E_G[i].w.auth."""
    core: int           # core index (u16 on this wire)
    auth_hash: bytes    # 32-octet authorizer hash


def authorizations_stf(authorization_pools: AuthorizationPool,     # α (mutated)
                       authorization_queues: AuthorizationQueue,       # ϕ (read-only)
                       guarantees_core_authors: list[CoreAuthorizer],    # per E_G item
                       current_slot: int,                                # τ'
                       spec: str = "tiny") -> AuthorizationsVerdict: 
    num_cores_checked = 0     # to avoid checking cores already dealt with                
    for i in range(util.core_count()):
      for guarantees_core_author in guarantees_core_authors[num_cores_checked:]:
        if guarantees_core_author.core == i:          
          authorization_pools.pools[i].remove(guarantees_core_author.auth_hash)
          num_cores_checked += 1
      authorization_pools.pools[i].append(authorization_queues.queues[i][current_slot % util.AUTHORIZATION_QUEUE_LENGTH])      
      pool_length = len(authorization_pools.pools[i])
      if pool_length > util.MAX_ITEMS_IN_AUTH_POOL:        
        authorization_pools.pools[i] = authorization_pools.pools[i][pool_length - util.MAX_ITEMS_IN_AUTH_POOL:]      
    return None