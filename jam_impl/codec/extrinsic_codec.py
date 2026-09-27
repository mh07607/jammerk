"""
Extrinsic codec: bytes <-> dataclass models (GP 4.3, C.17–C.21).

Wire order of the extrinsic tuple (GP C.16):
    E = (E_T tickets, E_P preimages, E_G guarantees, E_A assurances, E_D disputes)

Each component has its own decode_* (Decoder -> model) and encode_* (model ->
bytes) function; decode_extrinsic / encode_extrinsic compose them.

0.7.2 wire quirks (as encoded by the 0.7.1 vectors — verified byte-exact):
  * E_T ticket  = attempt E1 + ring-VRF signature (fixed 784 octets)   [C.17]
  * E_P entry   = service E4 + ↕blob                                   [C.18]
  * E_G entry   = report (C.29) + slot E4 + ↕(E2 vidx, 64-octet sig)   [C.19]
  * E_A entry   = anchor 32 + bitfield ⌈core-count/8⌉ + E2 assurer + 64-octet sig [C.20]
  * E_D         = ↕verdicts + ↕culprits + ↕faults                      [C.21]
      verdict  = target 32 + age E4 + judgments — judgments are a FIXED-SIZE
      sequence of validators-super-majority entries (NO length prefix on the
      0.7.2 wire; GP 0.8.0 C.21 adds an inner ↕ — not byte-compatible).
      judgment = vote (one octet: 0x00/0x01) + judge index E2 + sig 64
      culprit  = target 32 + key 32 + sig 64
      fault    = target 32 + vote (one octet) + key 32 + sig 64
"""

import jam_impl.util as util
from jam_impl.util import Decoder, Encoder
from jam_impl.codec.header_codec import spec_globals
from jam_impl.models.Extrinsic import (
    Ticket, Preimage, Assurance, Guarantee,
    PackageSpec, Context, SegmentRootLookupEntry, RefineLoad,
    WorkResult, ResultOk, ResultItem, Report, ValidatorSignature,
    Disputes, Verdict, Judgment, Culprit, Fault,
)
from jam_impl.models import Extrinsic


def validators_super_majority() -> int:
    return util.NUM_VALIDATORS_IN_EPOCH_MARK // 3 * 2 + 1


def bitfield_octets() -> int:
    return (util.NUM_VALIDATORS_IN_EPOCH_MARK // 3 + 7) // 8


# ---------------------------------------------------------------------------
# Tickets  E_T (GP C.17)
# ---------------------------------------------------------------------------

def decode_tickets(d: Decoder) -> list[Ticket]:
    n = d.decode_compact()
    return [Ticket(attempt=d.u8(), signature=d.take(784)) for _ in range(n)]


def encode_tickets(tickets: list[Ticket]) -> bytes:
    e = Encoder().compact(len(tickets))
    for ticket in tickets:
        e.u8(ticket.attempt).raw(ticket.signature)
    return e.finish()


# ---------------------------------------------------------------------------
# Preimages  E_P (GP C.18)
# ---------------------------------------------------------------------------

def decode_preimages(d: Decoder) -> list[Preimage]:
    n = d.decode_compact()
    return [Preimage(requester=d.u32(), blob=d.blob()) for _ in range(n)]


def encode_preimages(preimages: list[Preimage]) -> bytes:
    e = Encoder().compact(len(preimages))
    for preimage in preimages:
        e.u32(preimage.requester).blob(preimage.blob)
    return e.finish()


# ---------------------------------------------------------------------------
# Guarantees  E_G (GP C.19; report per C.29)
# ---------------------------------------------------------------------------

def decode_package_spec(d: Decoder) -> PackageSpec:
    return PackageSpec(
        hash=d.hash32(),
        length=d.u32(),
        erasure_root=d.hash32(),
        exports_root=d.hash32(),
        exports_count=d.u16(),
    )


def encode_package_spec(e: Encoder, package_spec: PackageSpec) -> None:
    e.hash32(package_spec.hash)
    e.u32(package_spec.length)
    e.hash32(package_spec.erasure_root)
    e.hash32(package_spec.exports_root)
    e.u16(package_spec.exports_count)


def decode_context(d: Decoder) -> Context:
    ctx = Context(
        anchor=d.hash32(),
        state_root=d.hash32(),
        beefy_root=d.hash32(),
        lookup_anchor=d.hash32(),
        lookup_anchor_slot=d.u32(),
        prerequisites=[],
    )
    ctx.prerequisites = [d.hash32() for _ in range(d.decode_compact())]
    return ctx


def encode_context(e: Encoder, context: Context) -> None:
    e.hash32(context.anchor)
    e.hash32(context.state_root)
    e.hash32(context.beefy_root)
    e.hash32(context.lookup_anchor)
    e.u32(context.lookup_anchor_slot)
    e.compact(len(context.prerequisites))
    for prerequisite in context.prerequisites:
        e.hash32(prerequisite)


def decode_work_result(d: Decoder) -> ResultItem:
    service_id = d.u32()
    code_hash = d.hash32()
    payload_hash = d.hash32()
    accumulate_gas = d.u64()
    tag = d.u8()
    try:
        result = WorkResult(tag)
    except ValueError:
        raise ValueError(f"invalid work-result tag {tag} (service {service_id})")
    result_payload = ResultOk(ok=d.blob()) if result is WorkResult.OK else None
    refine_load = RefineLoad(
        gas_used=d.decode_compact(),
        imports=d.decode_compact(),
        extrinsic_count=d.decode_compact(),
        extrinsic_size=d.decode_compact(),
        exports=d.decode_compact(),
    )
    return ResultItem(
        service_id=service_id, code_hash=code_hash, payload_hash=payload_hash,
        accumulate_gas=accumulate_gas, result=result,
        result_payload=result_payload, refine_load=refine_load,
    )


def encode_work_result(e: Encoder, result_item: ResultItem) -> None:
    e.u32(result_item.service_id)
    e.hash32(result_item.code_hash)
    e.hash32(result_item.payload_hash)
    e.u64(result_item.accumulate_gas)
    e.u8(result_item.result.value)
    if result_item.result is WorkResult.OK:
        assert result_item.result_payload is not None, \
            "WorkResult.OK requires result_payload (ResultOk)"
        e.blob(result_item.result_payload.ok)
    else:
        assert result_item.result_payload is None, \
            "only WorkResult.OK carries a payload"
    e.compact(result_item.refine_load.gas_used)
    e.compact(result_item.refine_load.imports)
    e.compact(result_item.refine_load.extrinsic_count)
    e.compact(result_item.refine_load.extrinsic_size)
    e.compact(result_item.refine_load.exports)


def decode_report(d: Decoder) -> Report:
    """Work report — GP C.29.

    Wire order (verified against guarantees_extrinsic.bin): package_spec,
    context, core (u8), authorizer hash, auth gas (compact), ↕auth output,
    ↕segment-root lookup, ↕results.
    """
    package_spec = decode_package_spec(d)
    context = decode_context(d)
    report = Report(
        package_spec=package_spec,
        context=context,
        core_index=d.u8(),
        authorizer_hash=d.hash32(),
        auth_gas_used=d.decode_compact(),   # compact N, NOT E8 (verified)
        auth_output=d.blob(),
        segment_root_lookup=[
            SegmentRootLookupEntry(work_package_hash=d.hash32(), segment_tree_root=d.hash32())
            for _ in range(d.decode_compact())
        ],
        results=[],
    )
    report.results = [decode_work_result(d) for _ in range(d.decode_compact())]
    return report


def encode_report(e: Encoder, report: Report) -> None:
    encode_package_spec(e, report.package_spec)
    encode_context(e, report.context)
    e.u8(report.core_index)
    e.hash32(report.authorizer_hash)
    e.compact(report.auth_gas_used)
    e.blob(report.auth_output)
    e.compact(len(report.segment_root_lookup))
    for entry in report.segment_root_lookup:
        e.hash32(entry.work_package_hash)
        e.hash32(entry.segment_tree_root)
    e.compact(len(report.results))
    for result_item in report.results:
        encode_work_result(e, result_item)


def decode_guarantees(d: Decoder) -> list[Guarantee]:
    n = d.decode_compact()
    guarantees = []
    for _ in range(n):
        report = decode_report(d)
        slot = d.u32()
        signatures = [
            ValidatorSignature(validator_index=d.u16(), signature=d.take(64))
            for _ in range(d.decode_compact())
        ]
        guarantees.append(Guarantee(report=report, slot=slot, signatures=signatures))
    return guarantees


def encode_guarantees(guarantees: list[Guarantee]) -> bytes:
    e = Encoder().compact(len(guarantees))
    for guarantee in guarantees:
        encode_report(e, guarantee.report)
        e.u32(guarantee.slot)
        e.compact(len(guarantee.signatures))
        for signature in guarantee.signatures:
            e.u16(signature.validator_index).raw(signature.signature)
    return e.finish()


# ---------------------------------------------------------------------------
# Assurances  E_A (GP C.20)
# ---------------------------------------------------------------------------

def decode_assurances(d: Decoder) -> list[Assurance]:
    n = d.decode_compact()
    return [
        Assurance(
            anchor=d.hash32(),
            bitfield=d.take(bitfield_octets()),
            validator_index=d.u16(),
            signature=d.take(64),
        )
        for _ in range(n)
    ]


def encode_assurances(assurances: list[Assurance]) -> bytes:
    e = Encoder().compact(len(assurances))
    for assurance in assurances:
        e.hash32(assurance.anchor)
        e.raw(assurance.bitfield)
        e.u16(assurance.validator_index)
        e.raw(assurance.signature)
    return e.finish()


# ---------------------------------------------------------------------------
# Disputes  E_D (GP C.21 — 0.7.2 wire: judgments have NO length prefix)
# ---------------------------------------------------------------------------

def decode_disputes(d: Decoder) -> Disputes:
    judgment_count = validators_super_majority()
    verdicts = []
    for _ in range(d.decode_compact()):
        target = d.hash32()
        age = d.u32()
        votes = [
            Judgment(vote=bool(d.u8()), index=d.u16(), signature=d.take(64))
            for _ in range(judgment_count)
        ]
        verdicts.append(Verdict(target=target, age=age, votes=votes))
    culprits = [
        Culprit(target=d.hash32(), key=d.hash32(), signature=d.take(64))
        for _ in range(d.decode_compact())
    ]
    faults = [
        Fault(target=d.hash32(), vote=bool(d.u8()), key=d.hash32(), signature=d.take(64))
        for _ in range(d.decode_compact())
    ]
    return Disputes(verdicts=verdicts, culprits=culprits, faults=faults)


def encode_disputes(disputes: Disputes) -> bytes:
    judgment_count = validators_super_majority()
    e = Encoder()
    e.compact(len(disputes.verdicts))
    for verdict in disputes.verdicts:
        e.hash32(verdict.target)
        e.u32(verdict.age)
        assert len(verdict.votes) == judgment_count, \
            f"verdict must carry exactly {judgment_count} judgments"
        for judgment in verdict.votes:
            e.u8(1 if judgment.vote else 0)
            e.u16(judgment.index)
            e.raw(judgment.signature)
    e.compact(len(disputes.culprits))
    for culprit in disputes.culprits:
        e.hash32(culprit.target).hash32(culprit.key).raw(culprit.signature)
    e.compact(len(disputes.faults))
    for fault in disputes.faults:
        e.hash32(fault.target).u8(1 if fault.vote else 0).hash32(fault.key).raw(fault.signature)
    return e.finish()


# ---------------------------------------------------------------------------
# Whole extrinsic  E (GP C.16: order T, P, G, A, D)
# ---------------------------------------------------------------------------

def decode_extrinsic(b: bytes, spec: str = "full") -> Extrinsic:
    """Decode the full extrinsic tuple into typed models (GP C.16)."""
    with spec_globals(spec):
        d = Decoder(b)
        ext = Extrinsic(
            tickets=decode_tickets(d),
            preimages=decode_preimages(d),
            guarantees=decode_guarantees(d),
            assurances=decode_assurances(d),
            disputes=decode_disputes(d),
        )
        d.finish()
        return ext


def encode_extrinsic(ext) -> bytes:
    """Encode the typed extrinsic tuple back to wire bytes."""
    return (
        encode_tickets(ext.tickets)
        + encode_preimages(ext.preimages)
        + encode_guarantees(ext.guarantees)
        + encode_assurances(ext.assurances)
        + encode_disputes(ext.disputes)
    )


if __name__ == "__main__":
    from jam_impl.codec.header_codec import load_vector
    b, j = load_vector("tiny", "extrinsic")
    ext = decode_extrinsic(b, spec="tiny")
    print("tickets:", len(ext.tickets), "preimages:", len(ext.preimages),
          "guarantees:", len(ext.guarantees), "assurances:", len(ext.assurances),
          "verdicts:", len(ext.disputes.verdicts))
    re_b = encode_extrinsic(ext)
    print("round-trip:", re_b == b)