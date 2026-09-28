import jam_impl.util as util
from jam_impl.util import Decoder, Encoder, StrictSet
from jam_impl.codec.header_codec import spec_globals
from jam_impl.codec.extrinsic_codec import decode_report, encode_report
from jam_impl.models.State import (
    ValidatorData, ValidatorStatistics, CoreStatistics, ServiceStatistics,
    TicketBody, AlwaysAccumulate, ReportedWorkPackage, BlockInfo, ReadyRecord,
    AuthorizationPool, AuthorizationQueue, RecentHistory, SafroleState,
    Disputes, EntropyAccumulator, UpcomingValidators, CurrentValidators,
    PreviousValidators, AvailabilityAssignment, AvailabilityAssignments,
    MostRecentTimeslot, PrivilegedServices, RegistrarState, AccumulationQueue,
    AccumulationHistory, Statistics,
    ServiceDefinition, ServiceDefinitionData, ServiceDefinitionDataService,
    ServiceAccount, ServiceStorageItem, PreimageBlob, PreimageLookupEntry,
    State,
)
from collections.abc import Callable

AUTHORIZATION_QUEUE_LENGTH = 80
RECENT_HISTORY_LENGTH = 8
TICKET_ENTRY_PER_VALIDATOR_COUNT = 2
VALIDATORS_PER_CORE = 3


def core_count() -> int:
    return util.NUM_VALIDATORS_IN_EPOCH_MARK // VALIDATORS_PER_CORE


# Shared sub-decoders


def decode_validator_list(d: Decoder) -> list[ValidatorData]:
    validators = []
    for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK):        
        validators.append(ValidatorData(
            bandersnatch=d.hash32(),
            ed25519=d.hash32(),
            bls=d.take(144),
            metadata=d.take(128),
        ))
    if len(set(validators)) != len(validators):
      raise ValueError("duplicate validator record")
    return validators


def encode_validator_list(e: Encoder, validators: list[ValidatorData]) -> None:
    for v in validators:
        e.hash32(v.bandersnatch)
        e.hash32(v.ed25519)
        e.raw(v.bls)
        e.raw(v.metadata)


def decode_validators_statistics(d: Decoder) -> list[ValidatorStatistics]:
    return [
        ValidatorStatistics(
            blocks=d.u32(),
            tickets=d.u32(),
            pre_images=d.u32(),
            pre_images_size=d.u32(),
            guarantees=d.u32(),
            assurances=d.u32(),
        )
        for _ in range(util.NUM_VALIDATORS_IN_EPOCH_MARK)
    ]


def encode_validators_statistics(e: Encoder, stats: list[ValidatorStatistics]) -> None:
    for s in stats:
        e.u32(s.blocks)
        e.u32(s.tickets)
        e.u32(s.pre_images)
        e.u32(s.pre_images_size)
        e.u32(s.guarantees)
        e.u32(s.assurances)


# State component decoders  C(1) to C(16)

def decode_authorization_pool(b: bytes) -> AuthorizationPool:
    d = Decoder(b)
    pools = []
    for _ in range(core_count()):
        pool_length = d.decode_compact()
        pools.append([d.hash32() for _ in range(pool_length)])
    d.finish()
    return AuthorizationPool(pools=pools)


def encode_authorization_pool(pool: AuthorizationPool) -> bytes:
    e = Encoder()
    for core_pool in pool.pools:
        e.compact(len(core_pool))
        for authorizer in core_pool:
            e.hash32(authorizer)
    return e.finish()


def decode_authorization_queue(b: bytes) -> AuthorizationQueue:
    d = Decoder(b)
    queues = []
    for _ in range(core_count()):
        queues.append([d.hash32() for _ in range(AUTHORIZATION_QUEUE_LENGTH)])
    d.finish()
    return AuthorizationQueue(queues=queues)


def encode_authorization_queue(queue: AuthorizationQueue) -> bytes:
    e = Encoder()
    for core_queue in queue.queues:
        assert len(core_queue) == AUTHORIZATION_QUEUE_LENGTH, \
            f"each authorization queue must hold {AUTHORIZATION_QUEUE_LENGTH} authorizers"
        for authorizer in core_queue:
            e.hash32(authorizer)
    return e.finish()


def decode_recent_history(b: bytes) -> RecentHistory:
    d = Decoder(b)
    history = []
    for _ in range(d.decode_compact()):        # ↕β_H
        header_hash = d.hash32()
        beefy_root = d.hash32()
        state_root = d.hash32()
        reported = [
            ReportedWorkPackage(hash=d.hash32(), exports_root=d.hash32())
            for _ in range(d.decode_compact())
        ]
        history.append(BlockInfo(
            header_hash=header_hash, beefy_root=beefy_root,
            state_root=state_root, reported=reported,
        ))
    mmr_peaks = []                            # E_M(β_B): ↕ of ¿-peaks
    for _ in range(d.decode_compact()):
        if d.u8() == 1:
            mmr_peaks.append(d.hash32())
        else:
            mmr_peaks.append(None)
    d.finish()
    return RecentHistory(history=history, mmr_peaks=mmr_peaks)


def encode_recent_history(history: RecentHistory) -> bytes:
    e = Encoder()
    e.compact(len(history.history))
    for block_info in history.history:
        e.hash32(block_info.header_hash)
        e.hash32(block_info.beefy_root)
        e.hash32(block_info.state_root)
        e.compact(len(block_info.reported))
        for package in block_info.reported:
            e.hash32(package.hash)
            e.hash32(package.exports_root)
    e.compact(len(history.mmr_peaks))
    for peak in history.mmr_peaks:
        if peak is None:
            e.u8(0)
        else:
            e.u8(1).hash32(peak)
    return e.finish()


def decode_safrole_state(b: bytes) -> SafroleState:
    d = Decoder(b)
    pending_validators = decode_validator_list(d)
    epoch_root = d.take(144)
    flag = d.u8()
    if flag == 0:                             # γ_S = tickets for this epoch
        tickets_or_keys = [
            TicketBody(id=d.hash32(), attempt=d.u8())
            for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
        ]
    elif flag == 1:                           # fallback: seal with keys instead
        tickets_or_keys = [
            d.hash32() for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS)
        ]
    else:
        raise ValueError(f"Slot sealer flag is invalid: {flag}")
    ticket_accumulator = [                    # γ_A, ↕-prefixed
        TicketBody(id=d.hash32(), attempt=d.u8())
        for _ in range(d.decode_compact())
    ]
    d.finish()
    return SafroleState(
        pending_validators=pending_validators,
        epoch_root=epoch_root,
        tickets_or_keys_flag=flag,
        tickets_or_keys=tickets_or_keys,
        ticket_accumulator=ticket_accumulator,
    )


def encode_safrole_state(safrole: SafroleState) -> bytes:
    e = Encoder()
    encode_validator_list(e, safrole.pending_validators)
    e.raw(safrole.epoch_root)
    e.u8(safrole.tickets_or_keys_flag)
    assert len(safrole.tickets_or_keys) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS, \
        f"safrole tickets/keys must hold exactly {util.LENGTH_OF_EPOCH_IN_TIMESLOTS} entries"
    for entry in safrole.tickets_or_keys:
        if safrole.tickets_or_keys_flag == 0:
            e.hash32(entry.id).u8(entry.attempt)
        else:
            e.hash32(entry)
    e.compact(len(safrole.ticket_accumulator))
    for ticket in safrole.ticket_accumulator:
        e.hash32(ticket.id).u8(ticket.attempt)
    return e.finish()


def decode_disputes(b: bytes) -> Disputes:
    d = Decoder(b)
    good = [d.hash32() for _ in range(d.decode_compact())]
    bad = [d.hash32() for _ in range(d.decode_compact())]
    wonky = [d.hash32() for _ in range(d.decode_compact())]
    offenders = [d.hash32() for _ in range(d.decode_compact())]
    d.finish()
    return Disputes(good=good, bad=bad, wonky=wonky, offenders=offenders)


def encode_disputes_state(disputes: Disputes) -> bytes:
    e = Encoder()
    e.compact(len(disputes.good))
    for target in disputes.good:
        e.hash32(target)
    e.compact(len(disputes.bad))
    for target in disputes.bad:
        e.hash32(target)
    e.compact(len(disputes.wonky))
    for target in disputes.wonky:
        e.hash32(target)
    e.compact(len(disputes.offenders))
    for key in disputes.offenders:
        e.hash32(key)
    return e.finish()


def decode_entropy_accumulator(b: bytes) -> EntropyAccumulator:
    d = Decoder(b)
    values = [d.hash32() for _ in range(4)]
    d.finish()
    return EntropyAccumulator(values=values)


def encode_entropy_accumulator(entropy: EntropyAccumulator) -> bytes:
    assert len(entropy.values) == 4, "η holds exactly 4 entropy values"
    e = Encoder()
    for value in entropy.values:
        e.hash32(value)
    return e.finish()


def decode_upcoming_validators(b: bytes) -> UpcomingValidators:
    d = Decoder(b)
    validators = decode_validator_list(d)
    d.finish()
    return UpcomingValidators(validators=validators)


def encode_upcoming_validators(upcoming: UpcomingValidators) -> bytes:
    e = Encoder()
    encode_validator_list(e, upcoming.validators)
    return e.finish()


def decode_current_validators(b: bytes) -> CurrentValidators:
    d = Decoder(b)
    validators = decode_validator_list(d)
    d.finish()
    return CurrentValidators(validators=validators)


def encode_current_validators(current: CurrentValidators) -> bytes:
    e = Encoder()
    encode_validator_list(e, current.validators)
    return e.finish()


def decode_previous_validators(b: bytes) -> PreviousValidators:
    d = Decoder(b)
    validators = decode_validator_list(d)
    d.finish()
    return PreviousValidators(validators=validators)


def encode_previous_validators(previous: PreviousValidators) -> bytes:
    e = Encoder()
    encode_validator_list(e, previous.validators)
    return e.finish()


def decode_availability_assignments(b: bytes) -> AvailabilityAssignments:
    d = Decoder(b)
    assignments = []
    for _ in range(core_count()):
        if d.u8() == 1:
            report = decode_report(d)
            timeout = d.u32()
            assignments.append(AvailabilityAssignment(
                report=report, timeout=timeout,
            ))
        else:
            assignments.append(None)
    d.finish()
    return AvailabilityAssignments(assignments=assignments)


def encode_availability_assignments(assignments: AvailabilityAssignments) -> bytes:
    e = Encoder()
    for assignment in assignments.assignments:
        if assignment is None:
            e.u8(0)
        else:
            e.u8(1)
            encode_report(e, assignment.report)
            e.u32(assignment.timeout)
    return e.finish()


def decode_most_recent_timeslot(b: bytes) -> MostRecentTimeslot:
    d = Decoder(b)
    timeslot = d.u32()
    d.finish()
    return MostRecentTimeslot(timeslot=timeslot)


def encode_most_recent_timeslot(timeslot: MostRecentTimeslot) -> bytes:
    return Encoder().u32(timeslot.timeslot).finish()


def decode_privileged_services(b: bytes) -> PrivilegedServices:
    d = Decoder(b)
    bless = d.u32()
    assign = [d.u32() for _ in range(core_count())]
    designate = d.u32()
    register = d.u32()
    always_acc = [                           # χ_Z, ↕-prefixed
        AlwaysAccumulate(service_id=d.u32(), gas=d.u64())
        for _ in range(d.decode_compact())
    ]
    d.finish()
    return PrivilegedServices(
        bless=bless, assign=assign, designate=designate,
        register=register, always_acc=always_acc,
    )


def encode_privileged_services(privileges: PrivilegedServices) -> bytes:
    e = Encoder()
    e.u32(privileges.bless)
    assert len(privileges.assign) == core_count(), \
        f"privileges.assign must hold exactly {core_count()} assigner services"
    for service_id in privileges.assign:
        e.u32(service_id)
    e.u32(privileges.designate)
    e.u32(privileges.register)
    e.compact(len(privileges.always_acc))
    for entry in privileges.always_acc:
        e.u32(entry.service_id)
        e.u64(entry.gas)
    return e.finish()


def decode_registrar_state(b: bytes) -> RegistrarState:
    d = Decoder(b)
    vals_curr_stats = decode_validators_statistics(d)
    vals_last_stats = decode_validators_statistics(d)
    cores_stats = [                          # ALL fields compact (verified)
        CoreStatistics(
            da_load=d.decode_compact(),
            popularity=d.decode_compact(),
            imports=d.decode_compact(),
            extrinsic_count=d.decode_compact(),
            extrinsic_size=d.decode_compact(),
            exports=d.decode_compact(),
            bundle_size=d.decode_compact(),
            gas_used=d.decode_compact(),
        )
        for _ in range(core_count())
    ]
    services_stats = {}                      # π_S: ↕-prefixed (id, record) pairs
    for _ in range(d.decode_compact()):
        service_id = d.u32()
        services_stats[service_id] = ServiceStatistics(
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
    d.finish()
    return RegistrarState(
        vals_curr_stats=vals_curr_stats,
        vals_last_stats=vals_last_stats,
        cores_stats=cores_stats,
        services_stats=services_stats,
    )


def encode_registrar_state(registrar: RegistrarState) -> bytes:
    e = Encoder()
    encode_validators_statistics(e, registrar.vals_curr_stats)
    encode_validators_statistics(e, registrar.vals_last_stats)
    assert len(registrar.cores_stats) == core_count(), \
        f"π_C must hold exactly {core_count()} core records"
    for stats in registrar.cores_stats:
        e.compact(stats.da_load)
        e.compact(stats.popularity)
        e.compact(stats.imports)
        e.compact(stats.extrinsic_count)
        e.compact(stats.extrinsic_size)
        e.compact(stats.exports)
        e.compact(stats.bundle_size)
        e.compact(stats.gas_used)
    e.compact(len(registrar.services_stats))
    for service_id in sorted(registrar.services_stats):  # dictionaries key-sorted (GP C.10)
        stats = registrar.services_stats[service_id]
        e.u32(service_id)
        e.compact(stats.provided_count)
        e.compact(stats.provided_size)
        e.compact(stats.refinement_count)
        e.compact(stats.refinement_gas_used)
        e.compact(stats.imports)
        e.compact(stats.extrinsic_count)
        e.compact(stats.extrinsic_size)
        e.compact(stats.exports)
        e.compact(stats.accumulate_count)
        e.compact(stats.accumulate_gas_used)
    return e.finish()


def decode_accumulation_queue(b: bytes) -> AccumulationQueue:
    d = Decoder(b)
    queue = []
    for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS):
        slot_records = []
        for _ in range(d.decode_compact()):
            report = decode_report(d)
            m = d.decode_compact()
            dependencies = StrictSet(d.hash32() for _ in range(m))
            slot_records.append(ReadyRecord(
                report=report, dependencies=dependencies,
            ))
        queue.append(slot_records)
    d.finish()
    return AccumulationQueue(queue=queue)


def encode_accumulation_queue(accumulation_queue: AccumulationQueue) -> bytes:
    assert len(accumulation_queue.queue) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS, \
        f"accumulation_queue C(14) must hold exactly {util.LENGTH_OF_EPOCH_IN_TIMESLOTS} slots"
    e = Encoder()
    for slot_records in accumulation_queue.queue:
        e.compact(len(slot_records))
        for record in slot_records:
            encode_report(e, record.report)
            e.compact(len(record.dependencies))
            for dependency in sorted(record.dependencies):  # GP C.11: ascending
                e.hash32(dependency)
    return e.finish()


def decode_accumulation_history(b: bytes) -> AccumulationHistory:
    d = Decoder(b)
    history = []
    for _ in range(util.LENGTH_OF_EPOCH_IN_TIMESLOTS):
        n = d.decode_compact()
        history.append(StrictSet(d.hash32() for _ in range(n)))
    d.finish()
    return AccumulationHistory(history=history)


def encode_accumulation_history(history: AccumulationHistory) -> bytes:
    assert len(history.history) == util.LENGTH_OF_EPOCH_IN_TIMESLOTS, \
        f"accumulation_history C(15) must hold exactly {util.LENGTH_OF_EPOCH_IN_TIMESLOTS} slots"
    e = Encoder()
    for slot_hashes in history.history:
        e.compact(len(slot_hashes))
        for package_hash in sorted(slot_hashes):  # GP C.11: ascending
            e.hash32(package_hash)
    return e.finish()


def decode_statistics(b: bytes) -> Statistics:
    d = Decoder(b)
    outputs = []
    for _ in range(d.decode_compact()):
        service_id = d.u32()
        work_report_hash = d.hash32()
        outputs.append((service_id, work_report_hash))
    d.finish()
    return Statistics(outputs=outputs)


def encode_statistics(statistics: Statistics) -> bytes:
    e = Encoder()
    e.compact(len(statistics.outputs))
    for service_id, work_report_hash in statistics.outputs:
        e.u32(service_id)
        e.hash32(work_report_hash)
    return e.finish()


def decode_service_definition(b: bytes, service_index: int) -> ServiceDefinition:
    d = Decoder(b)
    service_definition = ServiceDefinition(
        service_index=service_index,
        data=ServiceDefinitionData(
            service=ServiceDefinitionDataService(
                version=d.u8(),
                code_hash=d.hash32(),
                balance=d.u64(),
                min_item_gas=d.u64(),
                min_memo_gas=d.u64(),
                bytes_count=d.u64(),
                deposit_offset=d.u64(),
                items=d.u32(),
                creation_slot=d.u32(),
                last_accumulation_slot=d.u32(),
                parent_service=d.u32(),
            )
        ),
    )
    d.finish()
    return service_definition


def encode_service_definition(definition: ServiceDefinition) -> bytes:
    s = definition.data.service
    return (
        Encoder()
        .u8(s.version)
        .hash32(s.code_hash)
        .u64(s.balance)
        .u64(s.min_item_gas)
        .u64(s.min_memo_gas)
        .u64(s.bytes_count)
        .u64(s.deposit_offset)
        .u32(s.items)
        .u32(s.creation_slot)
        .u32(s.last_accumulation_slot)
        .u32(s.parent_service)
        .finish()
    )


def decode_form_three_component(b: bytes):
    # TODO: will have to look at this after trie
    return None


# Raw wire <-> State (semantic)
# decode functions take the raw value bytes; encode functions (called via the
# model methods) take the component. One row per first-form key: a component's
# key and codec only ever change together, in one place.
STATE_COMPONENTS: dict[int, tuple[Callable, Callable]] = {
    1: (decode_authorization_pool, encode_authorization_pool),
    2: (decode_authorization_queue, encode_authorization_queue),
    3: (decode_recent_history, encode_recent_history),
    4: (decode_safrole_state, encode_safrole_state),
    5: (decode_disputes, encode_disputes_state),
    6: (decode_entropy_accumulator, encode_entropy_accumulator),
    7: (decode_upcoming_validators, encode_upcoming_validators),
    8: (decode_current_validators, encode_current_validators),
    9: (decode_previous_validators, encode_previous_validators),
    10: (decode_availability_assignments, encode_availability_assignments),
    11: (decode_most_recent_timeslot, encode_most_recent_timeslot),
    12: (decode_privileged_services, encode_privileged_services),
    13: (decode_registrar_state, encode_registrar_state),
    14: (decode_accumulation_queue, encode_accumulation_queue),
    15: (decode_accumulation_history, encode_accumulation_history),
    16: (decode_statistics, encode_statistics),
}

# GP D.1 Form 1 to 3
def state_key_decoder(key: bytes) -> Callable | int | None:
    first = key[0]
    # first form
    if 0 < first <= 16 and key[1:] == b'\x00' * 30:
        return STATE_COMPONENTS[first][0]  # (decode, encode) tuple → decoder
    # second form
    elif (first == 255
          and key[2] == 0
          and key[4] == 0
          and key[6] == 0
          and key[8:] == b'\x00' * 23):
        # GP D.1 form-2: C((255, s)) = [255, n0, 0, n1, 0, n2, 0, n3, 0...] with
        # n = E4(s) little-endian at ODD positions. (The old code read bytes
        # 0,2,4,6 — which wrongly folded the constant 255 into the service id.)
        service_index = int.from_bytes(key[1:2] + key[3:4] + key[5:6] + key[7:8],
                                       byteorder="little")
        return service_index
    # third form
    else:
        return decode_form_three_component


def decode_state(b: bytes) -> State:
    """RawState wire -> semantic State: every form-1 component laid out by
    name, form-2 accounts bucketed by service id, form-3 parked in
    `undecoded` (nothing silently dropped)."""
    with spec_globals("tiny"):
        d = Decoder(b)
        state_root = d.hash32()
        n = d.decode_compact()
        state = State()
        for _ in range(n):
            key = d.take(31)
            value = d.blob()
            decode_function = state_key_decoder(key)
            if callable(decode_function):
                component = decode_function(value)
            else:  # form-2 key: the "decoder" IS the service index
                component = decode_service_definition(value, decode_function)
            _absorb_component(state, key, value, component)
        state.state_root = state_root
        return state


def _absorb_component(state: State, key: bytes, value: bytes, component) -> None:
    """Place one decoded entry into the semantic State."""
    first = key[0]
    if first == 255 and component is not None:
        sid = component.service_index
        state.accounts.setdefault(sid, ServiceAccount()).definition = component
    elif 1 <= first <= 16 and key[1:] == b'\x00' * 30:
        mapping = {
            1: "authorization_pool", 2: "authorization_queue",
            3: "recent_history", 4: "safrole", 5: "disputes",
            6: "entropy", 7: "upcoming_validators", 8: "current_validators",
            9: "previous_validators", 10: "availability_assignments",
            11: "most_recent_timeslot", 12: "privileged_services",
            13: "registrar", 14: "accumulation_queue",
            15: "accumulation_history", 16: "statistics",
        }
        setattr(state, mapping[first], component)
    else:
        state.undecoded.append((key, value))  # form-3 (component None)


def get_state_keyvals(state: State, spec: str = "tiny") -> list[tuple[bytes, bytes]]:
    """Semantic State -> all trie keyvals, sorted by key (the RawState wire
    order, verified across all 1,000 trace vectors)."""
    with spec_globals(spec):
        keyvals = list(_iter_component_keyvals(state))
    keyvals.sort(key=lambda kv: kv[0])
    return keyvals


def _iter_component_keyvals(state: State):
    if state.authorization_pool is not None:
        yield state.authorization_pool.key(), state.authorization_pool.encode()
    if state.authorization_queue is not None:
        yield state.authorization_queue.key(), state.authorization_queue.encode()
    if state.recent_history is not None:
        yield state.recent_history.key(), state.recent_history.encode()
    if state.safrole is not None:
        yield state.safrole.key(), state.safrole.encode()
    if state.disputes is not None:
        yield state.disputes.key(), state.disputes.encode()
    if state.entropy is not None:
        yield state.entropy.key(), state.entropy.encode()
    if state.upcoming_validators is not None:
        yield state.upcoming_validators.key(), state.upcoming_validators.encode()
    if state.current_validators is not None:
        yield state.current_validators.key(), state.current_validators.encode()
    if state.previous_validators is not None:
        yield state.previous_validators.key(), state.previous_validators.encode()
    if state.availability_assignments is not None:
        yield state.availability_assignments.key(), state.availability_assignments.encode()
    if state.most_recent_timeslot is not None:
        yield state.most_recent_timeslot.key(), state.most_recent_timeslot.encode()
    if state.privileged_services is not None:
        yield state.privileged_services.key(), state.privileged_services.encode()
    if state.registrar is not None:
        yield state.registrar.key(), state.registrar.encode()
    if state.accumulation_queue is not None:
        yield state.accumulation_queue.key(), state.accumulation_queue.encode()
    if state.accumulation_history is not None:
        yield state.accumulation_history.key(), state.accumulation_history.encode()
    if state.statistics is not None:
        yield state.statistics.key(), state.statistics.encode()
    for sid in sorted(state.accounts):
        account = state.accounts[sid]
        if account.definition is not None:
            yield account.definition.key(), account.definition.encode()
        # form-3 storage/preimages/lookup: emit raw parked entries whose key
        # starts with this service's C(s, ...) prefix — rebuilt from material
        # on the write path later; until then undecoded entries pass through
    for key, value in state.undecoded:
        yield key, value


def encode_state(state: State, spec: str = "full") -> bytes:
    """State -> RawState wire bytes (root + ↕-prefixed keyvals, key-sorted)."""
    with spec_globals(spec):
        keyvals = get_state_keyvals(state, spec)
        e = Encoder()
        e.hash32(state.state_root) if hasattr(state, "state_root") else None
        e.compact(len(keyvals))
        for key, value in keyvals:
            e.raw(key)
            e.compact(len(value))
            e.raw(value)
        return e.finish()