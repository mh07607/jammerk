from collections.abc import Callable
from dataclasses import dataclass

import jam_impl.util as util
from jam_impl.pvm_instruction_mapping import (
    INSTRUCTION_TYPE_AND_METHOD,
    InstructionTypes,
)

MIN_ADDRESS = 2**16
MAX_INSTRUCTION_LENGTH = 24
TERMINATION_OPCODE_NUMBERS = [0, 1, 40, 50, 80, 180]
MEMORY_SIZE = 2**32


@dataclass
class Program:
    instruction_data: bytes
    jump_table: list[int]
    opcode_bitmask: list[bool]

    def basic_block_and_termination_indices(self):
        n = 0
        indices = []
        while n < len(self.instruction_data):
            m = n + 1 + skip_to_next_instruction(n, self.opcode_bitmask)
            if (
                m < len(self.instruction_data)
                and self.opcode_bitmask[n]
                and self.instruction_data[n] in TERMINATION_OPCODE_NUMBERS
                and self.opcode_bitmask[m]
                # TODO: add correct version of this line
                # and self.instruction_data[m] in INSTRUCTION_TABLE.keys()
            ):
                indices.append(m)
            n = m
        return indices


@dataclass
class Memory:
    values: dict[int, int]
    access: dict[int, str]

    # The access gate is per-instruction, not per-call (GP 0.8.0 pvm.tex:168-178):
    # all-or-nothing over the instruction's inspection and mutation subscripts —
    # PANIC when min(x) mod 2^32 < 2^16 even for W pages, else FAULT carrying the
    # base address Z_P * floor(min(x) mod 2^32 / Z_P), state unchanged. read/write
    # run only after the gate passed, so they do no access check here; they only
    # canonicalize and mask.
    def _page(self, address: int) -> str | None:
        page = (address % 2**32) >> 12  # cyclic subscript: wraps at 2^32
        return self.access.get(page, None)  # 'W' | 'R' | None (None = inaccessible)

    def readable(self, start: int, length: int) -> bool:
        return all(self._page(start + i) is not None for i in range(length))

    def writable(self, start: int, length: int) -> bool:
        return all(self._page(start + i) == "W" for i in range(length))

    def read(self, address: int, length: int) -> list[int]:
        base = address % MEMORY_SIZE
        return [self.values.get((base + i) % 2**32, 0) for i in range(length)]

    def write(self, address: int, octets: list[int]) -> None:
        base = address % MEMORY_SIZE
        for i, octet in enumerate(octets):
            # store rows define the reduction themselves (store_u8: reg mod 2^8);
            # the mask is that same reduction, idempotent at the dict boundary.
            self.values[(base + i) % 2**32] = octet & 0xFF


@dataclass
class PVMState:
    program: Program
    registers: list
    memory: Memory
    gas: int
    instruction_register: int


# GP
def single_step_state_transition(
    program: Program,
    i: int,
    gas: int,
    registers: list[int],
    memory: Memory,
):
    # only 13 registers
    # panic when an index of RAM below 2^16 is required
    # otherwise fault if RAM is inaccessible
    # default case
    # memory and registors don't change
    instr_opcode = program.instruction_data[i]
    if (
        not program.opcode_bitmask[i]
        or instr_opcode not in INSTRUCTION_TYPE_AND_METHOD.keys()
    ):
        return "err"  # TODO: handle error
    instr_type, instr_method = INSTRUCTION_TYPE_AND_METHOD[instr_opcode]
    skip_length = skip_to_next_instruction(i, program.opcode_bitmask)
    if instr_type == InstructionTypes.NO_ARGS:
        # TODO: handle the return
        instr_method()
    elif instr_type == InstructionTypes.ONE_IMM:
        # TODO: handle this when understanding how host functions work
        pass
    elif instr_type == InstructionTypes.ONE_REG_ONE_EXT_IMM:
        r_A = min(12, program.instruction_data[i + 1] % 16)
        value = util.decode_fixed(program.instruction_data[i + 2 : i + 8], 8)
        instr_method(registers, r_A, value)
    elif instr_type == InstructionTypes.TWO_IMMS:
        imm1_len = min(4, program.instruction_data[i + 1] % 8)
        imm2_len = max(4, skip_length - imm1_len - 1)
        imm1 = signed_extension(
            util.decode_fixed(
                program.instruction_data[i + 2 : i + 2 + imm1_len], imm1_len
            ),
            imm1_len,
        )
        imm2 = signed_extension(
            util.decode_fixed(
                program.instruction_data[
                    i + 2 + imm1_len : i + 2 + imm1_len + imm2_len
                ],
                imm2_len,
            ),
            imm2_len,
        )
        instr_method(memory, imm1, imm2)
    elif instr_type == InstructionTypes.ONE_OFFSET:
        offset_len = min(4, skip_length)
        offset = i + to_signed(
            util.decode_fixed(
                program.instruction_data[i + 1 : i + 1 + offset_len], offset_len
            ),
            offset_len,
        )
        # TODO: This isn't implemented yet, looks like a host function
        instr_method(offset, True)
    elif instr_type == InstructionTypes.ONE_REG_ONE_IMM:
        reg_addr = min(12, program.instruction_data[i + 1] % 16)
        imm_len = min(4, max(0, skip_length - 1))
        imm = signed_extension(
            util.decode_fixed(
                program.instruction_data[i + 1 : i + 2 + imm_len], imm_len
            ),
            imm_len,
        )
        if instr_opcode == 50:
            instr_method(registers[reg_addr], imm)
        elif instr_opcode == 51:
            instr_method(registers, reg_addr, imm)
        else:
            instr_method(registers, reg_addr, memory, imm)
    elif instr_type == InstructionTypes.ONE_REG_TWO_IMM:
        reg_addr = min(12, program.instruction_data[i + 1] % 16)
        imm1_len = min(4, program.instruction_data[i + 1] // 16 % 8)
        imm1 = signed_extension(
            util.decode_fixed(
                program.instruction_data[i + 2 : i + 2 + imm1_len], imm1_len
            ),
            imm1_len,
        )
        imm2_len = min(4, max(0, skip_length - imm1_len - 1))
        imm2 = signed_extension(
            util.decode_fixed(
                program.instruction_data[
                    i + 2 + imm1_len : i + 2 + imm1_len + imm2_len
                ],
                imm2_len,
            ),
            imm2_len,
        )
        instr_method(registers, reg_addr, memory, imm1, imm2)
        registers[reg_addr]
    i = i + 1 + skip_length
    gas = gas - 1  # gas cost per single step
    # output = continue
    pass


# A.10 - A.11 signed transitions
def to_signed(x: int, n: int):
    if x < 2 ** (8 * n - 1):
        return x
    return x - 2 ** (8 * n)


def to_unsigned(x: int, n: int):
    return (2 ** (8 * n) + x) % 2 ** (8 * n)


# A.16
def signed_extension(x: int, n: int):
    return x + (x // 2 ** (8 * n - 1)) * (2**64 - 2 ** (8 * n))


# A.17
def branch(i: int, branch_i: int, condition: bool):
    if not condition:
        return "resume", i
    elif condition:
        return "panic", i
    else:
        return "resume", branch_i


# A.18
def dynamic_jump():
    pass


# GP A.2
def deblob(program: bytes) -> Program | str:
    d = util.Decoder(program)
    jump_table_length = d.decode_compact()
    jump_table_width = d.u8()
    instruction_data_length = d.decode_compact()
    jump_table = [d.decode_fixed(jump_table_width) for _ in range(jump_table_length)]
    instruction_data = d.take(instruction_data_length)
    opcode_bitmask = d.decode_bits(instruction_data_length)
    try:
        d.finish()
        return Program(
            instruction_data=instruction_data,
            jump_table=jump_table,
            opcode_bitmask=opcode_bitmask,
        )
    except Exception as e:
        return "panic"


# GP A.3
def skip_to_next_instruction(i: int, opcode_bitmask: list[bool]) -> int:
    if i >= len(opcode_bitmask):
        return 0
    else:
        for j in range(0, MAX_INSTRUCTION_LENGTH):
            if opcode_bitmask[i + j + 1]:
                break
        return j


# GP A.1
def invoke_pvm(
    program_bytes: bytes, register_val: int, gas: int, registers: list[int], memory
):
    program = deblob(program_bytes)
    out = single_step_state_transition(program, register_val, gas, registers, memory)
    if out.result == "continue":
        return invoke_pvm(program_bytes, out)
    elif out.result == "out_of_gas":  # doesn't exist in GP 0.8
        return (out_of_gas, register_val, out, registers, memory)
    elif out.result == "panic" or out.result == "halt":
        return (out, 0)
    else:
        pass
