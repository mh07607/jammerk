from collections.abc import Callable
from dataclasses import dataclass

import jam_impl.util as util

MIN_ADDRESS = 2**16
MAX_INSTRUCTION_LENGTH = 24

INSTRUCTION_TABLE: dict[int, Callable] = {
    0b00000000: 
}

@dataclass
class Program:
    instruction_data: bytes
    jump_table: list[int]
    opcode_bitmask: list[int]

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
        page = (address % 2**32) >> 12        # cyclic subscript: wraps at 2^32
        return self.access.get(page, None)    # 'W' | 'R' | None (None = inaccessible)

    def readable(self, start: int, length: int) -> bool:
        return all(self._page(start + i) is not None for i in range(length))

    def writable(self, start: int, length: int) -> bool:
        return all(self._page(start + i) == 'W' for i in range(length))

    def read(self, address: int, length: int) -> list[int]:
        base = address % 2**32
        return [self.values.get((base + i) % 2**32, 0) for i in range(length)]

    def write(self, address: int, octets: list[int]) -> None:
        base = address % 2**32
        for i, octet in enumerate(octets):
            # store rows define the reduction themselves (store_u8: reg mod 2^8);
            # the mask is that same reduction, idempotent at the dict boundary.
            self.values[(base + i) % 2**32] = octet & 0xFF


# GP
def single_step_state_transition(instruction_data: bytes, opcode_bitmask_bitmask: bytes, jump_table: list[int], register_val: int, gas: int, registers: list[int], memory: Memory):
    # only 13 registers
    # panic when an index of RAM below 2^16 is required
    # otherwise fault if RAM is inaccessible
    # default case
    # memory and registors don't change
    register_val = register_val + 1 + skip_to_next_instruction(register_val, opcode_bitmask)
    gas = gas - 1 # gas cost per single step
    # output = continue
    pass


# A.17
def branch():
    pass


# A.18
def dynamic_jump():
    pass


# GP A.2
def deblob(program: bytes) -> Program | str:
    d = util.Decoder(program)    
    jump_table_length = d.decode_compact()
    jump_table_width = d.u8()
    instruction_data_length = d.decode_compact()
    jump_table = [ d.decode_fixed(jump_table_width) for _ in range(jump_table_length) ]
    instruction_data = d.take(instruction_data_length)
    opcode_bitmask = d.decode_bits(instruction_data_length)
    try:
        d.finish()
        return Program(
            instruction_data=instruction_data,
            jump_table=jump_table,
            opcode_bitmask=opcode_bitmask
        )
    except Exception as e:
        return "panic"


#GP A.3
def skip_to_next_instruction(i: int, opcode_bitmask: list[int]) -> int:
    if j >= len(opcode_bitmask):
        j = 0
    else:
        for j in range(0, MAX_INSTRUCTION_LENGTH):
            if opcode_bitmask[i+j+1]:
                break
    return j


# GP A.1
def invoke_pvm(program: bytes, register_val: int, gas: int, registers: list[int], memory):
    code, k, j = deblob(program)
    out = single_step_state_transition(code, k, j, register_val, gas, registers, memory)
    if out.result == "continue":
        return invoke_pvm(program, out)
    elif out.result == "out_of_gas": # doesn't exist in GP 0.8
        return (out_of_gas, register_val, out, registers, memory)
    elif out.result == "panic" or out.result == "halt":
        return (out, 0)
    else:
        pass