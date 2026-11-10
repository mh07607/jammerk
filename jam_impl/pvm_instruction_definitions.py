import jam_impl.util as util
from jam_impl.pvm import (
    Memory,
    PVMState,
    MEMORY_SIZE,
    branch,
    signed_extension,
    to_signed,
)


def handle_instr_with_one_reg_and_one_imm(
    i: int, instruction_data: bytes, state: PVMState
):
    r_A = min(12, instruction_data[i + 1] % 16)
    value = util.decode_fixed(instruction_data[i + 2 : i + 2 + 8], 8)
    load_imm_64(state.registers, r_A, value)


def trap():
    return "panic"


def fallthrough():
    pass


def ecalli():
    # TODO: host function to be called here
    pass


def load_imm_64(registers: list, r_A: int, value: int):
    registers[r_A] = value


def store_imm_u8(memory: Memory, imm1: int, imm2: int):
    memory.write(imm1, list(util.u8(imm1 % 2**8)))


def store_imm_u16(memory: Memory, imm1: int, imm2: int):
    memory.write(imm1, list(util.u16(imm2 % 2**16)))


def store_imm_u32(memory: Memory, imm1: int, imm2: int):
    memory.write(imm1, list(util.u32(imm2 % 2**32)))


def store_imm_u64(memory: Memory, imm1: int, imm2: int):
    # I wonder why we aren't applying modulus here
    memory.write(imm1, list(util.u64(imm2)))


def jump(i: int, imm: int):
    return branch(i, imm, True)


# 50 - 62
def jump_ind(reg_addr: int, imm: int):
    pass


def load_imm(registers: list, reg_addr: int, imm: int):
    registers[reg_addr] = imm


def load_u8(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = util.decode_fixed(bytes(memory.read(mem_addr, 1)), 1)


def load_i8(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = signed_extension(
        util.decode_fixed(bytes(memory.read(mem_addr, 1)), 1), 1
    )


def load_u16(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = util.decode_fixed(bytes(memory.read(mem_addr, 2)), 2)


def load_i16(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = signed_extension(
        util.decode_fixed(bytes(memory.read(mem_addr, 2)), 2), 2
    )


def load_u32(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = util.decode_fixed(bytes(memory.read(mem_addr, 4)), 4)


def load_i32(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = signed_extension(
        util.decode_fixed(bytes(memory.read(mem_addr, 4)), 4), 4
    )


def load_u64(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    registers[reg_addr] = util.decode_fixed(bytes(memory.read(mem_addr, 8)), 8)


def store_u8(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    memory.write(mem_addr, [registers[reg_addr] % 2**8])


def store_u16(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    memory.write(mem_addr, list(util.u16(registers[reg_addr] % 2**16)))


def store_u32(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    memory.write(mem_addr, list(util.u32(registers[reg_addr] % 2**32)))


def store_u64(registers: list, reg_addr: int, memory: Memory, mem_addr: int):
    memory.write(mem_addr, list(util.u64(registers[reg_addr] % 2**64)))


# 70 - 73
def store_imm_ind_u8(
    registers: list, reg_addr: int, memory: Memory, imm1: int, imm2: int
):
    memory.write(reg_addr + imm1, [imm2 % 2**8])


def store_imm_ind_u16(
    registers: list, reg_addr: int, memory: Memory, imm1: int, imm2: int
):
    memory.write(reg_addr + imm1, list(util.u16(imm2 % 2**16)))


def store_imm_ind_u32(
    registers: list, reg_addr: int, memory: Memory, imm1: int, imm2: int
):
    memory.write(reg_addr + imm1, list(util.u32(imm2 % 2**32)))


def store_imm_ind_u64(
    registers: list, reg_addr: int, memory: Memory, imm1: int, imm2: int
):
    memory.write(reg_addr + imm1, list(util.u32(imm2 % 2**64)))


def load_imm_jump(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    registers[reg_addr] = imm
    return branch(i, offset, True)


def branch_eq_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] == imm)


def branch_ne_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] != imm)


def branch_lt_u_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] < imm)


def branch_le_u_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] <= imm)


def branch_ge_u_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] >= imm)


def branch_gt_u_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, registers[reg_addr] > imm)


def branch_lt_s_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, to_signed(registers[reg_addr], 8) < to_signed(imm, 8))


def branch_le_s_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, to_signed(registers[reg_addr], 8) <= to_signed(imm, 8))


def branch_ge_s_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, to_signed(registers[reg_addr], 8) >= to_signed(imm, 8))


def branch_gt_s_imm(i: int, offset: int, registers: list, reg_addr: int, imm: int):
    return branch(i, offset, to_signed(registers[reg_addr], 8) > to_signed(imm, 8))
