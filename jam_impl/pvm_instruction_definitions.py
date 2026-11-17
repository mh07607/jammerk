import jam_impl.util as util
from jam_impl.pvm import (
    Memory,
    PVMState,
    MEMORY_SIZE,
    branch,
    dynamic_jump,
    round_toward_zero,
    signed_extension,
    smod,
    to_bits,
    to_bits_reversed,
    to_signed,
    to_unsigned,
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
# TODO:
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


# 101 - 111
def move_reg(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = reg_addr


# TODO:
def sbrk(registers: list, dest_reg_addr: int, reg_addr: int):
    pass


def count_set_bits_64(registers: list, dest_reg_addr: int, reg_addr: int):
    bits = to_bits(registers[reg_addr], 8)
    registers[dest_reg_addr] = sum(bits)


def count_set_bits_32(registers: list, dest_reg_addr: int, reg_addr: int):
    bits = to_bits(registers[reg_addr] % 2**32, 4)
    registers[dest_reg_addr] = sum(bits)


def leading_zero_bits_64(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = 64 - registers[reg_addr].bit_length()


def leading_zero_bits_32(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = 32 - (registers[reg_addr] % 2**32).bit_length()


def trailing_zero_bits_64(registers: list, dest_reg_addr: int, reg_addr: int):
    x = registers[reg_addr]
    registers[dest_reg_addr] = 64 if x == 0 else (x & -x).bit_length() - 1


def trailing_zero_bits_32(registers: list, dest_reg_addr: int, reg_addr: int):
    x = registers[reg_addr] % 2**32
    registers[dest_reg_addr] = 32 if x == 0 else (x & -x).bit_length() - 1


def sign_extend_8(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = to_unsigned(to_signed(registers[reg_addr] % 2**8, 1), 8)


def sign_extend_16(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = to_unsigned(to_signed(registers[reg_addr] % 2**16, 2), 8)


def zero_extend_16(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = registers[reg_addr] % 2**16


def reverse_bytes(registers: list, dest_reg_addr: int, reg_addr: int):
    registers[dest_reg_addr] = int.from_bytes(
        registers[reg_addr].to_bytes(8, byteorder="big"), byteorder="little"
    )


# 120 - 161
def store_ind_u8(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    memory.write(registers[reg2_addr] + imm, [registers[reg1_addr] % 2**8])


def store_ind_u16(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    memory.write(
        registers[reg2_addr] + imm, list(util.u16(registers[reg1_addr] % 2**16))
    )


def store_ind_u32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    memory.write(
        registers[reg2_addr] + imm, list(util.u32(registers[reg1_addr] % 2**32))
    )


def store_ind_u64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    memory.write(
        registers[reg2_addr] + imm, list(util.u64(registers[reg1_addr] % 2**64))
    )


def load_ind_u8(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = util.decode_fixed(
        bytes(memory.read(registers[reg2_addr] + imm, 1)), 1
    )


def load_ind_i8(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(
            util.decode_fixed(bytes(memory.read(registers[reg2_addr] + imm, 1)), 1), 1
        ),
        8,
    )


def load_ind_u16(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = util.decode_fixed(
        bytes(memory.read(registers[reg2_addr] + imm, 2)), 2
    )


def load_ind_i16(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(
            util.decode_fixed(bytes(memory.read(registers[reg2_addr] + imm, 2)), 2), 2
        ),
        8,
    )


def load_ind_u32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = util.decode_fixed(
        bytes(memory.read(registers[reg2_addr] + imm, 4)), 4
    )


def load_ind_i32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(
            util.decode_fixed(bytes(memory.read(registers[reg2_addr] + imm, 4)), 4), 4
        ),
        8,
    )


def load_ind_u64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = util.decode_fixed(
        bytes(memory.read(registers[reg2_addr] + imm, 8)), 8
    )


def add_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension((registers[reg2_addr] + imm) % 2**32, 4)


def and_imm(registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int):
    registers[reg1_addr] = registers[reg2_addr] & imm


def xor_imm(registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int):
    registers[reg1_addr] = registers[reg2_addr] ^ imm


def or_imm(registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int):
    registers[reg1_addr] = registers[reg2_addr] | imm


def mul_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension((registers[reg2_addr] * imm) % 2**32, 4)


def set_lt_u_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = registers[reg2_addr] < imm


def set_lt_s_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_signed(registers[reg2_addr], 8) < to_signed(imm, 8)


def shlo_l_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (registers[reg2_addr] * 2 ** (imm % 32)) % 2**32, 4
    )


def shlo_r_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (registers[reg2_addr] % 2**32) // 2 ** (imm % 32), 4
    )


def shar_r_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(registers[reg2_addr] % 2**32, 4) // 2 ** (imm % 32), 8
    )


def neg_add_imm_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (imm + 2**32 - registers[reg2_addr]) % 2**32, 4
    )


def set_gt_u_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = registers[reg2_addr] > imm


def set_gt_s_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_signed(registers[reg2_addr], 8) > to_signed(imm, 8)


def shlo_l_imm_alt_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (imm * 2 ** (registers[reg2_addr] % 32) % 2**32), 4
    )


def shlo_r_imm_alt_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (imm % 2**32) // 2 ** (registers[reg2_addr] % 32), 4
    )


def shar_r_imm_alt_32(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(imm % 2**32, 4) // 2 ** (registers[reg2_addr] % 32), 8
    )


def cmov_iz_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = imm if registers[reg2_addr] == 0 else registers[reg1_addr]


def cmov_nz_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = imm if registers[reg2_addr] != 0 else registers[reg1_addr]


def add_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = (registers[reg2_addr] + imm) % 2**64


def mul_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = (registers[reg2_addr] * imm) % 2**64


def shlo_l_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(
        (registers[reg2_addr] * 2 ** (imm % 64)) % 2**64, 8
    )


def shlo_r_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = signed_extension(registers[reg2_addr] // 2 ** (imm % 64), 8)


def shar_r_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(registers[reg2_addr], 8) // 2 ** (imm % 64), 8
    )


def neg_add_imm_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = (imm + 2**64 - registers[reg2_addr]) % 2**64


def shlo_l_imm_alt_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = imm * 2 ** (registers[reg2_addr] % 64) % 2**64


def shlo_r_imm_alt_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = imm // 2 ** (registers[reg2_addr] % 64)


def shar_r_imm_alt_64(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    registers[reg1_addr] = to_unsigned(
        to_signed(imm, 8) // 2 ** (registers[reg2_addr] % 64), 8
    )


def rot_r_64_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    reg2_octets = to_bits(registers[reg2_addr], 8)
    out_octets = [0] * 64
    for i in range(64):
        out_octets[i] = reg2_octets[(i + imm) % 64]
    registers[reg1_addr] = int.from_bytes(bytes(out_octets))


def rot_r_64_imm_alt(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    imm_octets = to_bits(imm, 8)
    out_octets = [0] * 64
    reg2 = registers[reg2_addr]
    for i in range(64):
        out_octets[i] = imm_octets[(i + reg2) % 64]
    registers[reg1_addr] = int.from_bytes(bytes(out_octets))


def rot_r_32_imm(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    reg2_octets = to_bits(registers[reg2_addr], 4)
    out_octets = [0] * 32
    for i in range(32):
        out_octets[i] = reg2_octets[(i + imm) % 32]
    registers[reg1_addr] = signed_extension(int.from_bytes(bytes(out_octets)), 4)


def rot_r_32_imm_alt(
    registers: list, reg1_addr: int, reg2_addr: int, memory: Memory, imm: int
):
    imm_octets = to_bits(imm, 4)
    out_octets = [0] * 32
    reg2 = registers[reg2_addr]
    for i in range(32):
        out_octets[i] = imm_octets[(i + reg2) % 32]
    registers[reg1_addr] = signed_extension(int.from_bytes(bytes(out_octets)), 4)


# 170 - 175
def branch_eq(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(i, offset, registers[reg1_addr] == registers[reg2_addr])


def branch_ne(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(i, offset, registers[reg1_addr] != registers[reg2_addr])


def branch_lt_u(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(i, offset, registers[reg1_addr] < registers[reg2_addr])


def branch_lt_s(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(
        i,
        offset,
        to_signed(registers[reg1_addr], 8) < to_signed(registers[reg2_addr], 8),
    )


def branch_ge_u(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(i, offset, registers[reg1_addr] >= registers[reg2_addr])


def branch_ge_s(i: int, registers: list, reg1_addr: int, reg2_addr: int, offset: int):
    return branch(
        i,
        offset,
        to_signed(registers[reg1_addr], 8) >= to_signed(registers[reg2_addr], 8),
    )


# 180
def load_imm_jump_ind(
    i: int,
    jump_table: list[int],
    basic_block_indices: list[int],
    registers: list,
    reg1_addr: int,
    reg2_addr: int,
    imm1: int,
    imm2: int,
):
    registers[reg1_addr] = imm1
    return dynamic_jump(
        i, jump_table, basic_block_indices, (registers[reg2_addr] + imm2) % 2**32
    )


# 190 - 230
def add_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = signed_extension(
        (registers[regA_addr] + registers[regB_addr]) % 2**32, 4
    )


def sub_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    # this trick might be redundant in python, just do the same
    # as add_32
    # registers[regD_addr] = signed_extension(
    #     (registers[regA_addr] + 2**32 - (registers[regB_addr] % 2**32)) % 2**32, 4
    # )
    registers[regD_addr] = signed_extension(
        (registers[regA_addr] - registers[regB_addr]) % 2**32, 4
    )


def mul_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = signed_extension(
        (registers[regA_addr] * registers[regB_addr]) % 2**32, 4
    )


def div_u_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    if registers[regB_addr] % 2**32 == 0:
        registers[regD_addr] = 2**64 - 1
    else:
        registers[regD_addr] = signed_extension(
            (registers[regA_addr] % 2**32) // (registers[regB_addr] % 2**32), 4
        )


def div_s_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    a = to_signed(registers[regA_addr] % 2**32, 4)
    b = to_signed(registers[regA_addr] % 2**32, 4)
    if b == 0:
        registers[regD_addr] = 2**64 - 1
    elif a == -(2**31) and b == -1:
        registers[regD_addr] = to_unsigned(a, 8)
    else:
        registers[regD_addr] = to_unsigned(round_toward_zero(a / b), 8)


def rem_u_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    if registers[regB_addr] % 2**32 == 0:
        registers[regD_addr] = signed_extension(registers[regA_addr] % 2**32, 4)
    else:
        registers[regD_addr] = signed_extension(
            (registers[regA_addr] % 2**32) % (registers[regB_addr] % 2**32), 4
        )


def rem_s_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    a = to_signed(registers[regA_addr] % 2**32, 4)
    b = to_signed(registers[regA_addr] % 2**32, 4)
    if a == -(2**31) and b == -1:
        registers[regD_addr] = 0
    else:
        registers[regD_addr] = to_unsigned(smod(a, b), 4)


def shlo_l_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = signed_extension(
        (registers[regA_addr] * 2 ** (registers[regB_addr] % 32)) * 2**32, 4
    )


def shlo_r_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = signed_extension(
        (registers[regA_addr] % 2**32) // 2 ** (registers[regB_addr] % 32), 4
    )


def shar_r_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        to_signed(registers[regA_addr] % 2**32, 4) // 2 ** (registers[regB_addr] % 32),
        8,
    )


def add_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (registers[regA_addr] + registers[regB_addr]) % 2**64


def sub_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (registers[regA_addr] + 2**64 - registers[regB_addr]) % 2**64


def mul_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (registers[regA_addr] * registers[regB_addr]) % 2**64


def div_u_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    if registers[regB_addr] == 0:
        registers[regD_addr] = 2**64 - 1
    else:
        registers[regD_addr] = registers[regA_addr] // registers[regB_addr]


def div_s_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    a = to_signed(registers[regA_addr], 8)
    b = to_signed(registers[regB_addr], 8)
    if registers[regB_addr] == 0:
        registers[regD_addr] = 2**64 - 1
    elif a == -(2**63) and b == -1:
        registers[regD_addr] = registers[regA_addr]
    else:
        registers[regD_addr] = to_unsigned(round_toward_zero(a / b), 8)


def rem_u_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    if registers[regB_addr] == 0:
        registers[regD_addr] = registers[regA_addr]
    else:
        registers[regD_addr] = registers[regA_addr] % registers[regB_addr]


def rem_s_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    a = to_signed(registers[regA_addr], 8)
    b = to_signed(registers[regB_addr], 8)
    if a == -(2**63) and b == -1:
        registers[regD_addr] = 0
    else:
        registers[regD_addr] = to_unsigned(smod(a, b), 8)


def shlo_l_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (
        registers[regA_addr] * 2 ** (registers[regB_addr] % 64)
    ) % 2**64


def shlo_r_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] // 2 ** (registers[regB_addr] % 64)


def shar_r_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        to_signed(registers[regA_addr], 8) // 2 ** (registers[regB_addr] % 64), 8
    )


def and_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] & registers[regB_addr]


def xor_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] ^ registers[regB_addr]


def or_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] | registers[regB_addr]


def mul_upper_s_s(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        (to_signed(registers[regA_addr], 8) * to_signed(registers[regB_addr], 8))
        // 2**64,
        8,
    )


def mul_upper_u_u(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (registers[regA_addr] * registers[regB_addr]) // 2**64


def mul_upper_s_u(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        (to_signed(registers[regA_addr], 8) * registers[regB_addr]) // 2**64, 8
    )


def set_lt_u(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] < registers[regB_addr]


def set_lt_s(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_signed(registers[regA_addr], 8) < to_signed(
        registers[regB_addr], 8
    )


def cmov_iz(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (
        registers[regA_addr] if registers[regB_addr] == 0 else registers[regD_addr]
    )


def cmov_nz(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = (
        registers[regA_addr] if registers[regB_addr] != 0 else registers[regD_addr]
    )


def rot_l_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    regA_octets = to_bits(registers[regA_addr], 8)
    regB = registers[regB_addr]
    out_octets = [0] * 64
    for i in range(64):
        out_octets[(i + regB) % 64] = regA_octets[i]
    registers[regD_addr] = int.from_bytes(bytes(out_octets))


def rot_l_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    regA_octets = to_bits(registers[regA_addr], 8)
    regB = registers[regB_addr]
    out_octets = [0] * 32
    for i in range(32):
        out_octets[(i + regB) % 32] = regA_octets[i]
    registers[regD_addr] = signed_extension(int.from_bytes(bytes(out_octets)), 4)


def rot_r_64(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    regA_octets = to_bits(registers[regA_addr], 8)
    regB = registers[regB_addr]
    out_octets = [0] * 64
    for i in range(64):
        out_octets[i] = regA_octets[(i + regB) % 64]
    registers[regD_addr] = int.from_bytes(bytes(out_octets))


def rot_r_32(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    regA_octets = to_bits(registers[regA_addr], 8)
    regB = registers[regB_addr]
    out_octets = [0] * 32
    for i in range(32):
        out_octets[i] = regA_octets[(i + regB) % 32]
    registers[regD_addr] = signed_extension(int.from_bytes(bytes(out_octets)), 4)


def and_inv(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] & ~registers[regB_addr]


def or_inv(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = registers[regA_addr] | ~registers[regB_addr]


def xnor(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = ~(registers[regA_addr] ^ registers[regB_addr])


def max_s(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        max(to_signed(registers[regA_addr], 8), to_signed(registers[regB_addr], 8)), 8
    )


def max_u(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = max(registers[regA_addr], registers[regB_addr])


def min_s(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = to_unsigned(
        min(to_signed(registers[regA_addr], 8), to_signed(registers[regB_addr], 8)), 8
    )


def min_u(registers: list[int], regA_addr: int, regB_addr: int, regD_addr: int):
    registers[regD_addr] = min(registers[regA_addr], registers[regB_addr])
