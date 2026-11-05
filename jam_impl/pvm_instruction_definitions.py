import jam_impl.util as util
from jam_impl.pvm import Memory, PVMState


def handle_instr_with_one_reg_and_one_imm(
    i: int, instruction_data: bytes, state: PVMState
):
    r_A = min(12, instruction_data[i + 1] % 16)
    value = util.decode_fixed(instruction_data[i + 2 : i + 8], 8)
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
