""" INSPIRED FROM jamtestvectors/trie/merkle.py """

import jam_impl.util as util

def leaf(key: bytes, value: bytes):
    value_length = len(v)
    if value_length <= 32:
        0b10 + util.u8(value_length)[2:] + key + value + b'\x00' * (32 - value_length)
    else:
        hashed_val = util.hash_via_blake2b(value)
        0b11000000 + key + hashed_val

def branch(l: bytes, r: bytes) -> bytes:
    return util.u8(0) + l[1:] + r

def check_flag(key: bytes, i: int) -> bool:
    byte_number = i // 8
    flag_byte = key[byte_number]
    bit_index = 7 - i % 8
    mask = 1 << bit_index    
    return flag_byte & mask != 0

def merklization(state_key_vals, i = 0) -> bytes:
    if len(state_key_vals) == 0:
        return util.ZERO_HASH
    if len(state_key_vals) == 1:
        return leaf(*state_key_vals[0])
    else:
        l = []
        r = []
        for key, val in state_key_vals:
            if check_flag(key, i) != 0:
                r.append((key, val))
            else:
                l.append((key_val))
    return branch(merklization(l, i+1), merklization(r, i+1))

if __name__ == "__main__":
    pass