""" INSPIRED FROM jamtestvectors/trie/merkle.py """

import jam_impl.util as util

def leaf(key: bytes, value: bytes):
    value_length = len(value)
    if value_length <= 32:
        first = (128 | value_length).to_bytes()
        return first + key + value + b'\0' * (32 - value_length)
    else:
        hashed_val = util.hash_via_blake2b(value)
        return int('11000000', 2).to_bytes() + key + hashed_val

def branch(l: bytes, r: bytes) -> bytes:    
    return (l[0] & 127).to_bytes() + l[1:] + r

def check_flag(key: bytes, i: int) -> bool:
    byte_number = i // 8
    flag_byte = key[byte_number]
    bit_index = 7 - i % 8
    mask = 1 << bit_index    
    return flag_byte & mask != 0

def merklization(state_key_vals, i = 0) -> bytes:
    if len(state_key_vals) == 0:
        return util.ZERO_HASH
    elif len(state_key_vals) == 1:
        encoded = leaf(*state_key_vals[0])
    else:
        l = []
        r = []
        for key, val in state_key_vals:
            if check_flag(key, i) != 0:
                r.append((key, val))
            else:
                l.append((key, val))    
        encoded = branch(merklization(l, i+1), merklization(r, i+1))
    assert len(encoded) == 64, f"{len(encoded)}"
    return util.hash_via_blake2b(encoded)

if __name__ == "__main__":
    pass