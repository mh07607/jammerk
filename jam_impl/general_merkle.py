from collections.abc import Callable
import math

import jam_impl.util as util


X_NODE = b'node'
X_PEAK = b'peak'


def node(blobs: list[bytes], hash_function: Callable):
    if len(blobs) == 0:
        return b'\0' * util.HASH_LEN_IN_BYTES
    if len(blobs) == 1:
        return blobs[0]
    mid = math.ceil(len(blobs) / 2)
    return hash_function(X_NODE + node(blobs[:mid], hash_function) + node(blobs[mid:], hash_function))


def trace(blobs: list[bytes], i: int, hash_function: Callable):
    if len(blobs) <= 1:
        return []
    mid = math.ceil(len(blobs) / 2)    
    if not i < mid:
        trace_blob = blob[mid:]
        n = node(blob[:mid], hash_function)
    else:
        trace_blob = blob[:mid]
        n = node(blob[mid:], hash_function)        
    new_index = i - 0 if i < mid else mid
    return [n] + trace(trace_blob, new_index, hash_function)


def well_balanced_merkle(blobs: list[bytes], hash_function: Callable = util.hash_via_blake2b) -> bytes:
    if len(blobs) == 1:
        return hash_function[blobs[0]]
    return node(blobs, hash_function)


def append_to_mmr_recursive(peaks: list[bytes | None], item: bytes, n: int, hash_function: Callable):
    if n >= len(peaks):
        peaks.extend([item])    
        return peaks
    elif n < len(peaks) and peaks[n] == None:
        peaks[n] = item
        return peaks
    else:    
        peak = peaks[n]
        peaks[n] = None
        return append_to_mmr_recursive(peaks, hash_function(peak + item), n + 1, hash_function)


def append_to_mmr(peaks: list[bytes | None], item: bytes, hash_function: Callable) -> list[bytes | None]:
    return append_to_mmr_recursive(peaks=peaks, item=item, n=0, hash_function=hash_function)


def mmr_superpeak_recursive(peaks: list[bytes]):
    if len(peaks) <= 0:
        return b'\0' * util.HASH_LEN_IN_BYTES
    if len(peaks) == 1:
        return peaks[0]
    return util.hash_via_keccak256(X_PEAK + mmr_superpeak_recursive(peaks[:-1]) + peaks[-1])


def mmr_superpeak(peaks: list[bytes | None]):
    filtered_peaks = [ peak for peak in peaks if peak is not None ]
    return mmr_superpeak_recursive(filtered_peaks)