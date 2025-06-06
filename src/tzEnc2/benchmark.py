# tzEnc2/benchmark.py

import os
import math
import time
import random
import string
import matplotlib.pyplot as plt
import pandas as pd
from multiprocessing import shared_memory
from concurrent.futures import ProcessPoolExecutor

# --- STUBS: replace these with your real imports from tzEnc2 ---
def collect_chars_by_indexes(blocks, indexes):
    return list(string.ascii_uppercase * 10)

def pad_character_list_to_grid(expanded_character_list, grid_size):
    n = grid_size**3
    padded = expanded_character_list[:]
    while len(padded) < n:
        padded.extend(expanded_character_list)
    return padded[:n]

def calculate_minimum_grid_size(length, redundancy):
    return math.ceil((length * redundancy) ** (1/3))

def shuffle_list(character_list, seed, t):
    random.seed(seed + t)
    lst = character_list[:]
    random.shuffle(lst)
    return lst

def get_coord_math(idx, ch, grid_size, grid_seed, t):
    time.sleep(0.0005)  # simulate ~0.5 ms of work
    return idx, [0, 0, 0]

def get_char_math(idx, coords, grid_size, grid_seed, t):
    time.sleep(0.001)   # simulate ~1 ms of work
    return idx, "A"

CHARACTER_BLOCKS = []
CHARACTER_SET = set(string.ascii_uppercase)

def _unpack_get_coord(arg_tuple):
    return get_coord_math(*arg_tuple)

def _unpack_get_char(arg_tuple):
    return get_char_math(*arg_tuple)
# --- STUBS END ---

# This must be at top level for Windows to pickle it:
def init_worker_shared(shm_name: str, size: int):
    """
    Worker initializer for decryption: attach to shared memory and reconstruct a global
    PADDING_LIST exactly as your real code does. Because this is top‐level, it can be pickled.
    """
    global PADDING_LIST, _worker_shm
    _worker_shm = shared_memory.SharedMemory(name=shm_name)
    raw = _worker_shm.buf[:size]
    decoded = bytes(raw).decode("utf-8")
    PADDING_LIST = list(decoded)
    # We do NOT call _worker_shm.close() here; let the child hold it until exit.

def build_shared_padded_list(blocks, redundancy=1):
    """
    Build a “padded list” in shared memory in the same way your application does,
    then return (SharedMemory object, size_in_bytes, grid_size).
    """
    expanded = collect_chars_by_indexes(blocks, [])
    grid_size = calculate_minimum_grid_size(len(expanded), redundancy)
    padded = pad_character_list_to_grid(expanded, grid_size)
    joined = "".join(padded)
    utf8_bytes = joined.encode("utf-8")
    shm = shared_memory.SharedMemory(create=True, size=len(utf8_bytes))
    shm.buf[: len(utf8_bytes)] = utf8_bytes
    return shm, len(utf8_bytes), grid_size

def cleanup_shm(shm):
    shm.close()
    shm.unlink()

def benchmark_worker_function(unpack_fn, tasks, max_workers, chunksize, initializer=None, initargs=()):
    """
    Run a given unpack_fn (either _unpack_get_coord or _unpack_get_char) on the list of tasks
    using ProcessPoolExecutor with `max_workers` and `chunksize`. Measures total elapsed time.
    """
    start = time.perf_counter()
    with ProcessPoolExecutor(
        max_workers=max_workers,
        initializer=initializer,
        initargs=initargs
    ) as executor:
        for _ in executor.map(unpack_fn, tasks, chunksize=chunksize):
            pass
    return time.perf_counter() - start

def main():
    # 1) Create a sample message of length 10k for “encryption”
    message_length = 10000
    sample_message = "".join(random.choices(list(CHARACTER_SET), k=message_length))

    # 2) Build shared padded list for encryption/decryption
    shm_enc, size_enc, grid_size = build_shared_padded_list(CHARACTER_BLOCKS, redundancy=1)
    grid_seed = 12345
    start_time = 1000
    time_increment = 1

    # 3) Build “encryption tasks” = (idx, ch, grid_size, grid_seed, t)
    encrypt_tasks = []
    for i, ch in enumerate(sample_message):
        t = start_time + i * time_increment
        encrypt_tasks.append((i, ch, grid_size, grid_seed, t))

    # 4) Run single-threaded “encryption” to produce dummy ciphertext
    cipher_text = [get_coord_math(*task)[1] for task in encrypt_tasks]

    # 5) Build “decryption tasks” = (idx, coords, grid_size, grid_seed, t)
    decrypt_tasks = []
    for i, coords in enumerate(cipher_text):
        t = start_time + i * time_increment
        decrypt_tasks.append((i, coords, grid_size, grid_seed, t))

    # 6) Only benchmark the first 2000 tasks of each for speed
    enc_subset = encrypt_tasks[:2000]
    dec_subset = decrypt_tasks[:2000]

    # 7) Grid: workers 1..20, chunksize powers of two up to 1024
    workers_list = list(range(1, 21))              # 1 through 20
    chunksize_list = [2**i for i in range(0, 11)]   # 1,2,4,8,...,1024

    results = []
    for worker_count in workers_list:
        for chunksize in chunksize_list:
            # Measure encryption time (no initializer needed)
            time_enc = benchmark_worker_function(
                _unpack_get_coord,
                enc_subset,
                worker_count,
                chunksize,
                initializer=None,
                initargs=()
            )
            # Measure decryption time (with init_worker_shared)
            time_dec = benchmark_worker_function(
                _unpack_get_char,
                dec_subset,
                worker_count,
                chunksize,
                initializer=init_worker_shared,
                initargs=(shm_enc.name, size_enc)
            )
            results.append({
                'workers': worker_count,
                'chunksize': chunksize,
                'time_enc': time_enc,
                'time_dec': time_dec
            })

    df = pd.DataFrame(results)
    df['speed_enc'] = 2000 / df['time_enc']  # tasks per second
    df['speed_dec'] = 2000 / df['time_dec']


    df.to_csv("benchmark_results.csv", index=False)
    print("Benchmark results written to benchmark_results.csv")

    # Plot heatmaps for encryption and decryption speeds
    pivot_enc = df.pivot(index="workers", columns="chunksize", values="speed_enc")
    pivot_dec = df.pivot(index="workers", columns="chunksize", values="speed_dec")

    plt.figure(figsize=(10, 8))
    plt.title("Encryption Speed (tasks/sec)")
    plt.imshow(pivot_enc, aspect='auto', origin='lower', interpolation='nearest')
    plt.colorbar(label='Tasks/sec')
    plt.xlabel("Chunksize")
    plt.ylabel("Workers")
    plt.xticks(range(len(chunksize_list)), chunksize_list, rotation=45)
    plt.yticks(range(len(workers_list)), workers_list)
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(10, 8))
    plt.title("Decryption Speed (tasks/sec)")
    plt.imshow(pivot_dec, aspect='auto', origin='lower', interpolation='nearest')
    plt.colorbar(label='Tasks/sec')
    plt.xlabel("Chunksize")
    plt.ylabel("Workers")
    plt.xticks(range(len(chunksize_list)), chunksize_list, rotation=45)
    plt.yticks(range(len(workers_list)), workers_list)
    plt.tight_layout()
    plt.show()

    cleanup_shm(shm_enc)

if __name__ == "__main__":
    main()
