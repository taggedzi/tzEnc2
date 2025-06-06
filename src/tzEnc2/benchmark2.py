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

# ────────────────────────────────────────────────────────────────────────────────
# A) REAL imports from your tzEnc2 package
# ────────────────────────────────────────────────────────────────────────────────
#
# Adjust these if your functions are in a different module:
from tzEnc2.main import (
    encrypt,                     # your real encryption function
    decrypt,                     # your real decryption function
    collect_chars_by_indexes,    # helper to build expanded character list
    pad_character_list_to_grid,  # helper to pad to grid_size^3
    calculate_minimum_grid_size, # helper to find grid_size
    shuffle_list,                # real shuffling logic
    get_char_math,
    get_coord_math,
    find_used_character_block_indexes,
    CHARACTER_BLOCKS,
)

# If you have a global CHARACTER_SET defined, import it; otherwise:
CHARACTER_SET = set(string.ascii_uppercase)

# These unpack wrappers let executor.map call the var-arg functions
def _unpack_encrypt(arg_tuple):
    return encrypt(*arg_tuple)

def _unpack_decrypt(arg_tuple):
    return decrypt(*arg_tuple)
# ────────────────────────────────────────────────────────────────────────────────


def init_worker_shared(shm_name: str, size: int):
    """
    Worker initializer for both encryption and decryption phases. Attaches
    to the named shared‐memory block and rebuilds a global PADDING_LIST in each child.
    Must be a top‐level function so that ProcessPoolExecutor can pickle it.
    """
    global PADDING_LIST, _worker_shm
    _worker_shm = shared_memory.SharedMemory(name=shm_name)
    raw = _worker_shm.buf[:size]
    decoded = bytes(raw).decode("utf-8")
    PADDING_LIST = list(decoded)
    # We do NOT call _worker_shm.close() here; let the worker hold it until exit.


def build_shared_padded_list(sample_message: str, redundancy: int = 1):
    """
    1) From `sample_message`, determine which character blocks are needed (using your real logic).
    2) Build the expanded_character_list from those blocks.
    3) Calculate `grid_size` so that `grid_size^3 >= len(expanded_character_list) * redundancy`.
    4) Pad that expanded list to exactly grid_size^3, join into one big string, encode to UTF-8.
    5) Copy into a SharedMemory block so workers can attach.

    Returns:
        shm: SharedMemory handle
        size_bytes: int, length of the byte buffer
        grid_size: int, dimension (so grid_size^3 = padded length)
    """

    # Step 1: Which blocks are used by sample_message?
    message_set = set(sample_message)
    # Find all block indexes in CHARACTER_BLOCKS that cover message_set
    block_indexes = find_used_character_block_indexes(CHARACTER_BLOCKS, message_set)

    # Step 2: Build expanded_character_list by collecting characters from those blocks
    expanded_character_list = collect_chars_by_indexes(CHARACTER_BLOCKS, block_indexes)

    # Step 3: Compute grid_size (smallest cube that fits expanded * redundancy)
    grid_size = calculate_minimum_grid_size(len(expanded_character_list) * redundancy, redundancy)

    # Step 4: Pad the list to exactly grid_size^3
    padded_list = pad_character_list_to_grid(expanded_character_list, grid_size)

    # Join into one big string, encode to UTF-8
    joined = "".join(padded_list)
    utf8_bytes = joined.encode("utf-8")
    size_bytes = len(utf8_bytes)

    # Step 5: Create and populate a SharedMemory block
    shm = shared_memory.SharedMemory(create=True, size=size_bytes)
    shm.buf[:size_bytes] = utf8_bytes

    return shm, size_bytes, grid_size, block_indexes


def cleanup_shm(shm):
    """
    Close and unlink the SharedMemory block. Call this after all ProcessPoolExecutors
    that depend on it have exited.
    """
    shm.close()
    shm.unlink()


def benchmark_worker_function(unpack_fn, tasks, max_workers, chunksize, initializer=None, initargs=()):
    """
    Run `unpack_fn` over the list `tasks` in parallel, using a ProcessPoolExecutor
    with `max_workers` processes and `chunksize`. Measure and return wall‐clock time.
    """
    t0 = time.perf_counter()
    with ProcessPoolExecutor(
        max_workers=max_workers,
        initializer=initializer,
        initargs=initargs
    ) as executor:
        for _ in executor.map(unpack_fn, tasks, chunksize=chunksize):
            pass
    return time.perf_counter() - t0


def main():
    # ────────────────────────────────────────────────────────────────────────────
    # (A) Build a sample plaintext message of length 10 000 (only uppercase A–Z)
    # ────────────────────────────────────────────────────────────────────────────
    message_length = 10000
    sample_message = "".join(random.choices(list(CHARACTER_SET), k=message_length))

    # ────────────────────────────────────────────────────────────────────────────
    # (B) We will test these “target” padded‐list sizes (typical 256→512→10 000→~106 752)
    # ────────────────────────────────────────────────────────────────────────────
    padded_targets = [
        256,
        512,
        10000,
        256 * 417   # ≈ 106 752 (in your worst‐case scenario)
    ]

    # Timing parameters for encryption/decryption
    grid_seed = None  # will come from generate_key_materials
    start_time = None  # ditto
    time_increment = None

    results = []  # collect dictionaries of (padded_length, workers, chunksize, time_enc, time_dec)

    for target_length in padded_targets:
        # ────────────────────────────────────────────────────────────────────────
        # (B1) Build the shared padded list (real code path)
        # ────────────────────────────────────────────────────────────────────────
        shm, size_bytes, grid_size, block_indexes = build_shared_padded_list(sample_message[:2000], redundancy=1)

        # We still need a proper grid_seed, start_time, and time_increment from your real key‐derivation:
        # Use a dummy password & salt to call generate_key_materials, just once:
        from tzEnc2.main import generate_key_materials
        dummy_password = "benchmark"
        dummy_salt = os.urandom(16)
        start_time, time_increment, grid_seed = generate_key_materials(
            password=dummy_password,
            salt=dummy_salt
        )

        # ────────────────────────────────────────────────────────────────────────
        # (B2) Build real encryption tasks for the FIRST 2000 characters of sample_message
        #     Each task = (idx, char, grid_size, grid_seed, t)
        # ────────────────────────────────────────────────────────────────────────
        encrypt_tasks = []
        for i, ch in enumerate(sample_message[:2000]):
            t = start_time + i * time_increment
            encrypt_tasks.append((i, ch, grid_size, grid_seed, t))

        # (B3) Run a single‐thread encryption on those 2000 tasks to produce real ciphertext
        #      (We just need the “coords” from get_coord_math)
        ciphertext = [get_coord_math(*task)[1] for task in encrypt_tasks]

        # ────────────────────────────────────────────────────────────────────────
        # (B4) Build real decryption tasks for those coordinates
        #     Each task = (idx, coords, grid_size, grid_seed, t)
        # ────────────────────────────────────────────────────────────────────────
        decrypt_tasks = []
        for i, coords in enumerate(ciphertext):
            t = start_time + i * time_increment
            decrypt_tasks.append((i, coords, grid_size, grid_seed, t))

        # ────────────────────────────────────────────────────────────────────────
        # (C) Now vary `workers` = 1..20 and `chunksize` = 1, 2, 4, …, 1024
        # ────────────────────────────────────────────────────────────────────────
        workers_list = list(range(1, 21))
        chunksize_list = [2**i for i in range(0, 11)]  # 1,2,4,…,1024

        for worker_count in workers_list:
            for chunksize in chunksize_list:
                # (C1) Measure ENCRYPTION time (using the real `encrypt` via _unpack_encrypt)
                time_enc = benchmark_worker_function(
                    _unpack_encrypt,
                    encrypt_tasks,
                    worker_count,
                    chunksize,
                    initializer=init_worker_shared,
                    initargs=(shm.name, size_bytes)
                )

                # (C2) Measure DECRYPTION time (using the real `decrypt` via _unpack_decrypt)
                time_dec = benchmark_worker_function(
                    _unpack_decrypt,
                    decrypt_tasks,
                    worker_count,
                    chunksize,
                    initializer=init_worker_shared,
                    initargs=(shm.name, size_bytes)
                )

                results.append({
                    'padded_length': grid_size ** 3,
                    'workers': worker_count,
                    'chunksize': chunksize,
                    'time_enc': time_enc,
                    'time_dec': time_dec
                })

        # ────────────────────────────────────────────────────────────────────────
        # (D) Clean up shared memory for this padded length before moving on
        # ────────────────────────────────────────────────────────────────────────
        cleanup_shm(shm)

    # ────────────────────────────────────────────────────────────────────────────
    # (E) Post‐process results into a DataFrame, compute throughput, save & plot
    # ────────────────────────────────────────────────────────────────────────────
    df = pd.DataFrame(results)
    df['speed_enc'] = 2000 / df['time_enc']  # tasks per second
    df['speed_dec'] = 2000 / df['time_dec']

    # Print first few rows so you see it on the console
    print("\nBenchmark Results (first 10 rows):")
    print(df.head(10))

    # Save the full CSV for deeper analysis
    df.to_csv("benchmark_results.csv", index=False)
    print("\nFull results written to benchmark_results.csv")

    # Plot heatmaps, one for each padded_length and each mode (enc vs dec)
    for mode in ['enc', 'dec']:
        for pad_len in sorted(df['padded_length'].unique()):
            subset = df[df['padded_length'] == pad_len]
            pivot = subset.pivot(
                index="workers",
                columns="chunksize",
                values=f"speed_{mode}"
            )

            plt.figure(figsize=(8, 6))
            title = (
                ("Encryption" if mode == 'enc' else "Decryption")
                + f" Speed (padded={pad_len})"
            )
            plt.title(title)
            plt.imshow(pivot, aspect='auto', origin='lower', interpolation='nearest')
            plt.colorbar(label='Tasks/sec')
            plt.xlabel("Chunksize")
            plt.ylabel("Workers")
            plt.xticks(range(len(chunksize_list)), chunksize_list, rotation=45)
            plt.yticks(range(len(workers_list)), workers_list)
            plt.tight_layout()
            plt.show()


if __name__ == "__main__":
    main()
