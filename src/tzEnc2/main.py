# pylint: disable=logging-too-many-args,line-too-long
import math
import secrets
import struct
import hmac
import hashlib
import json
from typing import Union, List, Set, Tuple, TypeVar, Dict, Optional, Any
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from tzEnc2.constants import CHARACTER_BLOCKS, CHARACTER_SET
from tzEnc2.config import CONFIG
from tzEnc2.log_config import get_logger
from concurrent.futures import ProcessPoolExecutor, wait, FIRST_COMPLETED, as_completed, ThreadPoolExecutor
import os
from tzEnc2.function_profiler import FunctionProfiler
import itertools
import time
T = TypeVar("T")  # Allow generic lists of any type

log = get_logger(__name__)

PADDED_CHARACTER_LIST = None

@FunctionProfiler.track()
def generate_salt():
    """Generate a cryptographic salt."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits

@FunctionProfiler.track()
def generate_multiple_keys(
    password: str,
    salt: bytes,
    bits: int,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
    key_count: int,
):
    """Generate multiple instances of a cryptographic key from a password using argon2id
    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt used in the argon2id algorithm.
        bits (int): The number of bits to derive from the password.
        memory_cost (int): The amount of memory to use in the argon2id algorithm.
        time_cost (int): The amount of time to use in the argon2id algorithm.
        parallelism (int): The number of threads to use in the argon2id algorithm.
        key_count (int): The number of keys to generate

    Returns:
        list[bytes]: A list of cryptographic keys derived from the password.
    """
    # Validate the input parameters
    c_bytes = (bits + 7) // 8  # Calculate the number of bytes in each key
    total_bytes = c_bytes * key_count

    derived = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=total_bytes,
        type=Type.ID,
    )

    keys = []
    for i in range(key_count):
        keys.append(derived[i * c_bytes : (i + 1) * c_bytes])
    return keys

@FunctionProfiler.track()
def generate_key_materials(password: str, salt: bytes) -> Tuple[int, int, bytes]:
    """
    Generate deterministic key materials from a password and salt using Argon2id.

    This function derives three key materials:
    1. A start time (bounded int)
    2. A time increment (bounded int)
    3. A raw grid seed (bytes)

    These are derived using the Argon2id KDF via `generate_multiple_keys` with parameters
    pulled from the global CONFIG.

    Args:
        password (str): The user-provided password.
        salt (bytes): A cryptographic salt used in key derivation.

    Returns:
        Tuple[int, int, bytes]: A tuple containing:
            - start_time (int): A number between 0 and 99,999,998
            - time_increment (int): A number between 0 and 999,998
            - grid_seed (bytes): A raw byte sequence suitable for seeding PRNG/grid logic
    """
    if not isinstance(salt, bytes) or len(salt) != 16:
        log.error("Salt must be 16 bytes long. Given %d bytes.", len(salt))
        raise ValueError("Salt must be 16 bytes long.")

    key_materials = generate_multiple_keys(
        password=password,
        salt=salt,
        time_cost=CONFIG["argon2id"]["time_cost"],
        bits=CONFIG["argon2id"]["bits"],
        memory_cost=CONFIG["argon2id"]["memory_cost"],
        parallelism=CONFIG["argon2id"]["parallelism"],
        key_count=3
    )

    start_time = int.from_bytes(key_materials[0], byteorder="big") % 99999999
    time_increment = int.from_bytes(key_materials[1], byteorder="big") % 999999
    grid_seed = SHA256.new(key_materials[2]).digest()  # Always gives 32 bytes

    return (start_time, time_increment, grid_seed)

@FunctionProfiler.track()
def find_used_character_block_indexes(
    list_of_lists: List[List[str]], message_char_set: Set[str]
) -> List[int]:
    remaining_chars = set(message_char_set)
    result: List[int] = []

    for idx, char_list in enumerate(list_of_lists):
        if not remaining_chars:
            break

        # If this block contains any needed character, select it
        if any(ch in remaining_chars for ch in char_list):
            result.append(idx)
            # Remove only those in remaining_chars, not the entire block
            for ch in char_list:
                if ch in remaining_chars:
                    remaining_chars.remove(ch)

    return result

@FunctionProfiler.track()
def derive_aes_key(base_bytes: bytes, number: int, aes_bits: int = 128) -> bytes:
    """
    Derive a fixed-length AES key from a 32-byte seed and an integer using SHA-256.

    This function combines a 256-bit base (seed) and an arbitrary-size integer
    (e.g., time or counter value), then hashes them together using SHA-256 to
    produce a secure, deterministic AES key of the specified bit size.

    Args:
        base_bytes (bytes): A 32-byte (256-bit) base seed value.
        number (int): An arbitrary integer to vary the derived key (e.g., time).
        aes_bits (int, optional): The size of the output AES key in bits. Must be 128, 192, or 256.
                                  Defaults to 128.

    Returns:
        bytes: An AES key of the specified bit length.

    Raises:
        ValueError: If `base_bytes` is not 32 bytes or `aes_bits` is not one of the allowed sizes.
    """
    if aes_bits not in (128, 192, 256):
        log.error("AES bit length must be 128, 192, or 256")
        raise ValueError("AES bit length must be 128, 192, or 256")
    if len(base_bytes) != 32:
        log.error("base_bytes must be exactly 256 bits (32 bytes) given: %d", base_bytes)
        raise ValueError("base_bytes must be exactly 256 bits (32 bytes)")

    number_bytes = number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")

    hasher = SHA256.new()
    hasher.update(base_bytes)
    hasher.update(number_bytes)

    return hasher.digest()[: aes_bits // 8]

@FunctionProfiler.track()
def aes_prng_stream(key: bytes, count: int) -> List[int]:
    """
    Generate a stream of pseudo-random 64-bit integers using AES in CTR mode.

    This function uses AES-128 in CTR mode as a deterministic PRNG to generate
    `count` unsigned 64-bit integers. The key must be exactly 16 bytes (128 bits).

    Args:
        key (bytes): A 16-byte AES-128 key used as the seed for the PRNG.
        count (int): The number of 64-bit integers to generate.

    Returns:
        List[int]: A list of `count` unsigned 64-bit integers.

    Raises:
        ValueError: If the key is not 16 bytes long.
    """
    if len(key) != 16:
        log.error("Key must be 16 bytes (128 bits) for AES-128")
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

    # Each AES block (16 bytes) yields two 64-bit unsigned integers
    blocks_needed = (count + 1) // 2

    # Initialize AES in CTR mode with a 128-bit counter
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    random_ints: List[int] = []
    for _ in range(blocks_needed):
        block = cipher.encrypt(b"\x00" * 16)
        a, b = struct.unpack(">QQ", block)
        random_ints.extend((a, b))

    return random_ints[:count]

@FunctionProfiler.track()
def aes_deterministic_shuffle(data: List[T], key: bytes) -> List[T]:
    """
    Shuffle a list deterministically using AES as a cryptographically secure PRNG.

    This uses the Fisher–Yates shuffle algorithm, seeded with a pseudo-random
    stream derived from AES-128 in CTR mode. The same `key` and `data` will
    always produce the same shuffled output.

    Args:
        data (List[T]): The list to be shuffled.
        key (bytes): A 16-byte AES-128 key used to seed the PRNG.

    Returns:
        List[T]: A new list with elements from `data` in shuffled order.

    Raises:
        AssertionError: If key is not 16 bytes.
    """
    shuffled = data.copy()
    n = len(shuffled)

    if n < 2:
        return shuffled  # No need to shuffle

    random_ints = aes_prng_stream(key, n - 1)

    for i in reversed(range(1, n)):
        j = random_ints[n - i - 1] % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled

@FunctionProfiler.track()
def shuffle_list(character_list: List[str], seed: bytes, time: int) -> List[str]:
    """
    Cryptographically shuffle a list of characters in a deterministic way.

    This function derives a key from the provided seed and time, then uses
    AES-based deterministic shuffling to reorder the character list. The same
    `seed` and `time` will always produce the same output for the same input list.

    Args:
        character_list (List[str]): The list of characters to shuffle.
        seed (bytes): A 32-byte seed used to derive the AES key.
        time (int): A numeric value (e.g., timestamp or counter) to vary the derived key.

    Returns:
        List[str]: A new list containing the shuffled characters.
    """
    key = derive_aes_key(seed, time)
    return aes_deterministic_shuffle(character_list, key)

@FunctionProfiler.track()
def calculate_minimum_grid_size(char_list_length: int, redundancy: int) -> int:
    """
    Calculate the minimum cube dimension (grid size) needed to store
    a character list repeated `redundancy` times in a 3D grid.

    The function returns the smallest integer `n` such that:
        n³ >= char_list_length * redundancy

    Args:
        char_list_length (int): The number of unique characters in the list.
        redundancy (int): The number of times the list must fit into the cube.

    Returns:
        int: The minimum grid size (cube dimension) that can contain the required characters.
    """
    required_chars = char_list_length * redundancy
    grid_size = math.ceil(required_chars ** (1 / 3))
    return grid_size

@FunctionProfiler.track()
def pad_character_list_to_grid(
    expanded_character_list: List[str], grid_size: int
) -> List[str]:
    """
    Pad a list of characters by repeating it until it exactly fills a 3D cube grid.

    The grid is assumed to have dimensions (grid_size x grid_size x grid_size).
    This function repeats the input character list as many times as needed and
    then slices it to fill the cube volume exactly.

    Args:
        expanded_character_list (List[str]): The character list to pad.
        grid_size (int): The size of one cube edge (i.e., the grid has volume = grid_size³).

    Returns:
        List[str]: A new list of characters of length exactly grid_size³.

    Raises:
        ValueError: If the input list is empty.
    """
    volume = grid_size**3
    repeat_count = (volume + len(expanded_character_list) - 1) // len(
        expanded_character_list
    )

    return (expanded_character_list * repeat_count)[:volume]

@FunctionProfiler.track()
def find_char_locations_in_list(in_char: str, char_list: List[str]) -> List[int]:
    """Find all the occurances of a character in a character list and return
    a list of all the indexes found.

    Args:
        in_char (str): the character to search for
        char_list (List[str]): the list of characters to search through ['a', 'b', ...]

    Returns:
        List[int]: List of indexes that contain the character.
    """
    return [idx for idx, c in enumerate(char_list) if c == in_char]

@FunctionProfiler.track()
def get_coord_math(
    idx: int,
    character: str,
    character_list: List[str],
    grid_size: int,
    grid_seed: bytes,
    time: int,
) -> List[int]:
    """
    Determine the 3D grid coordinates of a given character after a deterministic shuffle.

    The character list is deterministically shuffled based on a seed and time value.
    All occurrences of the target character are located within the shuffled list.
    One of those locations is randomly selected, and its position in a theoretical
    3D cube (grid_size x grid_size x grid_size) is computed and returned.

    Args:
        character (str): The character to locate in the grid.
        character_list (List[str]): The original list of characters before shuffling.
        grid_size (int): The length of one side of the 3D cube (grid volume = grid_size³).
        grid_seed (bytes): A 32-byte cryptographic seed used for deterministic shuffling.
        time (int): A numeric time or counter value to vary the shuffle key.

    Returns:
        List[int]: A list of three integers [x, y, z] representing the grid coordinates.

    Raises:
        ValueError: If the character does not appear in the shuffled character list.
    """
    log.info("[get_coord_math] time=%s char=%r", time, character)
    shuffled_character_list = shuffle_list(
        character_list=character_list, seed=grid_seed, time=time
    )

    character_index_list = find_char_locations_in_list(
        in_char=character, char_list=shuffled_character_list
    )

    chosen_index = secrets.choice(character_index_list)

    # Compute 3D grid coordinates from linear index
    z = chosen_index % grid_size
    y = (chosen_index // grid_size) % grid_size
    x = chosen_index // (grid_size * grid_size)
    log.info("[get_coord_math] time=%s char=%r → coord=%s", time, character, [x, y, z])
    return idx, [x, y, z]

@FunctionProfiler.track()
def get_char_math(
    idx: int,
    coords: Union[List[int], Tuple[int, int, int]],
    character_list: List[str],
    grid_size: int,
    grid_seed: bytes,
    time: int,
) -> str:
    """
    Retrieve a character from a shuffled list based on its 3D grid coordinates.

    This function deterministically shuffles the input character list using a seed and time,
    then converts the provided (x, y, z) grid coordinates into a linear index. It returns
    the character at that index in the shuffled list.

    Args:
        coords (Union[List[int], Tuple[int, int, int]]): A 3D coordinate [x, y, z] in the grid.
        character_list (List[str]): The original list of characters to be shuffled.
        grid_size (int): The length of one side of the cube-shaped grid (volume = grid_size³).
        grid_seed (bytes): A 32-byte cryptographic seed for deterministic shuffling.
        time (int): A time or counter value used in key derivation for shuffling.

    Returns:
        str: The character found at the specified grid coordinates after shuffling.

    Raises:
        IndexError: If the computed index is out of bounds.
        ValueError: If `coords` is not exactly three elements.
    """
    if not isinstance(coords, (list, tuple)) or len(coords) != 3:
        log.error("Coordinates must be a list or tuple of 3 integers.")
        raise ValueError("Coordinates must be a list or tuple of 3 integers.")
    if not all(isinstance(i, int) and 0 <= i < grid_size for i in coords):
        log.error("Coordinates must be integers within 0 and %s", grid_size-1)
        raise ValueError(f"Coordinates must be integers within 0 and {grid_size-1}")

    x, y, z = coords
    index = x * (grid_size**2) + y * grid_size + z

    shuffled_character_list = shuffle_list(
        character_list=character_list, seed=grid_seed, time=time
    )

    if index >= len(shuffled_character_list):
        raise IndexError(
            f"Grid index {index} is out of bounds for shuffled list length {len(shuffled_character_list)}."
        )

    return idx, shuffled_character_list[index]

@FunctionProfiler.track()
def collect_chars_by_indexes(
    character_blocks: List[List[str]], indexes: List[int]
) -> List[str]:
    """
    Collect and combine characters from specified block indexes.

    This function takes a list of character blocks (each a list of characters)
    and flattens the characters from the specified block indexes into a single list.

    Args:
        character_blocks (List[List[str]]): A list of character lists (blocks).
        indexes (List[int]): A list of indexes pointing to the blocks to extract.

    Returns:
        List[str]: A flat list of characters collected from the specified blocks.

    Raises:
        IndexError: If any index in `indexes` is out of bounds.
    """
    return [char for idx in indexes for char in character_blocks[idx]]

@FunctionProfiler.track()
def compute_digest(data: dict, digest_passphrase: str) -> str:
    """
    Compute an HMAC-SHA256 digest of the input data using the provided passphrase.
    """
    key = digest_passphrase.encode("utf-8")
    message = json.dumps(data, sort_keys=True).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()

@FunctionProfiler.track()
def verify_digest(data: dict, digest_passphrase: str) -> bool:
    """
    Verifies that the HMAC digest in the data matches the expected value.
    """
    provided_digest = data.get("digest")
    if not provided_digest:
        log.error("No digest found in encrypted data.")
        raise ValueError("No digest found in encrypted data.")

    # Make a copy without the digest field
    data_copy = data.copy()
    del data_copy["digest"]
    expected_digest = compute_digest(data_copy, digest_passphrase)
    return hmac.compare_digest(provided_digest, expected_digest)

@FunctionProfiler.track()
def handle_digest_verification(
    json_data: dict, digest_passphrase: Optional[str], require_digest: bool = True
) -> None:
    """
    Handles all digest validation logic before proceeding with decryption.

    Args:
        json_data (dict): The encrypted message dictionary.
        digest_passphrase (str | None): The passphrase to verify the digest (optional).
        require_digest (bool): Whether to enforce digest presence/validation strictly.

    Raises:
        ValueError: If digest conditions do not align with passphrase usage.
    """
    has_digest = "digest" in json_data

    if has_digest and digest_passphrase:
        # Verify the digest matches
        if not verify_digest(json_data, digest_passphrase):
            log.error("Digest verification failed. Message may have been tampered with.")
            raise ValueError(
                "Digest verification failed. Message may have been tampered with."
            )
    elif has_digest and not digest_passphrase:
        # Digest exists but no way to verify
        log.error("Encrypted message contains a digest, but no digest passphrase was provided.")
        raise ValueError(
            "Encrypted message contains a digest, but no digest passphrase was provided."
        )
    elif not has_digest and digest_passphrase:
        # Passphrase was given but no digest to check
        log.error("Digest passphrase was provided, but the message contains no digest.")
        raise ValueError(
            "Digest passphrase was provided, but the message contains no digest."
        )
    elif not has_digest and not digest_passphrase:
        if require_digest:
            log.error("No digest present. Digest is required for this decryption.")
            raise ValueError(
                "No digest present. Digest is required for this decryption."
            )

PADDED_CHARACTER_LIST: List[Any] = None


def init_worker(padded_list: List[Any]):
    """
    This runs once in each child process before any map() calls. We assign
    the module-level global here so that process_item (or get_coord_math) can
    refer to it without pickling the whole object on every call.
    """
    global PADDED_CHARACTER_LIST
    PADDED_CHARACTER_LIST = padded_list


def _unpack_get_coord(arg_tuple: Tuple[int, str, int, bytes, int]) -> Tuple[int, Any]:
    """
    We expect arg_tuple = (i, ch, grid_size, grid_seed, t). We pull
    PADDED_CHARACTER_LIST (set by init_worker) instead of passing it in every time.
    """
    i, ch, grid_size, grid_seed, t = arg_tuple
    # Use the global PADDED_CHARACTER_LIST here, NOT a local variable:
    return get_coord_math(i, ch, PADDED_CHARACTER_LIST, grid_size, grid_seed, t)

@FunctionProfiler.track()
def encrypt(
    password: str, redundancy: int, message: str, digest_passphrase: str = ""
) -> Dict[str, Union[List[List[int]], List[int], int, str]]:
    """
    Encrypt a plaintext message into coordinate-based cipher data using a grid system.

    This function builds a shuffled 3D coordinate grid from a dynamically generated character set,
    then encodes each character from the message into a coordinate in the grid. The encryption
    process is deterministic for a given password, salt, and input, but cryptographically secure.

    Args:
        password (str): The user-provided password used to derive cryptographic keys.
        redundancy (int): The number of times the expanded character list should be repeated in the grid.
        message (str): The plaintext message to encrypt.
        digest_passphrase (str): None by default, if included calculates a digest of the contents using the digest_passphrase as the key.

    Returns:
        Dict[str, Union[List[List[int]], List[int], int, str]]: A dictionary containing:
            - "cipher_text": A list of [x, y, z] coordinates (one per character).
            - "character_blocks": Indexes of the blocks used from the master character list.
            - "redundancy": The redundancy factor used.
            - "salt": The hex-encoded salt used during key generation.

    Raises:
        ValueError: If the message contains characters not in the allowed CHARACTER_SET.
    """
    if not isinstance(password, str) or not 3 <= len(password) <= 256:
        log.error("Password must be a string between 3 and 256 characters.")
        raise ValueError("Password must be a string between 3 and 256 characters.")

    if not isinstance(redundancy, int) or redundancy < 1:
        log.error("Redundancy must be a positive integer.")
        raise ValueError("Redundancy must be a positive integer.")

    if not isinstance(message, str) or not message:
        log.error("Message must be a non-empty string.")
        raise ValueError("Message must be a non-empty string.")

    if digest_passphrase is not None and not 3 <= len(digest_passphrase) <= 256:
        log.error("Digest passphrase, if entered, must be between 3 and 256 characters.")
        raise ValueError("Digest passphrase, if entered, must be between 3 and 256 characters.")

    # Generate cryptographic materials
    salt = generate_salt()
    start_time, time_increment, grid_seed = generate_key_materials(
        password=password, salt=salt
    )

    # Validate characters
    message_set = set(message)
    if not message_set.issubset(CHARACTER_SET):
        unmapped_characters = message_set - CHARACTER_SET
        log.error("Input contains unmapped characters that cannot be encrypted: %s", unmapped_characters)
        raise ValueError(
            f"Input contains unmapped characters that cannot be encrypted: {unmapped_characters}"
        )

    # NEW: Ensure each character actually appears in at least one block
    all_blocks_union = set().union(*CHARACTER_BLOCKS)
    missing_from_master = message_set - all_blocks_union
    if missing_from_master:
        log.error("The following char(s) are not in any block: %s", missing_from_master)
        raise ValueError(
            f"The following character(s) cannot be encrypted because they are not in any block: {missing_from_master}"
        )

    # Determine which character blocks are needed
    block_indexes = find_used_character_block_indexes(CHARACTER_BLOCKS, message_set)

    used_chars = set()
    for idx in block_indexes:
        used_chars.update(CHARACTER_BLOCKS[idx])

    missing_after_selection = message_set - used_chars
    if missing_after_selection:
        log.error("Blocks chosen do not cover these message chars: %s", missing_after_selection)
        raise ValueError(
            f"After selecting blocks, these characters are still missing: {missing_after_selection}"
        )

    # Expand and prepare the character list for grid usage
    expanded_character_list = collect_chars_by_indexes(CHARACTER_BLOCKS, block_indexes)
    grid_size = calculate_minimum_grid_size(len(expanded_character_list), redundancy)
    padded_expanded_character_list = pad_character_list_to_grid(
        expanded_character_list=expanded_character_list, grid_size=grid_size
    )
        
    tasks: list[tuple[int, str, int, bytes, int]] = []
    for i, ch in enumerate(message):
        t = start_time + i * time_increment
        tasks.append((i, ch, grid_size, grid_seed, t))

    ### BEST YET
    num_tasks = len(tasks)
    encrypted_output = [None] * num_tasks
    cpu_count = os.cpu_count() or 1
    max_workers = max(1, math.ceil(cpu_count * 0.75))
    # Decide on chunksize. If get_coord_math is extremely fast (sub-ms), you might
    # choose a chunksize of several thousand. If it's heavier, maybe 128 or 256.
    chunksize = 16
    with ProcessPoolExecutor(max_workers=max_workers,
                            initializer=init_worker,
                            initargs=(padded_expanded_character_list,)) as executor:
        # executor.map will feed “chunks” of tasks to each worker, instead of one Future each.
        # The lambda unpacks our argument tuple into get_coord_math.
        for idx, coords in executor.map(
            _unpack_get_coord,
            tasks,
            chunksize=chunksize
        ):
            encrypted_output[idx] = coords

    json_output = {
        "cipher_text": encrypted_output,
        "character_blocks": block_indexes,
        "redundancy": redundancy,
        "salt": salt.hex(),
    }

    if digest_passphrase:
        json_output["digest"] = compute_digest(json_output, digest_passphrase)

    print("\n--- Function Profiling Summary ---")
    print(FunctionProfiler.report())

    return json_output

@FunctionProfiler.track()
def _unpack_get_char(arg_tuple):
    return get_char_math(*arg_tuple)

@FunctionProfiler.track()
def decrypt(password: str, json_data: Dict, digest_passphrase: str = "") -> str:
    """
    Decrypt a coordinate-based cipher back into the original plaintext message.

    This function reconstructs the same character grid used during encryption
    based on the provided password and metadata in `json_data`. It then maps
    each coordinate back to its corresponding character in the shuffled grid.

    Args:
        password (str): The password used during encryption.
        json_data (Dict): A dictionary containing:
            - "salt": Hex string used for key derivation.
            - "character_blocks": List of block indexes used.
            - "redundancy": The redundancy factor used in grid construction.
            - "cipher_text": List of [x, y, z] grid coordinates (encrypted characters).
        digest_passphrase (str): The passphrase used to validate the digest.

    Returns:
        str: The original decrypted plaintext message.
    """
    if not isinstance(password, str) or not 3 <= len(password) <= 256:
        log.error("Password must be a string between 3 and 256 characters.")
        raise ValueError("Password must be a string between 3 and 256 characters.")
    if digest_passphrase is not None and not 3 <= len(digest_passphrase) <= 256:
        log.error("Digest passphrase, if set, must be between 3 and 256 characters.")
        raise ValueError("Digest passphrase, if set, must be between 3 and 256 characters.")

    # Digest check
    handle_digest_verification(
        json_data, digest_passphrase=digest_passphrase, require_digest=True
    )

    salt = json_data["salt"]
    character_blocks = json_data["character_blocks"]
    redundancy = json_data["redundancy"]
    cipher_text = json_data["cipher_text"]

    # Derive keys
    salt_bytes = bytes.fromhex(salt)
    start_time, time_increment, grid_seed = generate_key_materials(
        password=password, salt=salt_bytes
    )

    # Reconstruct the character list
    expanded_character_list = collect_chars_by_indexes(
        CHARACTER_BLOCKS, character_blocks
    )

    # Determine grid size and pad character list
    grid_size = calculate_minimum_grid_size(len(expanded_character_list), redundancy)
    padded_expanded_character_list = pad_character_list_to_grid(
        expanded_character_list=expanded_character_list, grid_size=grid_size
    )
    
    tasks: list[tuple[int, str, List[str], int, bytes, int]] = []
    for i, coords in enumerate(cipher_text):
        t = start_time + i * time_increment
        tasks.append((i, coords, padded_expanded_character_list, grid_size, grid_seed, t))
        
        
    num_tasks = len(tasks)
    message = [None] * num_tasks
    cpu_count = os.cpu_count() or 1
    max_workers = max(1, math.ceil(cpu_count * 0.75))
    # Decide on chunksize. If get_coord_math is extremely fast (sub-ms), you might
    # choose a chunksize of several thousand. If it's heavier, maybe 128 or 256.
    chunksize = 16
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # executor.map will feed “chunks” of tasks to each worker, instead of one Future each.
        # The lambda unpacks our argument tuple into get_coord_math.
        for idx, char in executor.map(
            _unpack_get_char,
            tasks,
            chunksize=chunksize
        ):
            message[idx] = char

    return "".join(message)


if __name__ == "__main__":
    cipher = encrypt("test", 20, "hello there 뙱", "test2")
    print(cipher)
    message = decrypt("test", cipher, "test2")
    print(message)
