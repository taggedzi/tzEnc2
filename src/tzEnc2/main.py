# pylint: disable=logging-too-many-args,line-too-long,global-statement
import math
import secrets
import struct
import hmac
import hashlib
import json
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import shared_memory
from typing import Union, List, Set, Tuple, TypeVar, Dict, Optional, Any, Literal, cast
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from tzEnc2.constants import CHARACTER_BLOCKS, CHARACTER_SET, ARGON2ID
from tzEnc2.config import CONFIG
from tzEnc2.log_config import get_logger
from tzEnc2.function_profiler import FunctionProfiler
T = TypeVar("T")  # Allow generic lists of any type

log = get_logger(__name__)

# Shared memory value to reduce pickle load on ProcessPoolExecutor for large character lists.
PADDING_LIST = None  # type: Optional[List[str]]
_worker_shm: Optional[shared_memory.SharedMemory] = None  # Keep the SharedMemory object alive


@FunctionProfiler.track()
def generate_salt():
    """Generate a cryptographic salt."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits


@FunctionProfiler.track()
def generate_multiple_keys(
    password: str,
    salt: bytes,
    bits: int,
    key_count: int,
    time_cost: int = ARGON2ID["TIME_COST"],
    memory_cost: int = ARGON2ID["MEMORY_COST"],
    parallelism: int = ARGON2ID["PARALLELLISM"],
):
    """Generate multiple instances of a cryptographic key from a password using argon2id
    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt used in the argon2id algorithm.
        bits (int): The number of bits to derive from the password.
        key_count (int): The number of keys to generate
        time_cost (int): The amount of time to use in the argon2id algorithm.
        memory_cost (int): The amount of memory to use in the argon2id algorithm.
        parallelism (int): The number of threads to use in the argon2id algorithm.

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
    pulled from the constants.py file.

    Args:
        password (str): The user-provided password.
        salt (bytes): A cryptographic salt used in key derivation.

    Returns:
        Tuple[int, int, bytes]: A tuple containing:
            - start_time (int): A number between 0 and 99,999,999
            - time_increment (int): A number between 0 and 99,999
            - grid_seed (bytes): A raw byte sequence suitable for seeding PRNG/grid logic
    """
    if not isinstance(salt, bytes) or len(salt) != 16:
        log.error("Salt must be 16 bytes long. Given %d bytes.", len(salt))
        raise ValueError("Salt must be 16 bytes long.")

    key_materials = generate_multiple_keys(
        password=password,
        salt=salt,
        bits=ARGON2ID["BITS"],
        key_count=3
    )

    start_time = int.from_bytes(key_materials[0], byteorder="big") % 99999999
    time_increment = int.from_bytes(key_materials[1], byteorder="big") % 99999
    grid_seed = SHA256.new(key_materials[2]).digest()  # Always gives 32 bytes

    return (start_time, time_increment, grid_seed)


@FunctionProfiler.track()
def find_used_character_block_indexes(
    list_of_lists: List[List[str]], message_char_set: Set[str]
) -> List[int]:
    """
    Find the indexes of character blocks that contain characters from the message_char_set.

    Args:
        list_of_lists: A list of character lists (blocks).
        message_char_set: A set of characters that need to be matched.

    Returns:
        A list of indexes for blocks that contain at least one required character.
    """
    remaining_chars = set(message_char_set)
    used_indexes = []

    for idx, block in enumerate(list_of_lists):
        if not remaining_chars:
            break

        matching_chars = remaining_chars.intersection(block)
        if matching_chars:
            used_indexes.append(idx)
            remaining_chars.difference_update(matching_chars)

    return used_indexes


@FunctionProfiler.track()
def derive_aes_key(
    base_bytes: bytes,
    number: int,
    aes_bits: Literal[128, 192, 256] = 128
) -> bytes:
    """
    Derive a deterministic AES key from a 32-byte seed and an integer using SHA-256.

    Args:
        base_bytes (bytes): A 32-byte (256-bit) seed value.
        number (int): An integer to differentiate derived keys (e.g., a counter or timestamp).
        aes_bits (int, optional): Desired AES key length in bits (128, 192, or 256). Defaults to 128.

    Returns:
        bytes: AES key of the specified length.

    Raises:
        ValueError: If `base_bytes` is not 32 bytes or `aes_bits` is not a valid AES length.
    """
    if len(base_bytes) != 32:
        log.error("Invalid base_bytes length: expected 32 bytes, got %d", len(base_bytes))
        raise ValueError("base_bytes must be exactly 32 bytes (256 bits)")

    if aes_bits not in (128, 192, 256):
        log.error("Invalid AES key size: %d. Must be 128, 192, or 256", aes_bits)
        raise ValueError("aes_bits must be 128, 192, or 256")

    number_bytes = number.to_bytes((number.bit_length() + 7) // 8 or 1, "big")

    hasher = SHA256.new()
    hasher.update(base_bytes)
    hasher.update(number_bytes)

    key_bytes = aes_bits // 8
    return hasher.digest()[:key_bytes]


@FunctionProfiler.track()
def aes_prng_stream(key: bytes, count: int) -> List[int]:
    """
    Generate a stream of pseudo-random 64-bit unsigned integers using AES-128 in CTR mode.

    Args:
        key (bytes): A 16-byte AES-128 key used as the PRNG seed.
        count (int): Number of 64-bit integers to generate.

    Returns:
        List[int]: List of `count` pseudo-random unsigned 64-bit integers.

    Raises:
        ValueError: If key is not 16 bytes long.
    """
    if len(key) != 16:
        log.error("Invalid key length: expected 16 bytes, got %d", len(key))
        raise ValueError("Key must be 16 bytes (128 bits) for AES-128")

    # Each AES block (16 bytes) gives two 64-bit integers
    blocks_needed = (count + 1) // 2

    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    prng_output = []
    for _ in range(blocks_needed):
        block = cipher.encrypt(b"\x00" * 16)
        prng_output.extend(struct.unpack(">QQ", block))  # 2x 64-bit unsigned ints

    return prng_output[:count]


@FunctionProfiler.track()
def aes_deterministic_shuffle(data: List[T], key: bytes) -> List[T]:
    """
    Deterministically shuffle a list using AES-128 as a cryptographic PRNG.

    Uses the Fisher–Yates shuffle algorithm with a pseudo-random number stream
    derived from AES in CTR mode. Given the same `data` and `key`, the output
    will always be the same.

    Args:
        data (List[T]): The list to shuffle.
        key (bytes): A 16-byte AES-128 key for deterministic randomness.

    Returns:
        List[T]: A new shuffled list with deterministic order.

    Raises:
        ValueError: If the key is not 16 bytes long.
    """
    if len(key) != 16:
        log.error("Invalid key length for deterministic shuffle: %d bytes", len(key))
        raise ValueError("Key must be exactly 16 bytes (128 bits)")

    n = len(data)
    if n < 2:
        return data.copy()

    shuffled = data.copy()
    prng = aes_prng_stream(key, n - 1)

    for i in reversed(range(1, n)):
        j = prng[n - i - 1] % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled


@FunctionProfiler.track()
def shuffle_list(character_list: List[str], seed: bytes, time: int) -> List[str]:
    """
    Deterministically shuffle a list of characters using a cryptographic seed and time.

    This function derives an AES-128 key from the given 32-byte seed and integer `time`,
    then performs a deterministic shuffle using AES-based PRNG and Fisher–Yates.

    Args:
        character_list (List[str]): List of characters to shuffle.
        seed (bytes): A 32-byte (256-bit) seed to derive the AES key.
        time (int): Integer input (e.g., timestamp or counter) to vary the key.

    Returns:
        List[str]: A new list containing the shuffled characters.

    Raises:
        ValueError: If the seed is not 32 bytes.
    """
    if len(seed) != 32:
        log.error("Invalid seed length: expected 32 bytes, got %d", len(seed))
        raise ValueError("Seed must be exactly 32 bytes (256 bits)")

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
    Pad a list of characters by repeating it until it fills a 3D cube grid.

    The grid has dimensions (grid_size x grid_size x grid_size), so its volume is grid_size³.
    Characters are repeated as needed to exactly match the volume, then trimmed to fit.

    Args:
        expanded_character_list (List[str]): Base character list to pad.
        grid_size (int): Length of one side of the 3D cube.

    Returns:
        List[str]: Character list of length exactly grid_size³.

    Raises:
        ValueError: If the input list is empty.
    """
    if not expanded_character_list:
        log.error("Input character list must not be empty.")
        raise ValueError("Input character list must not be empty.")

    volume = grid_size ** 3
    needed_repeats = -(-volume // len(expanded_character_list))  # Ceiling division

    padded_list = (expanded_character_list * needed_repeats)[:volume]
    return padded_list


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


def get_coord_math(
    idx: int,
    character: str,
    grid_size: int,
    grid_seed: bytes,
    time: int,
) -> Tuple[int, List[int]]:
    """
    Compute the 3D coordinates of a character in a deterministically shuffled grid.

    The grid is based on a deterministic shuffle of a global character list (PADDING_LIST),
    influenced by a cryptographic seed and a time value. The function finds all positions
    where the given character appears, selects one randomly, and maps its index to a
    3D coordinate in a cube of size (grid_size³).

    Args:
        idx (int): The index this character is associated with (passed through).
        character (str): The character to locate in the shuffled grid.
        grid_size (int): Length of one cube edge (total volume = grid_size³).
        grid_seed (bytes): 32-byte seed used to deterministically shuffle the grid.
        time (int): Integer (e.g., timestamp) to vary the shuffle key.

    Returns:
        Tuple[int, List[int]]: Tuple of the input index and the [x, y, z] grid coordinates.

    Raises:
        ValueError: If the character is not found in the shuffled list.
        RuntimeError: If the global PADDING_LIST is not set when running.
    """
    log.info("[get_coord_math] time=%s char=%r", time, character)

    # Deterministically shuffle the padding list
    if PADDING_LIST is None:
        log.error("PADDING_LIST was accessed before being initialized.")
        raise RuntimeError("Global character list (PADDING_LIST) is not initialized.")
    shuffled_chars = shuffle_list(PADDING_LIST, seed=grid_seed, time=time)

    # Find all positions of the target character
    char_indices = find_char_locations_in_list(character, shuffled_chars)
    if not char_indices:
        log.error("Character %r not found in shuffled grid.", character)
        raise ValueError(f"Character {repr(character)} not found in shuffled grid.")

    # Randomly choose one occurrence
    chosen_index = secrets.choice(char_indices)

    # Convert 1D index to 3D coordinates (x, y, z)
    z = chosen_index % grid_size
    y = (chosen_index // grid_size) % grid_size
    x = chosen_index // (grid_size * grid_size)

    coord = [x, y, z]
    log.info("[get_coord_math] char=%r → coord=%s", character, coord)

    return idx, coord


def get_char_math(
    idx: int,
    coords: Union[List[int], Tuple[int, int, int]],
    grid_size: int,
    grid_seed: bytes,
    time: int
) -> Tuple[int, str]:
    """
    Retrieve a character from a deterministically shuffled list using 3D grid coordinates.

    This uses a shuffled version of PADDING_LIST, generated deterministically based on the
    given seed and time. The function converts the provided (x, y, z) coordinates into a
    1D index and returns the character at that position.

    Args:
        idx (int): An index passed through with the result.
        coords (Union[List[int], Tuple[int, int, int]]): 3D grid coordinates [x, y, z].
        grid_size (int): Length of one cube edge (total grid size = grid_size³).
        grid_seed (bytes): 32-byte seed used to derive deterministic shuffle key.
        time (int): Time or counter value to affect the shuffle.

    Returns:
        Tuple[int, str]: A tuple of the input index and the retrieved character.

    Raises:
        ValueError: If coordinates are invalid or out of bounds.
        IndexError: If the computed index exceeds the list bounds.
        RuntimeError: If the global PADDING_LIST is not set at run time.
    """
    if not isinstance(coords, (list, tuple)) or len(coords) != 3:
        log.error("Invalid coordinates: %r", coords)
        raise ValueError("Coordinates must be a list or tuple of exactly 3 integers.")

    if not all(isinstance(c, int) and 0 <= c < grid_size for c in coords):
        log.error("Coordinates out of bounds: %r (grid_size=%d)", coords, grid_size)
        raise ValueError(f"Coordinates must be integers in the range 0 to {grid_size - 1}.")

    x, y, z = coords
    index = x * (grid_size ** 2) + y * grid_size + z

    if PADDING_LIST is None:
        log.error("PADDING_LIST was accessed before being initialized.")
        raise RuntimeError("Global character list (PADDING_LIST) is not initialized.")
    shuffled_list = shuffle_list(PADDING_LIST, seed=grid_seed, time=time)

    if index >= len(shuffled_list):
        log.error("Computed index %d out of bounds (len=%d)", index, len(shuffled_list))
        raise IndexError(
            f"Grid index {index} is out of bounds for shuffled list length {len(shuffled_list)}."
        )

    return idx, shuffled_list[index]


@FunctionProfiler.track()
def collect_chars_by_indexes(
    character_blocks: List[List[str]], indexes: List[int]
) -> List[str]:
    """
    Collect and flatten characters from specified block indexes.

    Args:
        character_blocks (List[List[str]]): A list of character blocks (each a list of characters).
        indexes (List[int]): Indexes of the blocks to extract and flatten.

    Returns:
        List[str]: A single flat list of characters collected from the specified blocks.

    Raises:
        IndexError: If any index in `indexes` is out of range for `character_blocks`.
    """
    if not character_blocks:
        return []

    max_index = len(character_blocks) - 1
    for i in indexes:
        if not 0 <= i <= max_index:
            log.error("Block index %d out of bounds (max allowed: %d)", i, max_index)
            raise IndexError(f"Block index {i} out of bounds (max allowed: {max_index})")

    return [char for i in indexes for char in character_blocks[i]]


@FunctionProfiler.track()
def compute_digest(data: Dict, digest_passphrase: str) -> str:
    """
    Compute an HMAC-SHA256 digest of the given dictionary using a passphrase.

    The dictionary is serialized to a canonical JSON string with sorted keys,
    then an HMAC digest is computed using SHA-256.

    Args:
        data (Dict): The dictionary to sign.
        digest_passphrase (str): The passphrase used as the HMAC key.

    Returns:
        str: A hexadecimal HMAC-SHA256 digest string.
    """
    if not isinstance(data, dict):
        log.error("Data must be a dictionary for digest computation.")
        raise TypeError("Data must be a dictionary for digest computation.")
    if not isinstance(digest_passphrase, str):
        log.error("Digest passphrase must be a string.")
        raise TypeError("Digest passphrase must be a string.")

    key = digest_passphrase.encode("utf-8")
    message = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


@FunctionProfiler.track()
def verify_digest(data: Dict, digest_passphrase: str) -> bool:
    """
    Verify that the HMAC-SHA256 digest in the data matches the expected value.

    Args:
        data (Dict): A dictionary that includes a "digest" key and signed payload.
        digest_passphrase (str): The passphrase used to recompute the HMAC digest.

    Returns:
        bool: True if the digest is valid; False otherwise.

    Raises:
        ValueError: If the "digest" field is missing from the input data.
    """
    provided_digest = data.get("digest")
    if not provided_digest:
        log.error("Missing 'digest' field in input data.")
        raise ValueError("No digest found in input data.")

    # Compute expected digest from a copy of the data without the "digest" field
    data_to_verify = data.copy()
    data_to_verify.pop("digest")

    expected_digest = compute_digest(data_to_verify, digest_passphrase)
    is_valid = hmac.compare_digest(provided_digest, expected_digest)

    if not is_valid:
        log.warning("Digest verification failed.")

    return is_valid


@FunctionProfiler.track()
def handle_digest_verification(
    json_data: Dict,
    digest_passphrase: Optional[str],
    require_digest: bool = True
) -> None:
    """
    Validate digest presence and correctness before proceeding with decryption.

    Args:
        json_data (Dict): The encrypted message as a parsed JSON dictionary.
        digest_passphrase (Optional[str]): The passphrase used to verify the digest (if any).
        require_digest (bool): Whether to enforce the presence and validation of a digest.

    Raises:
        ValueError: If the digest check fails or expectations are mismatched.
    """
    has_digest = "digest" in json_data
    has_passphrase = bool(digest_passphrase)

    if has_digest and has_passphrase:
        if not verify_digest(json_data, digest_passphrase):
            log.error("Digest verification failed. Message may have been tampered with.")
            raise ValueError("Digest verification failed. Message may have been tampered with.")
    elif has_digest and not has_passphrase:
        log.error("Digest present, but no passphrase provided to verify it.")
        raise ValueError("Encrypted message contains a digest, but no digest passphrase was provided.")
    elif not has_digest and has_passphrase:
        log.error("Passphrase provided, but message does not contain a digest.")
        raise ValueError("Digest passphrase was provided, but the message contains no digest.")
    elif not has_digest and not has_passphrase and require_digest:
        log.error("Digest required, but not present.")
        raise ValueError("No digest present. Digest is required for this decryption.")


def init_worker_shared(shm_name: str, size: int) -> None:
    """
    Initialize shared memory in a worker process for parallel-safe read access.

    This function runs once in each child process to attach to a pre-existing
    shared memory block. It populates a global list of characters (`PADDING_LIST`)
    by decoding and splitting the shared memory contents.

    Args:
        shm_name (str): The name of the existing shared memory block.
        size (int): The number of bytes to read from the shared memory block.

    Globals:
        PADDING_LIST (List[str]): Global character list available to all workers.
        _worker_shm (SharedMemory): Handle to the shared memory block.
    """
    global PADDING_LIST, _worker_shm

    # 1. Attach to shared memory block by name
    _worker_shm = shared_memory.SharedMemory(name=shm_name)

    # 2. Extract `size` bytes and decode from UTF-8
    memory_slice = _worker_shm.buf[:size]
    decoded_string = memory_slice.tobytes().decode("utf-8")

    # 3. Split into a list of single-character strings
    PADDING_LIST = list(decoded_string)


def _unpack_get_coord(args: Tuple[int, str, int, bytes, int]) -> Tuple[int, Any]:
    """
    Unpack arguments and call get_coord_math without needing to pass PADDING_LIST explicitly.

    This is used for multiprocessing where the global PADDING_LIST is initialized in each worker.
    Avoids pickling large shared structures by relying on per-process setup via init_worker_shared.

    Args:
        args (Tuple): A tuple of (index, character, grid_size, grid_seed, time).

    Returns:
        Tuple[int, Any]: Output from get_coord_math, typically (index, [x, y, z]).
    """
    index, character, grid_size, grid_seed, time = args
    return get_coord_math(index, character, grid_size, grid_seed, time)


def encrypt(
    password: str,
    redundancy: int,
    message: str,
    digest_passphrase: str = "",
    max_workers: int = CONFIG["parallel"]["cpu_count"],
    chunksize: int = CONFIG["parallel"]["chunksize"]
) -> Dict[str, Union[List[List[int]], List[int], int, str]]:
    """
    Encrypt a plaintext message into coordinate-based cipher data using a grid system.

    Args:
        password (str): The user-provided password for key derivation.
        redundancy (int): Number of times to repeat the expanded character list in the grid.
        message (str): The plaintext message to encrypt.
        digest_passphrase (str): Optional passphrase to generate a digest.
        max_workers (int): Number of parallel worker processes to use.
        chunksize (int): Chunk size for parallel processing.

    Returns:
        Dict: A JSON-serializable dictionary with cipher data and metadata.
    """
    # --- Input validation ---
    if not isinstance(password, str) or not 3 <= len(password) <= 256:
        log.error("Password must be a string between 3 and 256 characters.")
        raise ValueError("Password must be a string between 3 and 256 characters.")

    if not isinstance(redundancy, int) or redundancy < 1:
        log.error("Redundancy must be a positive integer.")
        raise ValueError("Redundancy must be a positive integer.")

    if not isinstance(message, str) or not message:
        log.error("Message must be a non-empty string.")
        raise ValueError("Message must be a non-empty string.")

    if digest_passphrase and not 3 <= len(digest_passphrase) <= 256:
        log.error("Digest passphrase must be between 3 and 256 characters.")
        raise ValueError("Digest passphrase must be between 3 and 256 characters.")

    # --- Key and salt generation ---
    salt = generate_salt()
    start_time, time_increment, grid_seed = generate_key_materials(password, salt)

    # --- Character validation ---
    message_set = set(message)
    if not message_set.issubset(CHARACTER_SET):
        invalid_chars = message_set - CHARACTER_SET
        log.error("Input contains unmapped characters: %s", invalid_chars)
        raise ValueError(f"Cannot encrypt unsupported characters: {invalid_chars}")

    all_blocks_union = set().union(*CHARACTER_BLOCKS)
    missing_from_master = message_set - all_blocks_union
    if missing_from_master:
        log.error("Characters missing from all blocks: %s", missing_from_master)
        raise ValueError(f"Characters not in any block: {missing_from_master}")

    block_indexes = find_used_character_block_indexes(CHARACTER_BLOCKS, message_set)

    used_chars = set()
    for idx in block_indexes:
        used_chars.update(CHARACTER_BLOCKS[idx])

    missing_after_selection = message_set - used_chars
    if missing_after_selection:
        log.error("Selected blocks do not cover characters: %s", missing_after_selection)
        raise ValueError(f"Missing characters after block selection: {missing_after_selection}")

    # --- Character grid setup ---
    expanded_character_list = collect_chars_by_indexes(CHARACTER_BLOCKS, block_indexes)
    grid_size = calculate_minimum_grid_size(len(expanded_character_list), redundancy)
    padded_chars = pad_character_list_to_grid(expanded_character_list, grid_size)

    joined_str = "".join(padded_chars)
    utf8_bytes = joined_str.encode("utf-8")
    size_bytes = len(utf8_bytes)

    shm = shared_memory.SharedMemory(create=True, size=size_bytes)
    shm.buf[:size_bytes] = utf8_bytes

    # --- Task preparation ---
    tasks = [
        (i, ch, grid_size, grid_seed, start_time + i * time_increment)
        for i, ch in enumerate(message)
    ]
    encrypted_output = [None] * len(tasks)

    max_workers = max(1, max_workers)
    chunksize = max(1, chunksize)

    log.info("[main.encrypt] max_workers: %d, chunksize: %d", max_workers, chunksize)

    # --- Coordinate generation with multiprocessing ---
    try:
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker_shared,
            initargs=(shm.name, size_bytes)
        ) as executor:
            for idx, coords in executor.map(_unpack_get_coord, tasks, chunksize=chunksize):
                encrypted_output[idx] = coords
    except Exception as e:
        log.error("An unexpected exception has been raised: %s", e)
        raise Exception(f"An unexpected exception has been raised: {e}") from e  # pylint: disable=broad-exception-raised
    finally:
        shm.close()
        shm.unlink()

    # --- Result packaging ---
    json_output = {
        "cipher_text": encrypted_output,
        "character_blocks": block_indexes,
        "redundancy": redundancy,
        "salt": salt.hex(),
    }

    if digest_passphrase:
        json_output["digest"] = compute_digest(json_output, digest_passphrase)

    return json_output


def _unpack_get_char(args: Tuple[int, List[int], int, bytes, int]) -> Tuple[int, Any]:
    """
    Unpack arguments and call get_char_math using the global PADDING_LIST.

    This function is designed for use with multiprocessing where PADDING_LIST
    is initialized in each worker via init_worker_shared. It avoids passing
    large structures repeatedly by relying on per-process global setup.

    Args:
        args (Tuple): A tuple containing:
            - index (int)
            - coordinates (List[int])
            - grid_size (int)
            - grid_seed (bytes)
            - time (int)

    Returns:
        Tuple[int, Any]: Result from get_char_math, typically (index, character).
    """
    index, coords, grid_size, grid_seed, time = args
    return get_char_math(index, coords, grid_size, grid_seed, time)


@FunctionProfiler.track()
def decrypt(
    password: str,
    json_data: Dict,
    digest_passphrase: str = "",
    max_workers: int = CONFIG["parallel"]["cpu_count"],
    chunksize: int = CONFIG["parallel"]["chunksize"]
) -> str:
    """
    Decrypt a coordinate-based cipher into its original plaintext message.

    Args:
        password (str): The password used during encryption.
        json_data (Dict): Contains metadata and cipher coordinates:
            - "salt": Hex-encoded string used for key derivation.
            - "character_blocks": List of indexes into CHARACTER_BLOCKS.
            - "redundancy": Repetition factor used to pad the grid.
            - "cipher_text": List of [x, y, z] coordinates.
        digest_passphrase (str): Passphrase to verify message integrity.
        max_workers (int): Number of parallel processes.
        chunksize (int): Chunk size per worker.

    Returns:
        str: The decrypted plaintext message.
    """
    # --- Input validation ---
    if not isinstance(password, str) or not 3 <= len(password) <= 256:
        log.error("Password must be a string between 3 and 256 characters.")
        raise ValueError("Password must be a string between 3 and 256 characters.")

    if digest_passphrase and not 3 <= len(digest_passphrase) <= 256:
        log.error("Digest passphrase must be between 3 and 256 characters.")
        raise ValueError("Digest passphrase must be between 3 and 256 characters.")

    # --- Verify digest ---
    handle_digest_verification(
        json_data, digest_passphrase=digest_passphrase, require_digest=True
    )

    # --- Extract fields from input JSON ---
    salt = json_data["salt"]
    character_blocks = json_data["character_blocks"]
    redundancy = json_data["redundancy"]
    cipher_text = json_data["cipher_text"]

    # --- Derive key materials from password + salt ---
    salt_bytes = bytes.fromhex(salt)
    start_time, time_increment, grid_seed = generate_key_materials(password, salt_bytes)

    # --- Reconstruct padded character grid ---
    expanded_chars = collect_chars_by_indexes(CHARACTER_BLOCKS, character_blocks)
    grid_size = calculate_minimum_grid_size(len(expanded_chars), redundancy)
    padded_chars = pad_character_list_to_grid(expanded_chars, grid_size)

    utf8_bytes = "".join(padded_chars).encode("utf-8")
    size_bytes = len(utf8_bytes)

    shm = shared_memory.SharedMemory(create=True, size=size_bytes)
    shm.buf[:size_bytes] = utf8_bytes

    # --- Prepare tasks for parallel decoding ---
    tasks = [
        (i, coords, grid_size, grid_seed, start_time + i * time_increment)
        for i, coords in enumerate(cipher_text)
    ]

    message: List[Optional[str]] = [None] * len(tasks)
    max_workers = max(1, max_workers)
    chunksize = max(1, chunksize)

    log.info("[main.decrypt] max_workers: %d, chunksize: %d", max_workers, chunksize)

    # --- Coordinate resolution via multiprocessing ---
    try:
        with ProcessPoolExecutor(
            max_workers=max_workers,
            initializer=init_worker_shared,
            initargs=(shm.name, size_bytes)
        ) as executor:
            for idx, char in executor.map(_unpack_get_char, tasks, chunksize=chunksize):
                message[idx] = char
    except Exception as e:
        log.error("An unexpected exception has been raised: %s", e)
        raise Exception(f"An unexpected exception has been raised: {e}") from e  # pylint: disable=broad-exception-raised
    finally:
        shm.close()
        shm.unlink()

    return "".join(cast(List[str], message))
