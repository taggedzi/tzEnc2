
from collections import defaultdict
import math
import random
import secrets
import struct
from typing import Any, Union, List, Set, Tuple, TypeVar
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from src.tzEnc2 import CHARACTER_BLOCKS, CHARACTER_SET
from src.tzEnc2.config import CONFIG
T = TypeVar("T")  # Allow generic lists of any type

def generate_salt():
    """Generate a cryptographic salt."""
    return secrets.token_bytes(16)  # 16 bytes = 128 bits


def generate_multiple_keys(
    password: str,
    salt: bytes,
    bits: int,
    memory_cost: int,
    time_cost: int,
    parallelism: int,
    key_count: int
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
        type=Type.ID
    )

    keys = []
    for i in range(key_count):
        keys.append(derived[i * c_bytes:(i + 1) * c_bytes])
    return keys


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
    grid_seed = key_materials[2]

    return (start_time, time_increment, grid_seed)


def find_used_character_block_indexes(
    list_of_lists: List[List[str]],
    message_char_set: Set[str]
) -> List[int]:
    """
    Find the indexes of character blocks (sublists) that contain any characters
    from the given message character set. For each matching block, remove the
    matched characters from a copy of the set. Stops when all characters are matched
    or the list is exhausted. The original set is not modified.

    Args:
        list_of_lists (List[List[str]]): A list of character blocks (each a list of characters).
        message_char_set (Set[str]): A set of characters from the input message to be matched.

    Returns:
        List[int]: A list of unique indexes of blocks that contributed characters to the message.
    """
    remaining_chars = set(message_char_set)  # make a local copy
    result: List[int] = []

    for idx, char_list in enumerate(list_of_lists):
        if not remaining_chars:
            break

        if any(char in remaining_chars for char in char_list):
            result.append(idx)
            remaining_chars.difference_update(char_list)

    return result


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
        AssertionError: If `base_bytes` is not 32 bytes or `aes_bits` is not one of the allowed sizes.
    """
    assert aes_bits in (128, 192, 256), "AES bit length must be 128, 192, or 256"
    assert len(base_bytes) == 32, "base_bytes must be exactly 256 bits (32 bytes)"

    number_bytes = number.to_bytes((number.bit_length() + 7) // 8 or 1, 'big')

    hasher = SHA256.new()
    hasher.update(base_bytes)
    hasher.update(number_bytes)

    return hasher.digest()[:aes_bits // 8]


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
        AssertionError: If the key is not 16 bytes long.
    """
    assert len(key) == 16, "Key must be 16 bytes (128 bits) for AES-128"

    # Each AES block (16 bytes) yields two 64-bit unsigned integers
    blocks_needed = (count + 1) // 2

    # Initialize AES in CTR mode with a 128-bit counter
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    random_ints: List[int] = []
    for _ in range(blocks_needed):
        block = cipher.encrypt(b'\x00' * 16)
        a, b = struct.unpack('>QQ', block)
        random_ints.extend((a, b))

    return random_ints[:count]


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


def pad_character_list_to_grid(expanded_character_list: List[str], grid_size: int) -> List[str]:
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
    volume = grid_size ** 3
    repeat_count = (volume + len(expanded_character_list) - 1) // len(expanded_character_list)

    return (expanded_character_list * repeat_count)[:volume]



def find_char_locations_in_list(in_char:str, char_list:List[str]) -> List[int]:
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
    shuffled_character_list = shuffle_list(
        character_list=character_list,
        seed=grid_seed,
        time=time
    )

    character_index_list = find_char_locations_in_list(
        in_char=character,
        char_list=shuffled_character_list
    )

    chosen_index = secrets.choice(character_index_list)

    # Compute 3D grid coordinates from linear index
    z = chosen_index % grid_size
    y = (chosen_index // grid_size) % grid_size
    x = chosen_index // (grid_size * grid_size)

    return [x, y, z]


def get_char_math(
    coords: Union[List[int], Tuple[int, int, int]],
    character_list: List[str],
    grid_size: int,
    grid_seed: bytes,
    time: int
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
    if len(coords) != 3:
        raise ValueError("Coordinates must be a 3-element list or tuple (x, y, z).")

    x, y, z = coords
    index = x * (grid_size ** 2) + y * grid_size + z

    shuffled_character_list = shuffle_list(
        character_list=character_list,
        seed=grid_seed,
        time=time
    )

    if index >= len(shuffled_character_list):
        raise IndexError(f"Grid index {index} is out of bounds for shuffled list length {len(shuffled_character_list)}.")

    return shuffled_character_list[index]


def collect_chars_by_indexes(character_blocks: List[List[str]], indexes: List[int]) -> List[str]:
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


def encrypt(password:str, redundancy:int, message:str):
    
    # Generate all crypto stuff, salts/settings/seeds
    salt = generate_salt()
    start_time, time_increment, grid_seed = generate_key_materials(password=password, salt=salt)
    current_time = start_time
    
    # Verify message doesn't contain unmapped characters.
    message_set = set(message)
    if not set(message_set).issubset(CHARACTER_SET):
        unmapped_characters = message_set - CHARACTER_SET
        raise ValueError(f"Input contains unmapped charcters that cannot be encrypted: {unmapped_characters}")

    # Get Blocks
    block_indexes = find_used_character_block_indexes(CHARACTER_BLOCKS, set(message))

    # Build character block list
    expanded_character_list = collect_chars_by_indexes(CHARACTER_BLOCKS, block_indexes)

    # Determine Grid Size
    grid_size = calculate_minimum_grid_size(len(expanded_character_list), redundancy)
    
    # Pad character list to fill in gaps.
    padded_expanded_character_list = pad_character_list_to_grid(expanded_character_list=expanded_character_list, grid_size=grid_size)

    # Build list of coords
    encrypted_output = []
    
    for character in message:
        encrypted_output.append(get_coord_math(character=character, character_list=padded_expanded_character_list, grid_size=grid_size, grid_seed=grid_seed, time=current_time))
        current_time += time_increment
    
    json_output = {
        "cipher_text": encrypted_output,
        "character_blocks": block_indexes,
        "redundancy": redundancy,
        "salt": salt.hex()
    }
    return json_output

def decrypt(password:str, json_data:dict) -> str:
    
    salt = json_data["salt"]
    character_blocks = json_data["character_blocks"]
    redundancy = json_data["redundancy"]
    cipher_text = json_data['cipher_text']

    # build keys from password
    salt_bytes = bytes.fromhex(salt)
    start_time, time_increment, grid_seed = generate_key_materials(password=password, salt=salt_bytes)
    current_time = start_time
    
    # Build character block list
    expanded_character_list = collect_chars_by_indexes(CHARACTER_BLOCKS, character_blocks)
    
    # Determine Grid Size
    grid_size = calculate_minimum_grid_size(len(expanded_character_list), redundancy)
    
    # Pad character list to fill in gaps.
    padded_expanded_character_list = pad_character_list_to_grid(expanded_character_list=expanded_character_list, grid_size=grid_size)
    
    # loop through list
    message_list = []
    for coords in cipher_text:
        message_list.append(get_char_math(coords=coords, character_list=padded_expanded_character_list, grid_size=grid_size,
                      grid_seed=grid_seed, time=current_time))
        current_time += time_increment
    message = "".join(message_list)
    return message
    
    
if __name__ == "__main__":
    cipher = encrypt('test', 20, "hello there 뙱")
    print(cipher)
    message = decrypt('test', cipher)
    print(message)
    