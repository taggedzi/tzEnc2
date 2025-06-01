
from collections import defaultdict
import math
import random
import secrets
import struct
from typing import Any, Union, List
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from argon2.low_level import hash_secret_raw, Type
from src.tzEnc2 import CHARACTER_BLOCKS, CHARACTER_SET
from src.tzEnc2.config import CONFIG


def generate_salt():
    """Generate a cryptographic salt."""
    salt = secrets.token_bytes(16)  # 16 bytes = 128 bits
    return salt

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

def generate_key_materials(password: str, salt: bytes, message_length: int) -> tuple:
    """Generate the necessary key materials for encryption."""
    key_materials = generate_multiple_keys(
        password=password,
        salt=salt,
        time_cost=CONFIG["argon2id"]["time_cost"],
        bits=CONFIG["argon2id"]["bits"],
        memory_cost=CONFIG["argon2id"]["memory_cost"],
        parallelism=CONFIG["argon2id"]["parallelism"],
        key_count=3
    )
    max_increment = (CONFIG["MAX_INT"] // message_length) // 2
    time_increment = int.from_bytes(key_materials[1], byteorder="big") % max_increment
    max_start_time = CONFIG["MAX_INT"] - (max_increment * message_length)
    start_time = int.from_bytes(key_materials[0], byteorder="big") % max_start_time
    grid_seed = key_materials[2]
    result = (start_time, time_increment, grid_seed)
    return result

def find_used_character_block_indexes(list_of_lists, message_char_set):
    result = []
    seen = set()

    for idx, char_list in enumerate(list_of_lists):
        # Fast intersection check
        if not message_char_set:
            break

        if any(char in message_char_set for char in char_list):
            if idx not in seen:
                seen.add(idx)
                result.append(idx)
                # Remove any matching characters from the message_char_set
                message_char_set.difference_update(char_list)

    return result




# def derive_aes_key(base_bytes: bytes, number: int, aes_bits: int = 128) -> bytes:
#     """
#     This takes in a byte based key (like seed) and a number (like time) and converts into a key 
#         for use in aes for a key of the specified size.

#     Args:
#         base_64bit (int): a 64bit integer
#         number (int): an integer of unknown size
#         aes_bits (int, optional): The number of bits to make the output key. Defaults to 128.

#     Returns:
#         bytes: a bytes type object of the size specified.
#     """
#     assert aes_bits in (128, 192, 256), "AES bit length must be 128, 192, or 256"
#     assert len(base_bytes) == 32, "base_bytes must be exactly 256 bits (32 bytes)"

#     # Convert the number to bytes
#     number_bytes = number.to_bytes((number.bit_length() + 7) // 8 or 1, 'big')

#     # Hash using pycryptodome SHA256
#     h = SHA256.new()
#     h.update(base_bytes)
#     h.update(number_bytes)

#     return h.digest()[:aes_bits // 8]

# def aes_prng_stream(key: bytes, count: int) -> List[int]:
#     """
#         Generate `count` 64-bit integers using AES in CTR mode.
#             Pseudo-Random Number Generator Stream.

#     Args:
#         key (bytes): The key to use for the generator
#         count (int): The length of the list to shuffle

#     Returns:
#         List[int]: a list of integers (random numbers).
#     """
#     assert len(key) == 16, "Key must be 16 bytes (128 bits) for AES-128"

#     # AES block size is 16 bytes, so we get two 64-bit ints per block
#     blocks_needed = (count + 1) // 2

#     # Initialize AES-CTR
#     ctr = Counter.new(128)
#     cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

#     random_ints = []
#     for _ in range(blocks_needed):
#         block = cipher.encrypt(b'\x00' * 16)
#         a, b = struct.unpack('>QQ', block)
#         random_ints.extend((a, b))

#     return random_ints[:count]


# def aes_deterministic_shuffle(data: List, key: bytes) -> List:
#     """Shuffle a list deterministically and securely using AES as the PRNG.

#     Args:
#         data (List): The list to be cryptographically shuffled
#         key (bytes): the key to use for deterministic shuffling

#     Returns:
#         List: A shuffled list.
#     """
#     shuffled = data.copy()
#     n = len(shuffled)

#     # Generate all random numbers needed for Fisher–Yates
#     random_ints = aes_prng_stream(key, n - 1)

#     for i in reversed(range(1, n)):
#         j = random_ints[n - i - 1] % (i + 1)
#         shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

#     return shuffled


#     def _fill_grid(self):
#         self._build_empty_grid()    # Build an empty grid to correct dimensions

#         # So far best way I've found to do this.
#         char_iter = iter(self.expanded_character_list)

#         for x, plane in enumerate(self.grid):
#             for y, row in enumerate(plane):
#                 for z, _ in enumerate(row):
#                     character = next(char_iter)
#                     row[z] = character # Update the grid
#                     self.reverse_grid[character].append([x, y, z]) # Build dictionary of chars/locations


#     def _shuffle_list(self, time: int) -> list:
#         """Criptographically shuffle a list in a deterministic way.
#         Args:
#             time (int): The time to use for grid construction (partial seed)
#         """
#         key = derive_aes_key(self.seed_bytes, time)
#         shuffled = aes_deterministic_shuffle(self.expanded_character_list, key)
#         self.expanded_character_list = shuffled


#     def _create_expanded_character_list(self):
#         self.expanded_character_list = self.character_list * self.redundancy


#     def _pad_expanded_character_list(self):
#         grid_volume = self.grid_size ** 3
#         character_list_length = len(self.character_list)
#         expanded_list_length = len(self.expanded_character_list)
#         difference = grid_volume - expanded_list_length

#         if difference > 0:
#             add_loops = math.ceil(difference / character_list_length)
#             self.expanded_character_list += self.character_list * add_loops

#         self.expanded_character_list = self.expanded_character_list[:grid_volume]


#     def _calculate_grid_size(self):
#         self.grid_size = math.ceil(len(self.expanded_character_list) ** (1/3))


#     def _prep_lists(self, time: int):
#         if time < 0:
#             raise ValueError(f"Time must be a possitive integer. Got '{time}'.")
#         self._create_expanded_character_list()    # build the character list to fill redundancey
#         self._calculate_grid_size()               # calculate a grid that completely encompases the expanded character list
#         self._pad_expanded_character_list()       # pad the expanded character list to ensure there are no empty values
#         self._shuffle_list(time)                     # Shuffle the expanded character list psudo randomly based on seed and time.


#     def _build_grid(self, time: int) -> list[list[list[int]]]:
#         self._prep_lists(time)         # Do all prepwork to make sure lists are ready
#         self._fill_grid()           # Fill the grid with the characters.


#     def get_coord(self, character: str, time: int) -> list[int]:

       
#         self._build_grid(time=time)
#         return random.choice(self.reverse_grid[character])
    

#     def get_char(self, coordinates: Union[list[int], tuple[int, int, int]], time:int) -> str:

        
#         self._build_grid(time=time)
#         x, y, z = coordinates
#         return self.grid[x][y][z]
    

#     def _find_character_indexes(self, in_character: str) -> list[int]:
#         # find all the results that happen in the expanded_character_list
#         coordinates_for_character = []
#         for index, expanded_character in enumerate(self.expanded_character_list):
#             if expanded_character == in_character:
#                 coordinates_for_character.append(index)
#         return coordinates_for_character


#     def get_coord_math(
#             self,
#             character: str,
#             time: int
#         ) -> list[int]:
#         self._prep_lists(time = time)
#         character_index_list = self._find_character_indexes(in_character = character)
#         result = []
#         for option in character_index_list:
#             z = option % self.grid_size
#             y = (option // self.grid_size) % self.grid_size
#             x = option // (self.grid_size * self.grid_size)
#             result.append([x, y, z])
#         return random.choice(result)


#     def get_char_math(
#             self,
#             coords: Union[list[int], tuple[int, int, int]],
#             time: int
#         ) -> str:
        
#         x, y, z = coords
#         self._build_grid(time=time)
#         index = x * (self.grid_size ** 2) + y * self.grid_size + z
#         return self.expanded_character_list[index]

def main(password:str, message:str):
    
    # Generate all crypto stuff, salts/settings/seeds
    salt = generate_salt()
    print(salt)
    start_time, time_increment, grid_seed = generate_key_materials(password=password, salt=salt, message_length=len(message))
    print(start_time, time_increment, grid_seed)
    
    # Verify message doesn't contain unmapped characters.
    message_set = set(message)
    if not set(message_set).issubset(CHARACTER_SET):
        unmapped_characters = message_set - CHARACTER_SET
        raise ValueError(f"Input contains unmapped charcters that cannot be encrypted: {unmapped_characters}")
    print(message_set)

    # Get Blocks
    block_indexes = find_used_character_block_indexes(CHARACTER_BLOCKS, set(message))
    print(block_indexes)
    
    
    # Determine Grid Size
    # Build grids, assemble message.
    

if __name__ == "__main__":
    main('test', "hello there 뙱")
