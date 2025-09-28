import sys

from xtea import new, MODE_ECB

class Xtea:
    def __init__(self, keys: list[int]):
        if len(keys) != 4:
            raise ValueError("Key must be 4 integers long.")

        key_bytes = b''.join(key.to_bytes(4, byteorder=sys.byteorder, signed=False) for key in keys)

        self._xtea = new(key_bytes, mode=MODE_ECB, rounds=64, endian="<" if sys.byteorder == "little" else ">")

    def decrypt(self, data: bytes) -> bytes:
        decrypted_data = self._xtea.decrypt(self._pad_data(data))

        return decrypted_data

    def _pad_data(self, data: bytes, length: int = 8) -> bytes:
        missing_bytes = (length - len(data) % length) % length

        return data + b"\x00" * missing_bytes

