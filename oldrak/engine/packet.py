import sys
import zlib

from oldrak.os import Xtea
from oldrak.shared import ClientPacketType, ServerPacketType


class TibiaTcpPacket:
    def __init__(
            self,
            src: str,
            dest: str,
            src_port: int,
            dest_port: int,
            raw_size: int,
            sequence: int,
            is_compressed: bool,
            payload: bytes,
            is_valid: bool,
    ) -> None:
        self.src = src
        self.dest = dest
        self.src_port = src_port
        self.dest_port = dest_port
        self.expected_size = raw_size
        self.actual_size = len(payload)
        self.sequence = sequence
        self.is_compressed = is_compressed
        self.is_valid = is_valid
        self.payload = payload

        self.is_decrypted = False
        self.type = None

    @staticmethod
    def from_bytes(stream_id: tuple[str, int, str, int], raw_bytes: bytes) -> 'TibiaTcpPacket':
        src, src_port, dest, dest_port = stream_id

        if len(raw_bytes) < 6:
            raise Exception("Too small to be a valid packet")

        # The first 2 bytes are the size of the payload in multiples of 8 bytes in little endian.
        size = int.from_bytes(raw_bytes[:2], sys.byteorder, signed=False) * 8

        # Next 2 bytes = sequence number
        sequence = int.from_bytes(raw_bytes[2:4], sys.byteorder, signed=False)

        # Next 2 bytes = compression flag
        compression_flag = int.from_bytes(raw_bytes[4:6], sys.byteorder, signed=False)

        is_compressed = compression_flag == 0xC000
        is_valid = is_compressed or compression_flag == 0x0000

        # The rest = payload
        payload = raw_bytes[6:]

        return TibiaTcpPacket(
            src,
            dest,
            src_port,
            dest_port,
            size,
            sequence,
            is_compressed,
            payload,
            is_valid,
        )

    def to_bytes(self) -> bytes:
        """
        Convert the TibiaTcpPacket back to raw bytes.

        Returns:
            bytes: The raw packet bytes including header and payload
        """
        # Calculate size in multiples of 8 bytes
        size_value = self.expected_size // 8

        # Build header (6 bytes total)
        size_bytes = size_value.to_bytes(2, sys.byteorder, signed=False)
        sequence_bytes = self.sequence.to_bytes(2, sys.byteorder, signed=False)

        # Compression flag
        compression_flag = 0xC000 if self.is_compressed else 0x0000
        compression_bytes = compression_flag.to_bytes(2, sys.byteorder, signed=False)

        # Combine header and payload
        raw_bytes = size_bytes + sequence_bytes + compression_bytes + self.payload

        return raw_bytes

    def __repr__(self) -> str:
        return (
            f"{self.src}:{self.src_port} -> {self.dest}:{self.dest_port}\n"
            f"Size Header: {self.expected_size} (bytes) | Seq: {self.sequence} | Comp: {self.is_compressed}\n"
            f"Real Size: {self.actual_size}\n"
            f"Payload ({len(self.payload)} bytes): {self.payload.hex(" ")}\n"
            f"Type: {self.type}"
        )

    def decrypt(self, xtea: Xtea) -> None:
        decrypted_payload = xtea.decrypt(self.payload)

        #Remove junk bytes, the first byte indicates the byte padding (0-7)
        padding = int.from_bytes(decrypted_payload[:1], "little")

        if 0 <= padding <= 7:
            self.payload = decrypted_payload[1 : len(decrypted_payload) - padding]

            self.is_decrypted = True
            return

        self.payload = decrypted_payload

        self.is_decrypted = True

    def dec(self, decompressor: 'zlib.decompressobj') -> bytes|None:
        if not self.is_compressed:
            return

        try:
            out = decompressor.decompress(self.payload)

            #Optional monitoring info
            print(f"Decompressed {len(out)} bytes")
            print(f"Bytes consumed from payload: {len(self.payload) - len(decompressor.unconsumed_tail)}")
            print(f"Unconsumed tail length: {len(decompressor.unconsumed_tail)}")
            print(f"Unused data length: {len(decompressor.unused_data)}")

            self.payload = out

        except zlib.error as e:
            print(f"Streaming decompression error: {e}")

    def parse(self,) -> None:
        if not self.is_decrypted:
            raise Exception("Packet is not decrypted")

        try:
            command_byte = self.payload[:1]

            if self.is_client_packet():
                self.type = ClientPacketType(int.from_bytes(command_byte, sys.byteorder))
                self.payload = self.payload[1:]

                return

            self.type = ServerPacketType(int.from_bytes(command_byte, sys.byteorder))
            self.payload = self.payload[1:]
        except (TypeError, ValueError):
            pass

    def is_client_packet(self) -> bool:
        return self.src_port != 7171

    def is_incomplete(self) -> bool:
        return self.expected_size > self.actual_size

    def is_composed(self) -> bool:
        return self.expected_size < self.actual_size