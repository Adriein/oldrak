import csv
import queue
import struct
import sys
import zlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from oldrak.os import TcpStreamSet
from oldrak.engine.packet import TibiaTcpPacket
from oldrak.os.decryption import Xtea
from oldrak.shared import ServerPacketType, ClientPacketType


class GameSession:
    def __init__(self, tcp_stream: Optional[TcpStreamSet]):
        self._tcp_stream = tcp_stream
        self._incomplete_buffer = TcpStreamSet()


    def flush_raw(self) -> None:
        timestamp = datetime.now().strftime("%Y%m%d")

        session_file = Path(f"{timestamp}_tcp_session.csv")

        sid, buf = self._tcp_stream.get_server_stream()

        with session_file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            writer.writerow(['raw'])

            while not buf.empty():
                raw = buf.get_nowait()

                writer.writerow([raw.hex(" ")])

    def flush(self, record = False) -> None:
        if not record:
            return

        timestamp = datetime.now().strftime("%Y%m%d")

        session_file = Path(f"{timestamp}_tcp_session.csv")

        sid, buf = self._tcp_stream.get_server_stream()

        with session_file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            writer.writerow(['src', 'src_port', 'sequence', 'actual_size', 'expected_size', 'is_compressed', 'payload'])

            while not buf.empty():
                raw = buf.get_nowait()

                t_packet = TibiaTcpPacket.from_bytes(stream_id=sid, raw_bytes=raw)

                if not t_packet.is_valid:
                    incomplete_buff = self._incomplete_buffer[sid]

                    if incomplete_buff.empty():
                        raise Exception("Invalid packet in the sequence")

                    prev_bytes = incomplete_buff.get_nowait()

                    prev_packet = TibiaTcpPacket.from_bytes(stream_id=sid, raw_bytes=prev_bytes)

                    missing_offset = prev_packet.expected_size - prev_packet.actual_size

                    missing_bytes = raw[:missing_offset]

                    prev_packet.payload += missing_bytes
                    prev_packet.actual_size = len(prev_packet.payload)

                    if prev_packet.is_incomplete():
                        incomplete_buff.put_nowait(prev_packet.to_bytes())

                        continue

                    next_bytes = raw[missing_offset:]

                    if len(next_bytes) == 0:
                        writer.writerow([
                            prev_packet.src,
                            prev_packet.src_port,
                            prev_packet.sequence,
                            prev_packet.actual_size,
                            prev_packet.expected_size,
                            prev_packet.is_compressed,
                            prev_packet.payload.hex(" ")
                        ])

                        continue

                    t_packet = TibiaTcpPacket.from_bytes(stream_id=sid, raw_bytes=next_bytes)

                if t_packet.is_incomplete():
                    incomplete_buff = self._incomplete_buffer[sid]

                    incomplete_buff.put_nowait(raw)

                    continue

                if t_packet.is_composed():
                    raise Exception("Packet is composed")

                writer.writerow([
                    t_packet.src,
                    t_packet.src_port,
                    t_packet.sequence,
                    t_packet.actual_size,
                    t_packet.expected_size,
                    t_packet.is_compressed,
                    t_packet.payload.hex(" ")
                ])

class SessionDebugger:
    def __init__(self):
        self.decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)

    def replay_raw(self, session_id: str) -> None:
        session_file = Path(f"{session_id}_tcp_session.csv")
        keys_file = Path("key.txt")

        result = []

        with keys_file.open(mode='r', newline='', encoding='utf-8') as kf:
            keys = [int(k) for k in kf.read().split(',') if k.strip()]

        with session_file.open(mode='r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            prev_sequence = 0

            for row in reader:
                raw_bytes = bytes.fromhex(row['raw'].replace(" ", ""))

                # The first 2 bytes are the size of the payload in multiples of 8 bytes in little endian.
                size = int.from_bytes(raw_bytes[:2], sys.byteorder, signed=False) * 8

                # Next 2 bytes = sequence number
                sequence = int.from_bytes(raw_bytes[2:4], sys.byteorder, signed=False)

                sequence_delta = sequence - prev_sequence

                # Next 2 bytes = compression flag
                compression_flag = raw_bytes[4:6]

                compressed_literal_flag = 0xC000.to_bytes(2, sys.byteorder, signed=False)
                not_compressed_literal_flag = 0x0000.to_bytes(2, sys.byteorder, signed=False)

                is_compressed = compression_flag == compressed_literal_flag
                is_valid = is_compressed or compression_flag == not_compressed_literal_flag

                if sequence_delta > 1 or not is_valid:
                    prev_packet = result.pop()
                    if prev_packet.seq == 2:
                        print(prev_packet.payload.hex(" "))

                    prev_packet.payload += raw_bytes

                    if prev_packet.seq == 2:
                        print(prev_packet.payload.hex(" "))

                    result.append(prev_packet)

                    continue

                # The rest = payload
                payload = raw_bytes[6:]

                packet = RawPacket(sequence, size, is_compressed, payload)

                result.append(packet)

                prev_sequence = sequence

        xtea = Xtea(keys)

        for index, raw in enumerate(result):
            c = len(raw.payload)
            payload = xtea.decrypt(raw.payload)
            a = len(payload)
            # Remove junk bytes, the first byte indicates the byte padding (0-7)
            padding = int.from_bytes(payload[:1], "little", signed=False)

            if 0 <= padding <= 7:
                payload = payload[1:-padding] if padding > 0 else payload[1:]
                b = len(payload)
            if raw.is_compressed:
                print(f"Seq {raw.seq}: compressed={raw.is_compressed}, size={raw.size}, payload={payload.hex(" ")}")
                b = bytes.fromhex("AA 45 B9 01 00 00 00 4C 6F 6D 70 65 20 44 72 75 69 64 00 9E 01 07 07 00 00 00 61 6D".replace(" ", ""))

                FORMAT_STRING = '<i2s?h'

                try:
                    command_type = ServerPacketType(int.from_bytes(b[:1], sys.byteorder))
                    payload = payload[1:]
                except (TypeError, ValueError):
                    command_type = f"Unknown: {b[:1].hex()}"
                    payload = payload[1:]

                unpacked_data = struct.unpack(FORMAT_STRING, b[1:10])

                int32_val = unpacked_data[0]
                string_val = unpacked_data[1]
                bool_val = unpacked_data[2]
                int16_val = unpacked_data[3]

                print(f"Bytes used (First 9): {b[0:9].hex(' ', 1)}")
                print("-" * 30)
                print(f"1. int32 (4 bytes):      {int32_val}")
                print(f"2. 2-byte string (bytes):{string_val} (Decoded: {string_val.decode('ascii')!r})")
                print(f"3. bool (1 byte):        {bool_val}")
                print(f"4. int16 (2 bytes):      {int16_val}")



                print(b)

            # if raw.is_compressed:
            #     print("RAW payload")
            #     print(payload.hex(" "))
            #     print("-----------------------------------------------------------------------------------------")
            #     out = self.decompressor.decompress(payload)
            #
            #     print(
            #         f"Size: {raw.size} (bytes) | Seq: {raw.seq} | Com: {raw.is_compressed}\n"
            #         f"Payload ({len(raw.payload)} bytes): {out.hex(" ")}\n"
            #     )
            #
            #     continue
            #
            # command_byte = payload[:1]
            # try:
            #     command_type = ClientPacketType(int.from_bytes(command_byte, sys.byteorder))
            #     payload = payload[1:]
            # except (TypeError, ValueError):
            #     command_type = f"Unknown: {command_byte.hex()}"
            #     payload = payload[1:]
            #
            # print(
            #     f"Size: {raw.size} (bytes) | Seq: {raw.seq} | Com: {raw.is_compressed} | Type: {command_type}\n"
            #     f"Payload ({len(raw.payload)} bytes): {payload.hex(" ")}\n"
            # )

    def replay(self, session_id: str) -> None:
        session_file = Path(f"{session_id}_tcp_session.csv")
        keys_file = Path("key.txt")

        with keys_file.open(mode='r', newline='', encoding='utf-8') as f:
            keys = [int(k) for k in f.read().split(',') if k.strip()]

        with session_file.open(mode='r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                src = row['src']
                src_port = row['src_port']
                sequence = row['sequence']
                size = row['expected_size']
                is_compressed = row['is_compressed']
                payload = row['payload']

                t_packet = TibiaTcpPacket(
                        src,
                        "unknown",
                        int(src_port),
                        0,
                        int(size),
                        int(sequence),
                        is_compressed == 'True',
                        bytes.fromhex(payload),
                        True,
                )

                t_packet.decrypt(Xtea(keys))

                if not t_packet.is_compressed:
                    t_packet.parse()
                    print(t_packet)
                    print("-" * 100)

                if t_packet.is_compressed:
                    t_packet.dec(self.decompressor)

                #
                # if t_packet.is_compressed is False:
                #     t_packet.parse()
                #     print(t_packet)
                #     print("-" * 20)


class RawPacket:
    def __init__(self, seq: int, size: int, is_compressed: bool, payload: bytes):
        self.seq = seq
        self.size = size
        self.is_compressed = is_compressed
        self.payload = payload
