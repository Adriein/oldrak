import csv
import queue
import sys
import zlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from oldrak.os import TcpStreamSet
from oldrak.engine.packet import TibiaTcpPacket
from oldrak.os.decryption import Xtea


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

    def replay_raw(self, session_id: str):
        session_file = Path(f"{session_id}_tcp_session.csv")
        keys_file = Path("key.txt")

        result = queue.Queue()

        with keys_file.open(mode='r', newline='', encoding='utf-8') as kf:
            keys = [int(k) for k in kf.read().split(',') if k.strip()]

        with session_file.open(mode='r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            incomplete_packet = None

            for index, row in enumerate(reader):
                raw_bytes = bytes.fromhex(row['raw'].replace(" ", ""))

                if index == 0:
                    print(raw_bytes)

                    continue

                if incomplete_packet is not None:
                    incomplete_packet.payload += raw_bytes

                    if incomplete_packet.size == len(incomplete_packet.payload):
                        result.put_nowait(incomplete_packet)

                        incomplete_packet = None

                        continue


                    continue

                # The first 2 bytes are the size of the payload in multiples of 8 bytes in little endian.
                size = int.from_bytes(raw_bytes[:2], sys.byteorder, signed=False) * 8

                # Next 2 bytes = sequence number
                sequence = int.from_bytes(raw_bytes[2:4], sys.byteorder, signed=False)

                # Next 2 bytes = compression flag
                compression_flag = raw_bytes[4:6]

                compressed_literal_flag = 0xC000.to_bytes(2, sys.byteorder, signed=False)
                not_compressed_literal_flag = 0x0000.to_bytes(2, sys.byteorder, signed=False)

                is_compressed = compression_flag == compressed_literal_flag
                is_valid = is_compressed or compression_flag == not_compressed_literal_flag

                # The rest = payload
                payload = raw_bytes[6:]

                if len(payload) < size:
                    incomplete_packet = RawPacket(sequence, size, is_compressed, payload)

                    continue

                if len(payload) > size:
                    raise Exception("Not implemented")

                result.put_nowait(RawPacket(sequence, size, is_compressed, payload))

        xtea = Xtea(keys)

        while not result.empty():
            raw = result.get_nowait()

            payload = xtea.decrypt(raw.payload)

            # Remove junk bytes, the first byte indicates the byte padding (0-7)
            padding = int.from_bytes(payload[:1], "little", signed=False)

            if 0 <= padding <= 7:
                payload = payload[1:-padding] if padding > 0 else payload[1:]

            if raw.is_compressed:
                out = self.decompressor.decompress(payload)

                print(
                    f"Size: {raw.size} (bytes) | Seq: {raw.seq} | Com: {raw.is_compressed}\n"
                    f"Payload ({len(raw.payload)} bytes): {out.hex(" ")}\n"
                )

                continue

            print(
                f"Size: {raw.size} (bytes) | Seq: {raw.seq} | Com: {raw.is_compressed}\n"
                f"Payload ({len(raw.payload)} bytes): {raw.payload.hex(" ")}\n"
            )



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
