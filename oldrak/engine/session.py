import csv
import zlib
from datetime import datetime
from pathlib import Path
from typing import Optional

from oldrak.os import TcpStreamSet
from oldrak.os.packet import TibiaTcpPacket
from oldrak.os.decryption import Xtea


class GameSession:
    def __init__(self, tcp_stream: Optional[TcpStreamSet]):
        self._tcp_stream = tcp_stream

    def flush(self, record = False) -> None:
        if not record:
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        session_file = Path(f"{timestamp}_tcp_session.csv")

        buf = self._tcp_stream.get_server_stream()

        with session_file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            while not buf.empty():
                t_packet = buf.get_nowait()

                writer.writerow([
                    t_packet.src,
                    t_packet.src_port,
                    t_packet.sequence,
                    t_packet.size,
                    t_packet.is_compressed,
                    t_packet.payload.hex()
                ])

class SessionDebugger:
    def __init__(self):
        self.decompressor = zlib.decompressobj(wbits=-zlib.MAX_WBITS)

    def replay(self, session_id: str) -> None:
        session_file = Path(f"{session_id}_tcp_session.csv")
        keys_file = Path("key.txt")

        with keys_file.open(mode='r', newline='', encoding='utf-8') as f:
            keys = [int(k) for k in f.read().split(',') if k.strip()]

        with session_file.open(mode='r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)

            for row in reader:
                (src, src_port, sequence, size, is_compressed, payload) = row
                t_packet = TibiaTcpPacket(
                    src,
                    "unknown",
                    int(src_port),
                    0,
                    int(size),
                    int(sequence),
                    is_compressed == 'True',
                    bytes.fromhex(payload)
                )

                t_packet.decrypt(Xtea(keys))

                if t_packet.is_compressed and t_packet.sequence <= 164:
                    t_packet.decompress(self.decompressor)

                if t_packet.sequence <= 164:
                    print(t_packet)
                    print("-" * 20)


