import csv
from datetime import datetime
from pathlib import Path

from oldrak.os import TcpStreamSet

class GameSession:
    def __init__(self, tcp_stream: TcpStreamSet):
        self._tcp_stream = tcp_stream

    def flush(self, record = False) -> None:
        if not record:
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

        filename = Path(f"{timestamp}_tcp_session.csv")

        buf = self._tcp_stream.get_server_stream()

        with filename.open('w', newline='', encoding='utf-8') as f:
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

    def replay(self, session_id: str) -> None:
        session_file = Path(f"{session_id}_tcp_session.csv")
        keys_file = Path("key.txt")

        with open(keys_file, 'r', newline='', encoding='utf-8') as f:
            keys = f.read().split(',')



        with open(session_file, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                print(f"Source IP: {row['src']}")
                print(f"Sequence: {row['sequence']}")
                print(f"Payload Hex: {row['payload_hex']}")
                print("-" * 20)

                # Note: Values are returned as strings, so you may need to convert them
                # if you want to use them as integers (e.g., int(row['size'])).

                # Example of conversion:
                # size = int(row['size'])
                # is_compressed = row['is_compressed'] == 'True'

