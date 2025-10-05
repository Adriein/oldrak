import zlib
import queue
from typing import Optional

from scapy.all import Packet, Raw, AsyncSniffer
from scapy.layers.inet import IP, TCP

from oldrak.os.packet import TibiaTcpPacket


class Network:
    def __init__(self) -> None:
        self._xtea = None
        self.tcp_streams: TcpStreamSet = TcpStreamSet()
        self.decompressor = {}
        self.sniffer = None

    def sniff(self,) -> None:
        self.sniffer = AsyncSniffer(filter="tcp port 7171", prn= self._handle_tcp, store=0)
        self.sniffer.start()

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                payload = bytes(pkt[Raw].load)

                buf = self.tcp_streams[stream_id]

                if buf is None:
                    return

                if stream_id not in self.decompressor:
                    self.decompressor.setdefault(stream_id, zlib.decompressobj(-zlib.MAX_WBITS))

                t_packet = TibiaTcpPacket.from_raw(stream_id, payload)

                if t_packet.size < len(t_packet.payload):
                    print(f"Packet size is smaller than payload size, this means 2 commands in the same packet")
                    return

                buf.put_nowait(t_packet)

            except Exception as e:
                print(f"{e}")


class TcpStreamSet:
    def __init__(self,) -> None:
        self.set: dict[tuple[str, int, str, int], queue.Queue[TibiaTcpPacket]] = {}

    def __getitem__(self, stream_id: tuple[str, int, str, int]) -> Optional[queue.Queue[TibiaTcpPacket]]:
        src, src_port, dest, dest_port = stream_id

        has_to_ignore_tcp_packet = any(
            str_id[0] != src and str_id[1] == src_port
            for str_id in self.set.keys()
        )

        if has_to_ignore_tcp_packet:
            return None

        if stream_id not in self.set:
            self.set.setdefault(stream_id, queue.Queue())

        return self.set[stream_id]

    def __setitem__(self, stream_id: tuple[str, int, str, int], value: queue.Queue[TibiaTcpPacket]) -> None:
        self.set[stream_id] = value