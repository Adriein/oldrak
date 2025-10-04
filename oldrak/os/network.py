import zlib
import queue

from scapy.all import Packet, Raw, AsyncSniffer
from scapy.layers.inet import IP, TCP

from oldrak.os.packet import TibiaTcpPacket
from oldrak.os.decryption import Xtea


class Network:
    def __init__(self):
        self._xtea = None
        self.tcp_streams: dict[tuple[str, int, str, int], queue.Queue[TibiaTcpPacket]] = {}
        self.decompressor = {}
        self.sniffer = None

    def sniff(self, decrypt_keys: list[int]):
        self._xtea = Xtea(decrypt_keys)
        self.sniffer = AsyncSniffer(filter="tcp port 7171", prn= self._handle_tcp, store=0)
        self.sniffer.start()

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                payload = bytes(pkt[Raw].load)

                has_to_ignore_tcp_packet = any(
                    str_id[0] != pkt[IP].src and str_id[1] == pkt[TCP].sport
                    for str_id in self.tcp_streams.keys()
                )

                if has_to_ignore_tcp_packet:
                    return

                if stream_id not in self.tcp_streams:
                    self.tcp_streams.setdefault(stream_id, queue.Queue())

                if stream_id not in self.decompressor:
                    self.decompressor.setdefault(stream_id, zlib.decompressobj(-zlib.MAX_WBITS))

                t_packet = TibiaTcpPacket.from_raw(stream_id, payload)

                if t_packet.size < len(t_packet.payload):
                    print(f"Packet size is smaller than payload size, this means 2 commands in the same packet")
                    return

                if t_packet.is_compressed:
                    print(f"Packet compressed, skipping")
                    return

                t_packet.decrypt(self._xtea)

                t_packet.parse()

                print(t_packet)

                buf = self.tcp_streams[stream_id]
                buf.put_nowait(t_packet)

            except Exception as e:
                print(f"{e}")

