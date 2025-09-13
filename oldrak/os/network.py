import asyncio

from scapy.all import Packet, Raw, sniff
from scapy.layers.inet import IP, TCP


class Network:
    def __init__(self,):

        self.handle: asyncio.Task[None]|None = None

    def sniff(self,):
        sniff(filter="tcp port 7171", prn= self._handle_tcp, store=0)

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            src = pkt[IP].src
            dst = pkt[IP].dst
            sport = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            data = pkt[Raw].load  # <-- raw bytes
            print(f"{src}:{sport} -> {dst}:{dst_port}  ({len(data)} bytes)")
            try:
                t_packet = TibiaServerTcpPacket.from_raw(bytes(data))
                print(t_packet)
            except Exception as e:
                print(f"{e}")

            print("-" * 60)

class TibiaServerTcpPacket:
    def __init__(self, size: int, sequence: int, compression: int, payload: bytes) -> None:
        self.size = size
        self.sequence = sequence
        self.compression = compression
        self.payload = payload

    @staticmethod
    def from_raw(raw_bytes: bytes) -> 'TibiaServerTcpPacket':
        if len(raw_bytes) < 6:
            raise Exception("Too small to be a valid packet")

        # First 2 bytes are the size of the payload in multiples of 8 bytes (minus the header) in little endian.
        # I.e. Size 1 means 1 * 8 = Payload 8 bytes + 6 bytes header = 14 bytes total
        size = int.from_bytes(raw_bytes[0:2], "little")

        # Next 2 bytes = sequence number
        sequence = int.from_bytes(raw_bytes[2:4], "little")

        # Next 2 bytes = compression flag
        compression = int.from_bytes(raw_bytes[4:6], "little")

        # The rest = payload
        payload = raw_bytes[6:]

        return TibiaServerTcpPacket(
            size,
            sequence,
            compression,
            payload
        )

    def __repr__(self) -> str:
        return (
            f"Size: {self.size} | Seq: {self.sequence} | Comp: {self.compression}\n"
            f"Payload ({len(self.payload)} bytes): {self.payload}"
        )