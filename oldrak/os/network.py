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
            try:
                t_packet = TibiaServerTcpPacket.from_raw(pkt)
                print(t_packet)
            except Exception as e:
                print(f"{e}")

            print("-" * 60)


class TibiaServerTcpPacket:
    def __init__(
            self,
            src: str,
            dest: str,
            src_port: int,
            dest_port: int,
            size: int,
            sequence: int,
            compression: int,
            payload: bytes
    ) -> None:
        self.src = src
        self.dest = dest
        self.src_port = src_port
        self.dest_port = dest_port
        self.size = size
        self.sequence = sequence
        self.compression = compression
        self.payload = payload

    @staticmethod
    def from_raw(pkt: Packet) -> 'TibiaServerTcpPacket':
        src = pkt[IP].src
        dest = pkt[IP].dst
        src_port = pkt[TCP].sport
        dest_port = pkt[TCP].dport
        data = pkt[Raw].load
        raw_bytes = bytes(data)

        if len(raw_bytes) < 6:
            raise Exception("Too small to be a valid packet")

        # First 2 bytes are the size of the payload in multiples of 8 bytes (minus the header) in little endian.
        # I.e. Size 1 means 1 * 8 = Payload 8 bytes + 6 bytes header = 14 bytes total
        size = int.from_bytes(raw_bytes[0:2], "little") * 8 + 6

        # Next 2 bytes = sequence number
        sequence = int.from_bytes(raw_bytes[2:4], "little")

        # Next 2 bytes = compression flag
        compression = int.from_bytes(raw_bytes[4:6], "little")

        # The rest = payload
        payload = raw_bytes[6:]

        return TibiaServerTcpPacket(
            src,
            dest,
            src_port,
            dest_port,
            size,
            sequence,
            compression,
            payload
        )

    def __repr__(self) -> str:
        return (
            f"{self.src}:{self.src_port} -> {self.dest}:{self.dest_port}\n"
            f"Size: {self.size} (bytes) | Seq: {self.sequence} | Comp: {self.compression}\n"
            f"Payload ({len(self.payload)} bytes): {self.payload}"
        )