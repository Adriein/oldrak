import asyncio
from scapy.all import sniff, Raw, Packet


class Network:
    def __init__(self,):

        self.handle: asyncio.Task[None]|None = None

    def sniff(self,):
        sniff(filter="tcp port 7171", prn= self._handle_tcp, store=0)

    def _handle_tcp(self, pkt: Packet) -> None:
        print("pkt")
        print(pkt)

