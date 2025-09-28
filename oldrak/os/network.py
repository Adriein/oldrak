import zlib

from scapy.all import Packet, Raw, AsyncSniffer
from scapy.layers.inet import IP, TCP

from oldrak.os.packet import TibiaTcpPacket


class Network:
    def __init__(self):
        self._xtea = None
        self.tcp_buffer: dict[tuple[str, int, str, int], bytearray] = {}
        self.decompressor = {}
        self.sniffer = None

    def sniff(self,):
        #self._xtea = Xtea(decrypt_keys)
        self.sniffer = AsyncSniffer(filter="tcp port 7171", prn= self._handle_tcp, store=0)
        self.sniffer.start()

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                payload = bytes(pkt[Raw].load)

                if stream_id not in self.tcp_buffer:
                    self.tcp_buffer.setdefault(stream_id, bytearray())

                buf = self.tcp_buffer[stream_id]
                buf.extend(payload)

                if stream_id not in self.decompressor:
                    self.decompressor.setdefault(stream_id, zlib.decompressobj(-zlib.MAX_WBITS))

                t_packet = TibiaTcpPacket.from_raw(stream_id, payload)

                #t_packet.decrypt(self._xtea)

                if t_packet.is_compressed:
                    #print(t_packet)
                    #print("-" * 60)
                    #t_packet.decompress(self.decompressor[stream_id])

                    return
                    # Always failing because header says for example 8 bytes but we have 8 bytes header that are
                    # (1 byte padding -> 02) meaning i have to eliminate 2 bytes, now the payload is 8 - 3 = 5 so i need more info from the
                    # next sequence packet
                    # t_packet.decompress()


                #I've seen a not compressed packet where payload > header which means 2 command in the same payload, handle that case
                print(t_packet)
                print("-" * 60)
                t_packet = None

                # while True:
                #     if len(buf) < 2:
                #         break  # not enough to know packet length
                #
                #     size = int.from_bytes(buf[:2], "little") * 8
                #
                #     if len(buf) < size:
                #         if stream_id not in self.incomplete_packets:
                #             self.incomplete_packets.setdefault(stream_id, bytearray())
                #
                #         incomplete_buf = self.incomplete_packets[stream_id]
                #         incomplete_buf.extend(buf)
                #
                #         break  # wait for more data
                #
                #     packet_bytes = bytes(buf[:size])
                #
                #     del buf[:size]  # consume
                #
                #     t_packet = TibiaTcpPacket.from_raw(stream_id, packet_bytes)
                #
                # t_packet.decrypt(self._xtea)
                #
                # if t_packet.is_compressed:
                #     print(t_packet)
                #     t_packet.decompress()
                #     print("-" * 60)
                #     return
                #
                # print(t_packet)
                # print("-" * 60)

            except Exception as e:
                print(f"{e}")

