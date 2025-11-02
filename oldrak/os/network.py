import queue
from typing import Optional, Tuple

from scapy.all import Packet, Raw, AsyncSniffer
from scapy.layers.inet import IP, TCP

from oldrak.shared import TIBIA_SERVER_PORT


class Network:
    def __init__(self) -> None:
        self.tcp_streams: TcpStreamSet = TcpStreamSet()
        self.incomplete_buffer: TcpStreamSet = TcpStreamSet()
        self.sniffer = None
        self.last_packet = None

    def async_sniff(self) -> None:
        self.sniffer = AsyncSniffer(filter="tcp port 7171", prn= self._handle_tcp, store=0)
        self.sniffer.start()

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                stream_id = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
                payload = bytes(pkt[Raw].load)

                buf = self.tcp_streams[stream_id]

                if buf is None or payload == self.last_packet:
                    return

                buf.put_nowait(payload)

                self.last_packet = payload

                return

                # t_packet = TibiaTcpPacket.from_raw(stream_id, payload)
                #
                # if t_packet.is_incomplete() and not t_packet.is_client_packet():
                #     print(f"Incomplete packet:\n")
                #     print(t_packet)
                #     buff = self.incomplete_buffer[stream_id]
                #
                #     buff.put_nowait(t_packet)
                #
                #     return
                #
                # if t_packet.is_composed() and not t_packet.is_client_packet():
                #     print(f"Composed packet:\n")
                #     print(t_packet)
                #     composed_payload = t_packet.payload
                #
                #     read_offset = t_packet.size_header - 6
                #
                #     raw_next_packet = composed_payload[read_offset:]
                #
                #     t_packet.payload = composed_payload[:read_offset]
                #
                #     next_t_packet = TibiaTcpPacket.from_raw(stream_id, raw_next_packet)
                #
                #     buf.put_nowait(t_packet)
                #     buf.put_nowait(next_t_packet)
                #
                #     return
                #
                # print(f"Normal packet:\n")
                # print(t_packet)
                # print("-----------------------------------------------------------------------------------------------")
                # buf.put_nowait(t_packet)
            except Exception as e:
                print(f"{e}")


class TcpStreamSet:
    def __init__(self,) -> None:
        self.set: dict[tuple[str, int, str, int], queue.Queue[bytes]] = {}

    def __getitem__(self, stream_id: tuple[str, int, str, int]) -> Optional[queue.Queue[bytes]]:
        src, src_port, dest, dest_port = stream_id

        has_to_ignore = any(
            str_id[2] != dest and str_id[3] == TIBIA_SERVER_PORT
            for str_id in self.set.keys()
        )

        if has_to_ignore:
            return None

        if stream_id not in self.set:
            self.set.setdefault(stream_id, queue.Queue())

        return self.set[stream_id]

    def __setitem__(self, stream_id: tuple[str, int, str, int], value: queue.Queue[bytes]) -> None:
        self.set[stream_id] = value

    def get_server_stream(self) -> Tuple[tuple[str, int, str, int], queue.Queue[bytes]]:
        try:
            server_stream_id = next(stream_id for stream_id in self.set.keys() if stream_id[1] == TIBIA_SERVER_PORT)

            return server_stream_id, self[server_stream_id]

        except StopIteration:
            raise Exception("No server stream found")

