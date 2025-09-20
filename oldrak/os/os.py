import os
import subprocess
import asyncio
import time
import zlib

from ctypes import c_char, c_long, c_float, Array
from typing import Union

import scapy
from mem_edit import Process as MemEditProcess
from scapy.all import Packet, Raw, sniff
from scapy.layers.inet import IP, TCP

from oldrak.os.xtea import Xtea


class Memory:
    ModeReadOnly = 'r'

    def get_pid_by_name(self, name: str) -> int|None:
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue

            try:
                with open(os.path.join('/proc', pid, 'cmdline'), self.ModeReadOnly) as buff:
                    if name in buff.read().strip():
                        return int(pid)

            except (IOError, FileNotFoundError):
                continue

        return None

    def find(self, pid: int, value: Union[int, str, float, bytearray]) -> list[int]:
        with MemEditProcess.open_process(process_id=pid) as process:
            ctype = self._to_ctype(value)

            addresses: list[int] = []

            for address in process.search_all_memory(ctype, False):
                addresses.append(address)

            process.close()

            return addresses

    def _to_ctype(self, value: Union[int, str, float, bytearray]) -> Union[c_float, c_long, Array[c_char]]:
        if type(value) == str:
            b = bytearray()
            b.extend(value.encode("ascii"))

            return (c_char * len(b)).from_buffer(b)

        if type(value) == bytearray:
            return (c_char * len(value)).from_buffer(value)

        if type(value) == int:
            if abs(value) <= 2147483647:
                return c_long(value)

            return c_long(value)

        if type(value) == float:
            return c_float(value)

        raise Exception("Unknown value type")


class Process:
    def __init__(self, name: str):
        self._memory = Memory()
        self._debugger = Debugger(self._memory)

        self.name = name
        self.pid = self._memory.get_pid_by_name(self.name)
        self.keys = self._debugger.get_xtea_decode_key(self.pid)

    def spy_network(self) -> None:
        network = Network(self.keys)

        network.sniff()


class Debugger:
    def __init__(self, memory: Memory) -> None:
        self._memory = memory

    def _find_breakpoint_address(self, pid: int) -> str:
        # Look for the xtea decryption code using the magic number 0x61c88647 in memory.
        xtea_raw_code = "89cac1e20431da01c62d4786c861"

        addresses: list[int] = self._memory.find(pid, bytearray.fromhex(xtea_raw_code))

        if len(addresses) == 0:
            raise Exception("No breakpoint found")

        return hex(addresses[0])

    def get_xtea_decode_key(self, pid: int) -> list[int]:
        """Attach gdb to the process self.process_id and set a breakpoint at the address self.breakpoint_address.
        Prints 128 bits out of the $rdi address.
        Returns the gdb output as a string.
        """

        hex_address = self._find_breakpoint_address(pid)

        file_dir = os.path.dirname(os.path.realpath(__file__))
        gdb_file_directory = os.path.join(file_dir, "gdb_command")

        command = ["gdb", "-p", str(pid), "-batch",
                   "-ex", f"b *{hex_address}",
                   "-x", f"{gdb_file_directory}"]

        gdb_output = subprocess.check_output(command).decode("utf-8")
        print(f"{gdb_output=}")
        keys = [key for key in gdb_output.split(":\t")[1].split("\n")[0].split("\t") if key]

        # Keys are in 0x00 format, convert to bytes.
        keys = [int(key, 16) for key in keys]

        # Write key to file for debugging purposes.
        with open("key.txt", "w") as f:
            f.write(",".join([str(k) for k in keys]))

        return keys

class Network:
    def __init__(self, keys: list[int]):
        self._xtea = Xtea(keys)
        self.handle: asyncio.Task[None]|None = None

    def sniff(self,):
        sniff(filter="tcp port 7171", prn= self._handle_tcp, store=0)

    def _handle_tcp(self, pkt: Packet) -> None:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                t_packet = TibiaServerTcpPacket.from_raw(pkt)

                t_packet.parse(self._xtea)
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
            is_compressed: bool,
            payload: bytes
    ) -> None:
        self.decompressor = {}

        self.src = src
        self.dest = dest
        self.src_port = src_port
        self.dest_port = dest_port
        self.size = size
        self.sequence = sequence
        self.is_compressed = is_compressed
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



        # The first 2 bytes are the size of the payload in multiples of 8 bytes (minus the header) in little endian.
        # I.e., Size 1 means 1 * 8 = Payload 8 bytes + 6 bytes header = 14 bytes total
        size = int.from_bytes(raw_bytes[:2], "little") * 8 + 6

        # Next 2 bytes = sequence number
        sequence = int.from_bytes(raw_bytes[2:4], "little")

        # Next 2 bytes = compression flag
        compression_flag = int.from_bytes(raw_bytes[4:6], "little")
        is_compressed = bool(compression_flag)

        # The rest = payload
        payload = raw_bytes[6:]

        return TibiaServerTcpPacket(
            src,
            dest,
            src_port,
            dest_port,
            size,
            sequence,
            is_compressed,
            payload
        )

    def __repr__(self) -> str:
        return (
            f"{self.src}:{self.src_port} -> {self.dest}:{self.dest_port}\n"
            f"Size: {self.size} (bytes) | Seq: {self.sequence} | Comp: {self.is_compressed}\n"
            f"Payload ({len(self.payload)} bytes): {self.payload}"
        )

    def parse(self, xtea: Xtea) -> None:
        decrypted_payload = xtea.decrypt(self.payload)

        #Remove junk bytes, the first byte indicates the byte padding (0-7)
        padding = int.from_bytes(decrypted_payload[:1], "little")

        real_payload = decrypted_payload[1 : len(decrypted_payload) - padding]

        if self.is_compressed:
            print("before decryption payload")
            print(self.payload.hex(" "))
            print("compressed payload")
            print(decrypted_payload.hex(" "))
            print("padding")
            print(padding)
            print("real payload")
            print(real_payload)

            return

        self.payload = real_payload
