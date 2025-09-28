import os

from ctypes import c_char, c_long, c_float, Array
from typing import Union

from mem_edit import Process as MemEditProcess

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

