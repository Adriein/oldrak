import ctypes
import os
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

    def find(self, pid: int, value: Union[int, str, float, bytearray]) -> None:
        with MemEditProcess.open_process(process_id=pid) as process:
            for address in process.search_all_memory((ctypes.c_char * len(value)).from_buffer(value), False):
                print("mem_region")
                print(address)


            process.close()



class Process:
    def __init__(self, name: str):
        self._memory = Memory()
        self._debugger = Debugger(self._memory)

        self.name = name
        self.pid = self._memory.get_pid_by_name(self.name)
        self._debugger.find_breakpoint_address(self.pid)


class Debugger:
    def __init__(self, memory: Memory) -> None:
        self._memory = memory

    def find_breakpoint_address(self, pid: int) -> None:
        # Look for the xtea decryption code using the magic number 0x61c88647 in memory.
        xtea_raw_code = "89cac1e20431da01c62d4786c861"  # As of 12.09.2024. Check assembly if changed.
        self._memory.find(pid, bytearray.fromhex(xtea_raw_code))

        # Convert to hex for gdb.
        #self.breakpoint_address = hex(address)

    # def find_key(self) -> List[int]:
    #     """Attach gdb to the process self.process_id and set a breakpoint at the address self.breakpoint_address.
    #     Prints 128 bits out of the $rdi address.
    #     Returns the gdb output as a string.
    #     """
    #     if not self.breakpoint_address:
    #         self.find_breakpoint_address()
    #
    #     print(self.breakpoint_address)
    #
    #     file_dir = os.path.dirname(os.path.realpath(__file__))
    #     gdb_file_directory = os.path.join(file_dir, "gdb_find_xtea")
    #
    #     command = ["gdb", "-p", str(self.process_id), "-batch",
    #                "-ex", f"b *{self.breakpoint_address}",
    #                "-x", f"{gdb_file_directory}"]
    #
    #     gdb_output = subprocess.check_output(command).decode("utf-8")
    #     print(f"{gdb_output=}")
    #     keys = [key for key in gdb_output.split(":\t")[1].split("\n")[0].split("\t") if key]
    #
    #     # Keys are in 0x00 format, convert to bytes.
    #     keys = [int(key, 16) for key in keys]
    #
    #     # Write key to file for debugging purposes.
    #     with open("key.txt", "w") as f:
    #         f.write(",".join([str(k) for k in keys]))
    #
    #     return keys