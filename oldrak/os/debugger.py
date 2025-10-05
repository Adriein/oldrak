import os
import subprocess

from oldrak.os.memory import Memory

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

        keys = [key for key in gdb_output.split(":\t")[1].split("\n")[0].split("\t") if key]

        # Keys are in 0x00 format, convert to bytes.
        keys = [int(key, 16) for key in keys]

        # Write key to file for debugging purposes.
        with open("key.txt", "w") as f:
            f.write(",".join([str(k) for k in keys]))

        return keys
