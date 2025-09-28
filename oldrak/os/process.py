from oldrak.os.memory import Memory
from oldrak.os.network import Network
from oldrak.os.debugger import Debugger


class Process:
    def __init__(self, memory: Memory, network: Network, debugger: Debugger):
        self._memory = memory
        self._debugger = debugger
        self._network = network

        self.name = 'Tibia'
        self.pid = None

    def hook(self,) -> None:
        self.pid = self._memory.get_pid_by_name(self.name)


    def spy_network(self) -> None:
        #decrypt_keys = self._debugger.get_xtea_decode_key(self.pid)
        if self._network.sniffer is not None:
            return

        self._network.sniff()

    def abort_spy_network(self) -> None:
        self._network.sniffer.stop()
        self._network.sniffer = None