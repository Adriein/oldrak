from oldrak.os.memory import Memory
from oldrak.os.network import Network
from oldrak.os.debugger import Debugger
from oldrak.os.video import Video, VideoStream


class Process:
    def __init__(self, memory: Memory, network: Network, debugger: Debugger, video: Video):
        self._memory = memory
        self._debugger = debugger
        self._network = network
        self._video = video

        self.name = 'Tibia'
        self.pid = None

    def hook(self,) -> None:
        self.pid = self._memory.get_pid_by_name(self.name)


    def spy_network(self) -> None:
        if self._network.sniffer is not None:
            return

        decrypt_keys = self._debugger.get_xtea_decode_key(self.pid)

        self._network.sniff(decrypt_keys)

    def capture_video(self) -> VideoStream:
        if self._video.is_running():
            return self._video.stream

        self._video.start()

        return self._video.stream

    def abort_spy_network(self) -> None:
        self._network.sniffer.stop()
        self._network.sniffer = None

    def abort_video_capture(self) -> None:
        self._video.stop()