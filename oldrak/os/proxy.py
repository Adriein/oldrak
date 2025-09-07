import asyncio
import os
import subprocess
from typing import List

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

class Proxy:
    def __init__(self, addons: List):
        self._options = Options()
        self._master = DumpMaster(self._options, with_dumper=False)
        self._master.addons.add(*addons)

        self.handle: asyncio.Task[any]|None = None

    async def run(self):
        self.handle = asyncio.create_task(self._master.run())

        certificate_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        subprocess.run(["cp", certificate_path, "/usr/local/share/ca-certificates/mitmproxy.crt"])
        subprocess.run(["update-ca-certificates"])
