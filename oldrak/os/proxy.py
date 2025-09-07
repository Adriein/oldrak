import os
import subprocess

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

class Proxy:
    def __init__(self):
        options = Options()
        master = DumpMaster(options, with_dumper=False)

        master.run()

        certificate_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        subprocess.run(["cp", certificate_path, "/usr/local/share/ca-certificates/mitmproxy.crt"])
        subprocess.run(["update-ca-certificates"])
